//! The wheel's zip structure, read only when every reader agrees on it.
//!
//! Zip readers locate entries differently: Python's `zipfile` (pip) follows a
//! zip64 locator, reads the central directory at the end-of-central-directory
//! (EOCD) position minus its size, and takes a name from an Info-ZIP Unicode
//! Path field; streaming readers take names from local headers. A wheel that
//! reads one way to the scanner and another to an installer can hide a hook,
//! so the archive is refused (wheel unverified) unless:
//!
//! - there is exactly one EOCD record and it ends the file;
//! - it is not zip64 (no markers, no locator before it, no zip64 extra field);
//! - the central directory ends exactly where the EOCD starts, holds exactly
//!   the entries the EOCD counts, and lies on disk 0;
//! - every entry's local header carries the same name, and its data ends
//!   before the central directory starts;
//! - no name contains NUL and no entry is encrypted.

use anyhow::{Result, anyhow, bail};
use flate2::read::DeflateDecoder;
use std::io::Read;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const EOCD_LEN: usize = 22;
const MAX_COMMENT: usize = 65_535;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const CENTRAL_LEN: usize = 46;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const LOCAL_LEN: usize = 30;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_EXTRA: usize = 0x0001;
const UNICODE_PATH_EXTRA: usize = 0x7075;
const ENCRYPTED_FLAG: usize = 0x0001;
const MAX_ENTRIES: usize = 100_000;

pub(super) struct Entry {
    /// Every name a reader may install the entry under: the central
    /// directory name (lossy UTF-8) and any Unicode Path extra field name.
    pub names: Vec<String>,
    method: usize,
    compressed: usize,
    uncompressed: u64,
    data_start: usize,
}

fn u16_at(data: &[u8], at: usize) -> Result<usize> {
    let bytes = data
        .get(at..at + 2)
        .ok_or_else(|| anyhow!("truncated zip"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let bytes = data
        .get(at..at + 4)
        .ok_or_else(|| anyhow!("truncated zip"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn slice(data: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    data.get(at..at + len)
        .ok_or_else(|| anyhow!("truncated zip"))
}

fn is_eocd(data: &[u8], at: usize) -> bool {
    u32_at(data, at).is_ok_and(|sig| sig == EOCD_SIGNATURE)
}

fn ends_file(data: &[u8], at: usize) -> bool {
    u16_at(data, at + 20).is_ok_and(|comment| at + EOCD_LEN + comment == data.len())
}

/// The EOCD every reader picks: the last signature in the comment window
/// (as `zipfile` and the zip crates search). It must end the file, and no
/// other record in the window may also end it.
fn find_eocd(data: &[u8]) -> Result<usize> {
    let last = data
        .len()
        .checked_sub(EOCD_LEN)
        .ok_or_else(|| anyhow!("not a zip archive (no end-of-central-directory record)"))?;
    let floor = last.saturating_sub(MAX_COMMENT);
    let candidates: Vec<usize> = (floor..=last).filter(|&at| is_eocd(data, at)).collect();
    let Some(&chosen) = candidates.last() else {
        bail!("not a zip archive (no end-of-central-directory record)");
    };
    if !ends_file(data, chosen) {
        bail!("data follows the end-of-central-directory record");
    }
    if candidates.iter().filter(|&&at| ends_file(data, at)).count() > 1 {
        bail!("the archive has more than one end-of-central-directory record");
    }
    Ok(chosen)
}

/// Bounds of the central directory, checked against the EOCD at `eocd`.
fn directory(data: &[u8], eocd: usize) -> Result<(usize, usize)> {
    let has_locator = eocd >= ZIP64_LOCATOR_LEN
        && u32_at(data, eocd - ZIP64_LOCATOR_LEN)? == ZIP64_LOCATOR_SIGNATURE;
    let total = u16_at(data, eocd + 10)?;
    let size = u32_at(data, eocd + 12)?;
    let offset = u32_at(data, eocd + 16)?;
    if has_locator || total == 0xFFFF || size == u32::MAX || offset == u32::MAX {
        bail!("zip64 archives are not supported");
    }
    let disk = u16_at(data, eocd + 4)?;
    let directory_disk = u16_at(data, eocd + 6)?;
    if disk != 0 || directory_disk != 0 || u16_at(data, eocd + 8)? != total {
        bail!("multi-disk archives are not supported");
    }
    if total > MAX_ENTRIES {
        bail!("archive has {total} entries (limit {MAX_ENTRIES})");
    }
    if offset as usize + size as usize != eocd {
        bail!(
            "the central directory does not end where the end-of-central-directory record starts"
        );
    }
    Ok((offset as usize, total))
}

/// `(id, body)` of each extra field; a field running past the block is corrupt.
fn extra_fields(mut extra: &[u8]) -> Result<Vec<(usize, &[u8])>> {
    let mut fields = Vec::new();
    while extra.len() >= 4 {
        let id = u16_at(extra, 0)?;
        let len = u16_at(extra, 2)?;
        let body = extra
            .get(4..4 + len)
            .ok_or_else(|| anyhow!("corrupt extra field {id:#06x}"))?;
        fields.push((id, body));
        extra = &extra[4 + len..];
    }
    Ok(fields)
}

/// Names from extra fields; zip64 fields are refused.
fn extra_names(extra: &[u8]) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for (id, body) in extra_fields(extra)? {
        match id {
            ZIP64_EXTRA => bail!("zip64 archives are not supported"),
            UNICODE_PATH_EXTRA => {
                let name = body
                    .get(5..)
                    .ok_or_else(|| anyhow!("corrupt Unicode Path extra field"))?;
                names.push(String::from_utf8_lossy(name).into_owned());
            }
            _ => {}
        }
    }
    Ok(names)
}

/// Where the entry's data starts, after checking its local header names the
/// same file and its data ends before the central directory.
fn local_data_start(
    data: &[u8],
    offset: usize,
    name: &[u8],
    compressed: usize,
    directory_start: usize,
) -> Result<usize> {
    let shown = String::from_utf8_lossy(name);
    if u32_at(data, offset).ok() != Some(LOCAL_SIGNATURE) {
        bail!("the local header of '{shown}' does not match the central directory");
    }
    let name_len = u16_at(data, offset + 26)?;
    let extra_len = u16_at(data, offset + 28)?;
    if slice(data, offset + LOCAL_LEN, name_len)? != name {
        bail!("the local header of '{shown}' names a different file");
    }
    extra_names(slice(data, offset + LOCAL_LEN + name_len, extra_len)?)?;
    let start = offset + LOCAL_LEN + name_len + extra_len;
    if start + compressed > directory_start {
        bail!("the data of '{shown}' runs into the central directory");
    }
    Ok(start)
}

/// The entry at `at` and where the next one starts.
fn central_entry(data: &[u8], at: usize, directory_start: usize) -> Result<(Entry, usize)> {
    if u32_at(data, at)? != CENTRAL_SIGNATURE {
        bail!("corrupt central directory");
    }
    let name_len = u16_at(data, at + 28)?;
    let extra_len = u16_at(data, at + 30)?;
    let comment_len = u16_at(data, at + 32)?;
    let compressed = u32_at(data, at + 20)?;
    let uncompressed = u32_at(data, at + 24)?;
    let offset = u32_at(data, at + 42)?;
    if [compressed, uncompressed, offset].contains(&u32::MAX) || u16_at(data, at + 34)? == 0xFFFF {
        bail!("zip64 archives are not supported");
    }
    if u16_at(data, at + 34)? != 0 {
        bail!("multi-disk archives are not supported");
    }
    let name_bytes = slice(data, at + CENTRAL_LEN, name_len)?;
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    if u16_at(data, at + 8)? & ENCRYPTED_FLAG != 0 {
        bail!("encrypted entry '{name}' is not supported");
    }
    let mut names = vec![name];
    names.extend(extra_names(slice(
        data,
        at + CENTRAL_LEN + name_len,
        extra_len,
    )?)?);
    if names.iter().any(|n| n.contains('\0')) {
        bail!(
            "entry name '{}' contains a NUL byte",
            names[0].replace('\0', "\\0")
        );
    }
    let data_start = local_data_start(
        data,
        offset as usize,
        name_bytes,
        compressed as usize,
        directory_start,
    )?;
    let entry = Entry {
        names,
        method: u16_at(data, at + 10)?,
        compressed: compressed as usize,
        uncompressed: u64::from(uncompressed),
        data_start,
    };
    Ok((entry, at + CENTRAL_LEN + name_len + extra_len + comment_len))
}

pub(super) fn central_entries(data: &[u8]) -> Result<Vec<Entry>> {
    let eocd = find_eocd(data)?;
    let (start, total) = directory(data, eocd)?;
    let mut at = start;
    let mut entries = Vec::with_capacity(total);
    for _ in 0..total {
        if at >= eocd {
            bail!("the central directory holds fewer entries than it declares");
        }
        let (entry, next) = central_entry(data, at, start)?;
        entries.push(entry);
        at = next;
    }
    if at != eocd {
        bail!("the central directory size does not match its entries");
    }
    Ok(entries)
}

/// The entry's content, at most `max` bytes.
pub(super) fn entry_bytes(data: &[u8], entry: &Entry, max: u64) -> Result<Vec<u8>> {
    if entry.uncompressed > max || (entry.method == 0 && entry.compressed as u64 > max) {
        bail!(
            "{} bytes (limit {max})",
            entry.uncompressed.max(entry.compressed as u64)
        );
    }
    let raw = slice(data, entry.data_start, entry.compressed)?;
    match entry.method {
        0 => Ok(raw.to_vec()),
        8 => {
            let mut out = Vec::new();
            DeflateDecoder::new(raw)
                .take(max + 1)
                .read_to_end(&mut out)?;
            if out.len() as u64 > max {
                bail!("decompresses beyond {max} bytes");
            }
            Ok(out)
        }
        other => bail!("unsupported compression method {other}"),
    }
}
