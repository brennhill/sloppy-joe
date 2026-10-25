//! The zip structure is read only when every reader would agree on it: one
//! end-of-central-directory record, no zip64, a central directory that ends
//! where that record starts, and local headers that name what the central
//! directory names. Anything else is an error (wheel unverified), never a
//! decoy read as clean.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Default)]
struct Member {
    name: &'static [u8],
    content: &'static [u8],
    central_extra: Vec<u8>,
    local_name: Option<&'static [u8]>,
    flags: u16,
    central_comment: Vec<u8>,
}

fn member(name: &'static str, content: &'static [u8]) -> Member {
    Member {
        name: name.as_bytes(),
        content,
        ..Member::default()
    }
}

/// Local records and the central directory entries for `members` (stored).
fn records(members: &[Member]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut locals = Vec::new();
    let mut centrals = Vec::new();
    for m in members {
        let offset = locals.len() as u32;
        let local_name = m.local_name.unwrap_or(m.name);
        locals.extend(0x0403_4b50u32.to_le_bytes());
        locals.extend(20u16.to_le_bytes());
        locals.extend(m.flags.to_le_bytes());
        locals.extend(0u16.to_le_bytes());
        locals.extend([0u8; 8]);
        locals.extend((m.content.len() as u32).to_le_bytes());
        locals.extend((m.content.len() as u32).to_le_bytes());
        locals.extend((local_name.len() as u16).to_le_bytes());
        locals.extend(0u16.to_le_bytes());
        locals.extend(local_name);
        locals.extend(m.content);

        let mut central = Vec::new();
        central.extend(0x0201_4b50u32.to_le_bytes());
        central.extend([20, 0, 20, 0]);
        central.extend(m.flags.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend([0u8; 8]);
        central.extend((m.content.len() as u32).to_le_bytes());
        central.extend((m.content.len() as u32).to_le_bytes());
        central.extend((m.name.len() as u16).to_le_bytes());
        central.extend((m.central_extra.len() as u16).to_le_bytes());
        central.extend((m.central_comment.len() as u16).to_le_bytes());
        central.extend([0u8; 8]); // disk, internal and external attrs
        central.extend(offset.to_le_bytes());
        central.extend(m.name);
        central.extend(&m.central_extra);
        central.extend(&m.central_comment);
        centrals.push(central);
    }
    (locals, centrals)
}

fn eocd(entries: usize, size: usize, offset: usize, comment: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((entries as u16).to_le_bytes());
    out.extend((entries as u16).to_le_bytes());
    out.extend((size as u32).to_le_bytes());
    out.extend((offset as u32).to_le_bytes());
    out.extend((comment.len() as u16).to_le_bytes());
    out.extend(comment);
    out
}

fn archive(members: &[Member]) -> Vec<u8> {
    let (mut out, centrals) = records(members);
    let central = centrals.concat();
    let offset = out.len();
    out.extend(&central);
    out.extend(eocd(centrals.len(), central.len(), offset, b""));
    out
}

fn error(wheel: &[u8]) -> String {
    format!("{:#}", inspect_wheel(wheel).unwrap_err())
}

fn hook_and_readme() -> Vec<Member> {
    vec![
        member("readme.txt", b"hello"),
        member("evil.pth", b"import os\n"),
    ]
}

/// The decoy pip installed while the scanner read a clean listing: the EOCD
/// points at a central directory without the `.pth`; a zip64 locator points
/// at the full one.
fn zip64_decoy() -> Vec<u8> {
    let (mut out, centrals) = records(&hook_and_readme());
    let decoy = centrals[0].clone();
    let real = centrals.concat();
    let decoy_offset = out.len();
    let real_offset = decoy_offset + decoy.len();
    let record_offset = real_offset + real.len();
    out.extend(&decoy);
    out.extend(&real);
    out.extend(0x0606_4b50u32.to_le_bytes());
    out.extend(44u64.to_le_bytes());
    out.extend([45, 0, 45, 0]);
    out.extend([0u8; 8]); // disk numbers
    out.extend(2u64.to_le_bytes());
    out.extend(2u64.to_le_bytes());
    out.extend((real.len() as u64).to_le_bytes());
    out.extend((real_offset as u64).to_le_bytes());
    out.extend(0x0706_4b50u32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend((record_offset as u64).to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out.extend(eocd(1, decoy.len(), decoy_offset, b""));
    out
}

#[test]
fn a_well_formed_archive_is_read() {
    let hooks = inspect_wheel(&archive(&hook_and_readme()))
        .unwrap()
        .startup_hooks;
    assert_eq!(hooks.len(), 1);
}

#[test]
fn a_zip64_locator_pointing_at_another_central_directory_is_refused() {
    assert!(error(&zip64_decoy()).contains("zip64"));
}

#[test]
fn a_zip64_locator_signature_before_the_eocd_is_refused_even_inside_a_comment() {
    // Python's zipfile looks for the locator 20 bytes before the EOCD wherever it sits.
    let mut members = hook_and_readme();
    let mut comment = 0x0706_4b50u32.to_le_bytes().to_vec();
    comment.extend([0u8; 16]);
    members[1].central_comment = comment;
    assert!(error(&archive(&members)).contains("zip64"));
}

#[test]
fn zip64_extra_fields_and_size_markers_on_entries_are_refused() {
    let mut members = hook_and_readme();
    members[0].central_extra = [1u16.to_le_bytes(), 0u16.to_le_bytes()].concat();
    assert!(error(&archive(&members)).contains("zip64"));

    let mut wheel = archive(&hook_and_readme());
    let at = wheel
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
        .unwrap();
    wheel[at + 20..at + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(error(&wheel).contains("zip64"));
}

#[test]
fn a_central_directory_that_does_not_end_at_the_eocd_is_refused() {
    let (mut out, centrals) = records(&hook_and_readme());
    let central = centrals.concat();
    let offset = out.len();
    out.extend(&central);
    out.extend([0u8; 16]);
    out.extend(eocd(2, central.len(), offset, b""));
    assert!(error(&out).contains("central directory"));
}

#[test]
fn an_eocd_pointing_at_a_decoy_directory_before_the_real_one_is_refused() {
    let (mut out, centrals) = records(&hook_and_readme());
    let decoy = centrals[0].clone();
    let decoy_offset = out.len();
    out.extend(&decoy);
    out.extend(centrals.concat());
    out.extend(eocd(1, decoy.len(), decoy_offset, b""));
    assert!(error(&out).contains("central directory"));
}

#[test]
fn a_directory_with_more_bytes_than_its_entries_is_refused() {
    let (mut out, centrals) = records(&hook_and_readme());
    let offset = out.len();
    out.extend(centrals.concat());
    // Claims one entry; the second sits unread inside the directory.
    out.extend(eocd(1, centrals.concat().len(), offset, b""));
    assert!(error(&out).contains("central directory"));
}

#[test]
fn data_after_the_eocd_is_refused() {
    let mut wheel = archive(&hook_and_readme());
    wheel.extend(b"trailing");
    assert!(error(&wheel).contains("end-of-central-directory"));
}

#[test]
fn a_second_eocd_record_is_refused() {
    let (mut out, centrals) = records(&hook_and_readme());
    let central = centrals.concat();
    let offset = out.len();
    out.extend(&central);
    // The real record's comment holds another record that also reaches the end.
    let inner = eocd(2, central.len(), offset, b"");
    out.extend(eocd(2, central.len(), offset, &inner));
    assert!(error(&out).contains("more than one end-of-central-directory"));
}

#[test]
fn split_or_inconsistent_entry_counts_are_refused() {
    let mut wheel = archive(&hook_and_readme());
    let eocd = wheel.len() - 22;
    wheel[eocd + 8..eocd + 10].copy_from_slice(&1u16.to_le_bytes());
    assert!(inspect_wheel(&wheel).is_err());

    let mut wheel = archive(&hook_and_readme());
    let eocd = wheel.len() - 22;
    wheel[eocd + 4..eocd + 6].copy_from_slice(&1u16.to_le_bytes());
    assert!(inspect_wheel(&wheel).is_err());
}

#[test]
fn a_local_header_naming_a_different_file_is_refused() {
    // A streaming installer reads names from local headers, not the directory.
    let mut members = hook_and_readme();
    members[0].local_name = Some(b"other.pth!");
    members[0].name = b"readme.txt";
    assert!(error(&archive(&members)).contains("local header"));
}

#[test]
fn a_unicode_path_extra_field_name_is_matched_too() {
    // Python 3.12+ installs an entry under its Info-ZIP Unicode Path (0x7075) name.
    let mut members = vec![member("readme.txt", b"import os\n")];
    let unicode_name = b"evil.pth";
    let mut body = vec![1u8];
    body.extend(crc32(b"readme.txt").to_le_bytes());
    body.extend(unicode_name);
    let mut extra = 0x7075u16.to_le_bytes().to_vec();
    extra.extend((body.len() as u16).to_le_bytes());
    extra.extend(body);
    members[0].central_extra = extra;
    let wheel = archive(&members);
    let hooks = inspect_wheel(&wheel).unwrap().startup_hooks;
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].path, "evil.pth");
    if let Some(names) = python_zip_names(&wheel) {
        assert_eq!(names, ["evil.pth"], "Python reads the Unicode Path name");
    }
}

#[test]
fn nul_bytes_in_names_and_encrypted_entries_are_refused() {
    // Python's zipfile truncates a name at NUL (`evil.pth\0.txt` installs as evil.pth).
    let wheel = archive(&[member("evil.pth\0.txt", b"import os\n")]);
    assert!(error(&wheel).contains("NUL"));

    let mut encrypted = member("evil.pth", b"import os\n");
    encrypted.flags = 1;
    assert!(error(&archive(&[encrypted])).contains("encrypted"));
}

#[test]
fn entry_data_reaching_into_the_central_directory_is_refused() {
    let mut wheel = archive(&hook_and_readme());
    let at = wheel
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
        .unwrap();
    // Grow the first entry's sizes so its data overlaps the directory.
    wheel[at + 20..at + 24].copy_from_slice(&4096u32.to_le_bytes());
    wheel[at + 24..at + 28].copy_from_slice(&4096u32.to_le_bytes());
    assert!(error(&wheel).contains("central directory"));
}

#[test]
fn python_reads_the_hidden_pth_from_the_zip64_decoy() {
    // Proof the decoy is real: Python's zipfile (what pip uses) lists the hook.
    if let Some(names) = python_zip_names(&zip64_decoy()) {
        assert!(names.contains(&"evil.pth".to_string()), "{names:?}");
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The member names Python's `zipfile` reads from `wheel`, when `python3`
/// is installed (`None` without it; a zipfile error fails the test).
fn python_zip_names(wheel: &[u8]) -> Option<Vec<String>> {
    let available = std::process::Command::new("python3")
        .args(["-I", "-c", "pass"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        eprintln!("python3 not available; skipping the zipfile comparison");
        return None;
    }
    static N: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "sj-wheel-zip-{}-{}.zip",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&path, wheel).unwrap();
    let output = std::process::Command::new("python3")
        .args([
            "-I",
            "-c",
            "import sys, zipfile; print('\\n'.join(zipfile.ZipFile(sys.argv[1]).namelist()))",
        ])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).ok();
    assert!(
        output.status.success(),
        "python3 zipfile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_string)
            .collect(),
    )
}
