//! PyPI wheel inspection: Python startup hooks.
//!
//! A wheel is a zip. Anything installed at the top of `site-packages` runs
//! without being imported: `*.pth` lines starting with `import` execute at
//! every interpreter start, and `sitecustomize` / `usercustomize` are imported
//! by `site`. Compromised releases (LiteLLM 1.82.8, the Hades campaign) used
//! exactly this to run before any application code.
//!
//! The wheel is read in memory and never extracted. The central directory is
//! authoritative, as it is for Python's own `zipfile`. Anything this reader
//! cannot model (zip64, unknown compression, bad offsets, too many entries) is
//! an error, not a pass.

mod layout;
mod pth;

use super::npm_tarball::{IntegrityMismatch, download_tarball, hex};
use super::pypi_release::PypiFile;
use anyhow::{Result, anyhow, bail};
use flate2::read::DeflateDecoder;
use layout::Role;
use serde::{Deserialize, Serialize};
use std::io::Read;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const MAX_ENTRIES: usize = 100_000;
/// Hook files larger than this are reported unread (and treated as risky).
const MAX_HOOK_BYTES: u64 = 256 * 1024;
/// Executable lines kept per hook for the report.
const MAX_SHOWN_LINES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookKind {
    /// A `*.pth` file with at least one line site.py executes.
    PthImport,
    /// `sitecustomize` / `usercustomize`, imported by `site` at startup.
    CustomizeModule,
    /// A `*.pth` file with only directory lines: `site` appends them to
    /// `sys.path` before importing `sitecustomize`, so a customize module in
    /// one of them (from this wheel or another) runs at startup.
    PthPath,
    /// A `*.start` file (Python 3.15, PEP 829) whose `pkg.mod:callable`
    /// entry points `site` calls at startup.
    StartEntryPoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupHook {
    /// Path inside the wheel.
    pub path: String,
    pub kind: HookKind,
    /// First executable lines (truncated); empty for customize modules.
    pub code: Vec<String>,
    /// Why the content could not be read (oversize, unsupported compression).
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WheelFacts {
    pub startup_hooks: Vec<StartupHook>,
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

struct Entry {
    name: String,
    method: usize,
    compressed: usize,
    uncompressed: u64,
    local_offset: usize,
}

fn find_eocd(data: &[u8]) -> Result<usize> {
    let floor = data.len().saturating_sub(22 + 65_535);
    (floor..=data.len().saturating_sub(22))
        .rev()
        .find(|at| u32_at(data, *at).is_ok_and(|sig| sig == EOCD_SIGNATURE))
        .ok_or_else(|| anyhow!("not a zip archive (no end-of-central-directory record)"))
}

fn central_entries(data: &[u8]) -> Result<Vec<Entry>> {
    let eocd = find_eocd(data)?;
    let total = u16_at(data, eocd + 10)?;
    let directory_size = u32_at(data, eocd + 12)?;
    let directory_offset = u32_at(data, eocd + 16)?;
    if total == 0xFFFF || directory_size == u32::MAX || directory_offset == u32::MAX {
        bail!("zip64 archives are not supported");
    }
    if total > MAX_ENTRIES {
        bail!("archive has {total} entries (limit {MAX_ENTRIES})");
    }
    let mut at = directory_offset as usize;
    let mut entries = Vec::with_capacity(total);
    for _ in 0..total {
        if u32_at(data, at)? != CENTRAL_SIGNATURE {
            bail!("corrupt central directory");
        }
        let name_len = u16_at(data, at + 28)?;
        let extra_len = u16_at(data, at + 30)?;
        let comment_len = u16_at(data, at + 32)?;
        let name_bytes = data
            .get(at + 46..at + 46 + name_len)
            .ok_or_else(|| anyhow!("truncated central directory"))?;
        entries.push(Entry {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            method: u16_at(data, at + 10)?,
            compressed: u32_at(data, at + 20)? as usize,
            uncompressed: u64::from(u32_at(data, at + 24)?),
            local_offset: u32_at(data, at + 42)? as usize,
        });
        at += 46 + name_len + extra_len + comment_len;
    }
    Ok(entries)
}

fn entry_bytes(data: &[u8], entry: &Entry) -> Result<Vec<u8>> {
    if entry.uncompressed > MAX_HOOK_BYTES {
        bail!("{} bytes (limit {MAX_HOOK_BYTES})", entry.uncompressed);
    }
    if u32_at(data, entry.local_offset)? != LOCAL_SIGNATURE {
        bail!("local header does not match the central directory");
    }
    let name_len = u16_at(data, entry.local_offset + 26)?;
    let extra_len = u16_at(data, entry.local_offset + 28)?;
    let start = entry.local_offset + 30 + name_len + extra_len;
    let raw = data
        .get(start..start + entry.compressed)
        .ok_or_else(|| anyhow!("entry data runs past the end of the archive"))?;
    match entry.method {
        0 => Ok(raw.to_vec()),
        8 => {
            let mut out = Vec::new();
            DeflateDecoder::new(raw)
                .take(MAX_HOOK_BYTES + 1)
                .read_to_end(&mut out)?;
            if out.len() as u64 > MAX_HOOK_BYTES {
                bail!("decompresses beyond {MAX_HOOK_BYTES} bytes");
            }
            Ok(out)
        }
        other => bail!("unsupported compression method {other}"),
    }
}

/// The strongest startup role `name` takes, if any. Directory entries
/// (`.../`) install nothing.
fn strongest_role(name: &str) -> Result<Option<Role>> {
    if name.ends_with('/') {
        return Ok(None);
    }
    Ok(layout::roles(name)?.into_iter().max())
}

fn hook(path: &str, kind: HookKind, mut code: Vec<String>) -> Option<StartupHook> {
    if code.is_empty() && kind != HookKind::CustomizeModule {
        return None;
    }
    code.truncate(MAX_SHOWN_LINES);
    Some(StartupHook {
        path: path.to_string(),
        kind,
        code,
        unreadable: None,
    })
}

/// The hook a member installs: customize modules are hooks unread; `.pth`
/// and `.start` files are hooks when a line acts at startup, or when they
/// cannot be read (reported, never skipped).
fn member_hook(data: &[u8], entry: &Entry, path: &str, role: Role) -> Option<StartupHook> {
    let content = match role {
        Role::Customize => return hook(path, HookKind::CustomizeModule, Vec::new()),
        Role::Pth | Role::Start => entry_bytes(data, entry),
    };
    let unreadable_kind = match role {
        Role::Start => HookKind::StartEntryPoint,
        _ => HookKind::PthImport,
    };
    let content = match content {
        Ok(content) => content,
        Err(err) => {
            return Some(StartupHook {
                path: path.to_string(),
                kind: unreadable_kind,
                code: Vec::new(),
                unreadable: Some(format!("{err:#}")),
            });
        }
    };
    if role == Role::Start {
        return hook(
            path,
            HookKind::StartEntryPoint,
            pth::start_entries(&content),
        );
    }
    let lines = pth::pth_lines(&content);
    if lines.imports.is_empty() {
        hook(path, HookKind::PthPath, lines.paths)
    } else {
        hook(path, HookKind::PthImport, lines.imports)
    }
}

pub fn inspect_wheel(data: &[u8]) -> Result<WheelFacts> {
    let mut hooks = Vec::new();
    for entry in central_entries(data)? {
        let Some(role) = strongest_role(&entry.name)? else {
            continue;
        };
        hooks.extend(member_hook(data, &entry, &entry.name, role));
    }
    Ok(WheelFacts {
        startup_hooks: hooks,
    })
}

pub(crate) fn wheel_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("sloppy-joe (https://github.com/brennhill/sloppy-joe)")
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .expect("failed to build HTTP client")
}

/// Largest wheel downloaded for inspection.
pub(crate) const MAX_WHEEL_BYTES: u64 = 128 * 1024 * 1024;

/// Accept a wheel URL only on PyPI's file host (same scheme, host and port),
/// without credentials, query or fragment, ending in `.whl`.
pub(crate) fn validate_wheel_url(raw: &str, files_origin: &reqwest::Url) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw)
        .map_err(|e| anyhow!("wheel URL {raw:?} is not a valid URL: {e}"))?;
    if url.scheme() != "https" && files_origin.scheme() == "https" {
        bail!("wheel URL {raw:?} does not use HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("wheel URL {raw:?} embeds credentials");
    }
    if url.scheme() != files_origin.scheme()
        || url.host_str() != files_origin.host_str()
        || url.port_or_known_default() != files_origin.port_or_known_default()
    {
        bail!(
            "wheel URL {raw:?} is not on the PyPI file host {}",
            files_origin.host_str().unwrap_or("")
        );
    }
    if url.query().is_some() || url.fragment().is_some() || !url.path().ends_with(".whl") {
        bail!("wheel URL {raw:?} is not a plain .whl path");
    }
    Ok(url)
}

/// Download a wheel, check its sha256 against the digest PyPI published, and
/// inspect it. A missing digest is an error: unhashed bytes are never read.
pub(crate) async fn fetch_and_inspect(
    client: &reqwest::Client,
    files_origin: &reqwest::Url,
    file: &PypiFile,
) -> Result<WheelFacts> {
    let expected = file
        .sha256
        .clone()
        .ok_or_else(|| anyhow!("PyPI publishes no sha256 digest for {}", file.filename))?;
    let url = validate_wheel_url(&file.url, files_origin)?;
    let bytes = download_tarball(client, &url, MAX_WHEEL_BYTES).await?;
    tokio::task::spawn_blocking(move || {
        use sha2::Digest;
        let actual = hex(&sha2::Sha256::digest(&bytes));
        if actual != expected {
            return Err(IntegrityMismatch(format!(
                "wheel sha256 {actual} does not match the digest PyPI published ({expected})"
            ))
            .into());
        }
        inspect_wheel(&bytes)
    })
    .await
    .map_err(|e| anyhow!("wheel inspection task failed: {e}"))?
}

#[cfg(test)]
#[path = "wheel_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "wheel_fetch_tests.rs"]
mod fetch_tests;

#[cfg(test)]
#[path = "wheel_layout_tests.rs"]
mod layout_tests;
