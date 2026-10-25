//! PyPI wheel inspection: Python startup hooks.
//!
//! A wheel is a zip. Anything installed at the top of `site-packages` runs
//! without being imported: `*.pth` lines starting with `import` execute at
//! every interpreter start, and `sitecustomize` / `usercustomize` are imported
//! by `site`. Compromised releases (LiteLLM 1.82.8, the Hades campaign) used
//! exactly this to run before any application code. A wheel's `<dist>.data/`
//! directory can also install outside `site-packages`, into the standard
//! library or over the interpreter and activation scripts (`environment`).
//!
//! The wheel is read in memory and never extracted. Anything this reader
//! cannot model, or that installers could read differently (zip64, a second
//! central directory, mismatched local headers, ambiguous member names: see
//! `archive` and `layout`), is an error, not a pass. Unknown compression and
//! oversize hook files are reported as unreadable hooks.

mod archive;
pub(crate) mod core_metadata;
mod environment;
mod layout;
mod pth;
mod stdlib;

use super::npm_tarball::{IntegrityMismatch, download_tarball, hex};
use super::pypi_release::PypiFile;
use anyhow::{Result, anyhow, bail};
use archive::{Entry, central_entries};
use layout::Role;
use serde::{Deserialize, Serialize};

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
    /// A `<dist>.data/` file installed outside `site-packages` into the
    /// standard library of a base interpreter (`lib/pythonX.Y/`, Windows
    /// `Lib\`, `DLLs\`, the stdlib zip), or a stdlib-named module beside the
    /// console scripts, which import it instead of the standard library's.
    StdlibOverwrite,
    /// A `<dist>.data/` file that replaces the environment's interpreter
    /// (`bin/python3`, `python.exe`, `python3XY.dll`), its configuration
    /// (`pyvenv.cfg`, `._pth`) or an activation script.
    EnvironmentOverwrite,
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

/// The strongest startup role the entry takes under any of its names, and
/// the name that gives it. Directory names (`.../`) install nothing.
fn strongest_role(entry: &Entry) -> Result<Option<(Role, &str)>> {
    let mut best: Option<(Role, &str)> = None;
    for name in entry.names.iter().filter(|n| !n.ends_with('/')) {
        if let Some(role) = layout::roles(name)?.into_iter().max()
            && best.is_none_or(|(strongest, _)| role > strongest)
        {
            best = Some((role, name));
        }
    }
    Ok(best)
}

/// Hooks that are reported for what they are, without reading their content.
fn unread_kind(role: Role) -> Option<HookKind> {
    match role {
        Role::Customize => Some(HookKind::CustomizeModule),
        Role::Stdlib => Some(HookKind::StdlibOverwrite),
        Role::Environment => Some(HookKind::EnvironmentOverwrite),
        Role::Pth | Role::Start => None,
    }
}

fn hook(path: &str, kind: HookKind, mut code: Vec<String>) -> Option<StartupHook> {
    let runs_by_content = matches!(
        kind,
        HookKind::PthImport | HookKind::PthPath | HookKind::StartEntryPoint
    );
    if code.is_empty() && runs_by_content {
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

/// The hook a member installs: customize modules and files outside
/// `site-packages` are hooks unread; `.pth` and `.start` files are hooks when
/// a line acts at startup, or when they cannot be read (reported, never skipped).
fn member_hook(data: &[u8], entry: &Entry, path: &str, role: Role) -> Option<StartupHook> {
    if let Some(kind) = unread_kind(role) {
        return hook(path, kind, Vec::new());
    }
    let content = archive::entry_bytes(data, entry, MAX_HOOK_BYTES);
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
        let Some((role, path)) = strongest_role(&entry)? else {
            continue;
        };
        hooks.extend(member_hook(data, &entry, path, role));
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

#[cfg(test)]
#[path = "wheel_pth_tests.rs"]
mod pth_tests;

#[cfg(test)]
#[path = "wheel_archive_tests.rs"]
mod archive_tests;

#[cfg(test)]
#[path = "wheel_environment_tests.rs"]
mod environment_tests;
