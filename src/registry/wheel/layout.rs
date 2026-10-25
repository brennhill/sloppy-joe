//! Where a wheel member lands in `site-packages`, read the way installers read
//! member names.
//!
//! pip resolves each name with `os.path.normpath` (dropping `.`, empty
//! segments and `segment/..`; on Windows `\` is a separator too) and joins it
//! onto the install directory, so `./x.pth`, `pkg/../x.pth` and
//! `d.data/purelib//x.pth` all land at the top of `site-packages`. Windows also
//! drops trailing dots and spaces (`x.pth.` is `x.pth`). Every reading a name
//! has on some platform is checked, and the member is a hook if any reading
//! puts it where `site` looks at startup.
//!
//! Fail closed: a name that is absolute, climbs above the install directory,
//! contains `:` (drive letters, NTFS streams) or has a segment Windows reduces
//! to nothing (` `, `...`) has no single landing place, so it is an error
//! (the wheel is reported unverified) instead of being skipped.

use anyhow::{Result, bail};

/// What a member is, at the top of a `site-packages` directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Role {
    /// `*.pth`: processed by `site` at every start.
    Pth,
    /// `*.start` (Python 3.15): entry points called at every start.
    Start,
    /// `sitecustomize` / `usercustomize` as a module, extension, bytecode or package.
    Customize,
    /// Outside `site-packages`, in or ahead of the standard library (see `environment`).
    Stdlib,
    /// Outside `site-packages`: the interpreter, its configuration or activation scripts.
    Environment,
}

const CUSTOMIZE: [&str; 2] = ["sitecustomize", "usercustomize"];
pub(super) const SITE_DIRS: [&str; 2] = ["site-packages", "dist-packages"];
/// `<dist>.data/<key>/` subdirectories whose files go straight into `site-packages`.
const LIB_SCHEMES: [&str; 2] = ["purelib", "platlib"];

/// Every startup role `name` takes under any installer's reading of it.
pub(super) fn roles(name: &str) -> Result<Vec<Role>> {
    if name.contains(':') {
        bail!("wheel member '{name}' contains ':' (a drive letter or NTFS stream)");
    }
    let mut roles = Vec::new();
    for windows in [false, true] {
        let segments = segments(name, windows)?;
        for landing in landings(&segments) {
            roles.extend(role_at_top(&landing));
        }
        roles.extend(super::environment::role(&segments));
    }
    roles.sort();
    roles.dedup();
    Ok(roles)
}

/// The name's segments after `.`/`..`/empty-segment resolution, as pip's
/// `normpath` gives them on POSIX (`windows == false`) or Windows.
fn segments(name: &str, windows: bool) -> Result<Vec<String>> {
    let absolute = name.starts_with('/') || (windows && name.starts_with('\\'));
    if absolute {
        bail!("wheel member '{name}' is an absolute path");
    }
    let separators: &[char] = if windows { &['/', '\\'] } else { &['/'] };
    let mut kept: Vec<String> = Vec::new();
    for raw in name.split(separators) {
        match raw {
            "" | "." => {}
            ".." => {
                if kept.pop().is_none() {
                    bail!("wheel member '{name}' climbs above the install directory");
                }
            }
            _ if windows => {
                let trimmed = raw.trim_end_matches(['.', ' ']);
                if trimmed.is_empty() {
                    bail!("wheel member '{name}' has a segment Windows reduces to nothing");
                }
                kept.push(trimmed.to_string());
            }
            _ => kept.push(raw.to_string()),
        }
    }
    Ok(kept)
}

/// Paths relative to a `site-packages` directory where the member may land:
/// the root scheme (the name itself), `<dist>.data/purelib|platlib/<rest>`,
/// any `<dist>.data/<key>/.../site-packages/<rest>` (the `data` scheme
/// installs under the environment prefix, which holds `site-packages`), and
/// `<dist>.data/data/<rest>` itself: on Windows `site` treats the prefix as a
/// site directory too (`site.getsitepackages()` lists `sys.prefix`).
fn landings(segments: &[String]) -> Vec<Vec<String>> {
    let mut found = vec![segments.to_vec()];
    let [data, key, rest @ ..] = segments else {
        return found;
    };
    if !data.to_ascii_lowercase().ends_with(".data") || rest.is_empty() {
        return found;
    }
    let key = key.to_ascii_lowercase();
    if LIB_SCHEMES.contains(&key.as_str()) || key == "data" {
        found.push(rest.to_vec());
    }
    for (at, segment) in rest.iter().enumerate() {
        if SITE_DIRS.contains(&segment.to_ascii_lowercase().as_str()) && at + 1 < rest.len() {
            found.push(rest[at + 1..].to_vec());
        }
    }
    found
}

pub(super) fn module_stem(segment: &str) -> String {
    segment
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn role_at_top(landing: &[String]) -> Option<Role> {
    let (first, rest) = landing.split_first()?;
    let customize = |segment: &str| CUSTOMIZE.contains(&module_stem(segment).as_str());
    match rest {
        // A package directory (`sitecustomize/__init__.py`) imports as the module.
        [_, ..] if customize(first) => Some(Role::Customize),
        [cached] if first == "__pycache__" && customize(cached) => Some(Role::Customize),
        [_, ..] => None,
        [] if customize(first) => Some(Role::Customize),
        [] => {
            let lower = first.to_ascii_lowercase();
            if lower.ends_with(".pth") {
                Some(Role::Pth)
            } else if lower.ends_with(".start") {
                Some(Role::Start)
            } else {
                None
            }
        }
    }
}
