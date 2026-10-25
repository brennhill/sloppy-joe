//! Files a wheel installs outside `site-packages` that the interpreter runs.
//!
//! pip and uv install `<dist>.data/data/<rest>` at `<prefix>/<rest>` (the `data` scheme
//! path is `sys.prefix` itself) and `<dist>.data/scripts/<rest>` in `bin` (`Scripts` on
//! Windows), replacing any file already there. `purelib`/`platlib` go to `site-packages`
//! (see `layout`) and `headers` to the include directory, which nothing imports. So:
//!
//! - A base (non-venv) interpreter, as in Docker images and system installs, keeps its
//!   standard library at `<prefix>/lib/pythonX.Y` (`lib64` for some distributions, `Lib`,
//!   `DLLs` and `python3XY.zip` on Windows). A file there replaces or adds a stdlib module,
//!   and modules such as `encodings` run at every start.
//! - A console script runs with `bin/` first on `sys.path`, so `bin/json.py` is imported
//!   instead of the standard library's `json` by every script in the environment.
//! - `bin/python*`, the activation scripts, `pyvenv.cfg` and the Windows interpreter files
//!   at the prefix are the environment itself.
//!
//! Anything else in `bin` is an ordinary script, and other data files (`share/`, `etc/`,
//! `include/`, shared libraries in `lib/`) are not run by Python.

use super::layout::{Role, SITE_DIRS, module_stem};
use super::stdlib::is_stdlib_module;

/// The overwrite role of a normalized member path, if it installs outside `site-packages`
/// into the standard library or the environment.
pub(super) fn role(segments: &[String]) -> Option<Role> {
    let [data, key, rest @ ..] = segments else {
        return None;
    };
    if !data.to_ascii_lowercase().ends_with(".data") || rest.is_empty() {
        return None;
    }
    match key.to_ascii_lowercase().as_str() {
        "scripts" => scripts_role(rest),
        "data" => data_role(rest),
        _ => None,
    }
}

/// A path relative to the environment prefix.
fn data_role(rest: &[String]) -> Option<Role> {
    let lower: Vec<String> = rest.iter().map(|s| s.to_ascii_lowercase()).collect();
    match lower.as_slice() {
        [file] => prefix_file_role(file),
        [first, ..] if first == "bin" || first == "scripts" => scripts_role(&rest[1..]),
        // Windows user scheme: `<userbase>\Python3XY\Scripts`.
        [first, second, ..] if first.starts_with("python") && second == "scripts" => {
            scripts_role(&rest[2..])
        }
        [first, ..] if first == "dlls" => Some(Role::Stdlib),
        [first, tail @ ..] if first == "lib" || first == "lib64" => lib_role(tail),
        _ => None,
    }
}

/// `lib/<tail>`: `lib/pythonX.Y/` (POSIX) is the standard library except its
/// `site-packages`; `Lib\` (Windows, any case) is too, for anything importable.
fn lib_role(tail: &[String]) -> Option<Role> {
    let (first, after) = tail.split_first()?;
    if is_site_dir(first) {
        return None;
    }
    if is_interpreter_dir(first) {
        return match after.first() {
            Some(next) if is_site_dir(next) => None,
            _ => Some(Role::Stdlib),
        };
    }
    windows_importable(tail.last()?).then_some(Role::Stdlib)
}

/// A file at the top of the prefix (Windows keeps the interpreter there).
fn prefix_file_role(file: &str) -> Option<Role> {
    if is_interpreter_dir(file) && file.ends_with(".zip") {
        return Some(Role::Stdlib);
    }
    let interpreter_binary = ["exe", "dll"].iter().any(|ext| {
        file.strip_suffix(&format!(".{ext}"))
            .is_some_and(is_interpreter_name)
    });
    let runtime = file.starts_with("vcruntime") && file.ends_with(".dll");
    let config = file == "pyvenv.cfg" || file.ends_with("._pth");
    (interpreter_binary || runtime || config).then_some(Role::Environment)
}

/// A path relative to the scripts directory (`bin`, `Scripts`).
fn scripts_role(rest: &[String]) -> Option<Role> {
    let (first, more) = rest.split_first()?;
    let lower = first.to_ascii_lowercase();
    let environment_file =
        is_interpreter_name(lower.trim_end_matches(".exe")) || is_activation_script(&lower);
    if more.is_empty() && environment_file {
        return Some(Role::Environment);
    }
    // A package directory (`bin/json/`) or a module file imports as the module.
    let module = !more.is_empty() || importable(&lower);
    (module && is_stdlib_module(&module_stem(first))).then_some(Role::Stdlib)
}

fn is_site_dir(segment: &str) -> bool {
    SITE_DIRS.contains(&segment.to_ascii_lowercase().as_str())
}

/// `pythonX.Y`, `python3XY.zip`, `pypy3.10`: an interpreter's library name.
fn is_interpreter_dir(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    lower.starts_with("python") || lower.starts_with("pypy")
}

/// `python`, `python3`, `python3.12`, `python3.13t`, `pythonw`, `python312_d`, `pypy3`.
fn is_interpreter_name(name: &str) -> bool {
    let version = ["pythonw", "python", "pypy"]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix));
    version.is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || "._dt".contains(c)))
}

/// The scripts `venv` and `virtualenv` write: `activate`, `activate.<shell>`,
/// `Activate.ps1`, `activate_this.py`, `deactivate.bat`, ...
fn is_activation_script(name: &str) -> bool {
    name == "activate"
        || name.starts_with("activate.")
        || name == "activate_this.py"
        || name.starts_with("deactivate.")
}

fn extension(name: &str) -> &str {
    name.rsplit_once('.').map_or("", |(_, ext)| ext)
}

/// Loaded by the import system on some platform.
fn importable(name: &str) -> bool {
    matches!(extension(name), "py" | "pyc" | "pyw" | "pyd" | "so")
}

/// Loaded by the import system on Windows (`.so` is a POSIX extension module).
fn windows_importable(name: &str) -> bool {
    matches!(
        extension(&name.to_ascii_lowercase()),
        "py" | "pyc" | "pyw" | "pyd"
    )
}
