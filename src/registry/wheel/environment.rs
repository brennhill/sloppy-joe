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
//!   at the prefix are the environment itself, as are a macOS framework build's `Python`
//!   (the interpreter as a library) and `Resources/Python.app` (the binary `bin/python3`
//!   executes).
//! - Shared libraries in `lib/` are not always inert. An `--enable-shared` interpreter (the
//!   official Docker images) loads `lib/libpython3.12.so.1.0` through its `RUNPATH` at every
//!   start, and conda environments and python.org macOS builds load the libraries the
//!   standard library links (`libssl`, `libffi`, `libz`, ...) from `lib/` (`RPATH`
//!   `$ORIGIN/../..`, absolute install names). A wheel's copy replaces them. On Debian and
//!   Ubuntu `lib/<multiarch>/` (`/usr/local/lib/x86_64-linux-gnu`) precedes the system's
//!   library directories, so after the next `ldconfig` any library there replaces the
//!   system's copy for every program.
//!
//! Anything else in `bin` is an ordinary script, and other data files (`share/`, `etc/`,
//! `include/`, `lib/pkgconfig/`, static archives, libraries in `lib/` under names the
//! interpreter does not load, such as Intel's `libmkl_*`) are not run by Python.

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
        [first, tail @ ..] => prefix_dir_role(first, tail),
        [] => None,
    }
}

/// `<first>/<tail>` under the prefix, `<first>` lowercased.
fn prefix_dir_role(first: &str, tail: &[String]) -> Option<Role> {
    match first {
        "dlls" => Some(Role::Stdlib),
        "lib" | "lib64" => lib_role(tail),
        // A macOS framework build: `bin/python3` executes `Resources/Python.app`.
        "resources" => tail
            .first()
            .is_some_and(|app| app == "python.app")
            .then_some(Role::Environment),
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
    if replaces_loaded_library(tail) {
        return Some(Role::Environment);
    }
    windows_importable(tail.last()?).then_some(Role::Stdlib)
}

/// `lib/<tail>` is a shared library the interpreter loads (`lib/libssl.so.3`), or any shared
/// library in a Debian multiarch directory (`lib/x86_64-linux-gnu/libz.so.1`).
fn replaces_loaded_library(tail: &[String]) -> bool {
    match tail {
        [file] => is_shared_library(file) && is_interpreter_library(file),
        [dir, file] => dir.contains("-linux-") && is_shared_library(file),
        _ => false,
    }
}

/// `libz.so`, `libz.so.1.3`, `libz.1.dylib`, `zlib1.dll`.
fn is_shared_library(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".so", ".dylib", ".dll"]
        .iter()
        .any(|ext| lower.ends_with(ext))
        || lower.contains(".so.")
}

/// Library names the interpreter and its standard-library extension modules link, after
/// trailing version digits are dropped (`libsqlite3` is `libsqlite`, `libtcl8.6` is `libtcl`).
const INTERPRETER_LIBRARIES: [&str; 30] = [
    "libatomic",
    "libb", // libb2 (_blake2)
    "libbz",
    "libc",
    "libcrypt",
    "libcrypto",
    "libdb",
    "libdl",
    "libedit",
    "libexpat",
    "libffi",
    "libgcc_s",
    "libhistory",
    "libiconv",
    "libintl",
    "liblzma",
    "libm",
    "libmpdec",
    "libnsl",
    "libpthread",
    "libreadline",
    "librt",
    "libsqlite",
    "libssl",
    "libstdc++",
    "libtirpc",
    "libutil",
    "libuuid",
    "libz",
    "libzstd",
];

/// Library families matched by prefix: `libpython3.12`, `libpypy3.10-c`, `libtcl9tk9.0`,
/// `libicuuc`, `libncursesw`, `libgdbm_compat`.
const INTERPRETER_LIBRARY_FAMILIES: [&str; 11] = [
    "libpython",
    "libpypy",
    "libtcl",
    "libtk",
    "libicu",
    "libncurses",
    "libtinfo",
    "libpanel",
    "libform",
    "libmenu",
    "libgdbm",
];

fn is_interpreter_library(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let end = lower.find(['.', '-']).unwrap_or(lower.len());
    let stem = lower[..end].trim_end_matches(|c: char| c.is_ascii_digit());
    INTERPRETER_LIBRARIES.contains(&stem)
        || INTERPRETER_LIBRARY_FAMILIES
            .iter()
            .any(|family| stem.starts_with(family))
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
    // A macOS framework build's interpreter library, `Python.framework/Versions/X.Y/Python`.
    let framework = file == "python";
    (interpreter_binary || runtime || config || framework).then_some(Role::Environment)
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

/// `python`, `python3`, `python3.12`, `python3.13t`, `python3.7m`, `pythonw`, `python312_d`,
/// `pypy3`.
fn is_interpreter_name(name: &str) -> bool {
    let version = ["pythonw", "python", "pypy"]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix));
    version.is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || "._dtm".contains(c)))
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
