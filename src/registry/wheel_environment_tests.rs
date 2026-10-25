//! Files a wheel's `<dist>.data/` directory installs outside `site-packages`: pip and uv
//! install `data/` under the environment prefix and `scripts/` in `bin`/`Scripts`, so a
//! wheel can write into the standard library, shadow it for console scripts, or replace
//! the interpreter and activation scripts.

use super::tests::zip;
use super::*;

fn kinds(name: &str) -> Vec<HookKind> {
    let wheel = zip(&[(name, b"import os\n", false)]);
    inspect_wheel(&wheel)
        .unwrap()
        .startup_hooks
        .into_iter()
        .map(|h| h.kind)
        .collect()
}

#[test]
fn data_scheme_files_in_the_standard_library_are_stdlib_overwrites() {
    for name in [
        // POSIX base interpreters (system, Docker): <prefix>/lib/pythonX.Y is the stdlib.
        "sj-1.0.data/data/lib/python3.12/site.py",
        "sj-1.0.data/data/lib/python3.12/encodings/aliases.py",
        "sj-1.0.data/data/lib/python3.13t/lib-dynload/_ssl.cpython-313t-darwin.so",
        "sj-1.0.data/data/lib64/python3.12/lib-dynload/_ssl.so",
        "sj-1.0.data/data/lib/python312.zip",
        "sj-1.0.data/data/lib/pypy3.10/os.py",
        "sj-1.0.data/data/lib/python3.12/usercustomize.py",
        "sj-1.0.data/data/lib/python3.12/site-packages/../json/__init__.py",
        "sj-1.0.data/purelib/../data/lib/python3.12/site.py",
        "sj-1.0.DATA/DATA/LIB/PYTHON3.12/site.py",
        // Windows: <prefix>\Lib, <prefix>\DLLs and <prefix>\python3XY.zip.
        "sj-1.0.data/data/Lib/site.py",
        "sj-1.0.data/data/Lib/encodings/utf_8.py",
        "sj-1.0.data/data/Lib/__pycache__/os.cpython-312.pyc",
        "sj-1.0.data/data/lib/sjnew.pyd",
        "sj-1.0.data/data/DLLs/_ssl.pyd",
        "sj-1.0.data/data/DLLs/libssl-3.dll",
        "sj-1.0.data/data/python312.zip",
        "sj-1.0.data\\data\\Lib\\site.py",
    ] {
        assert_eq!(kinds(name), [HookKind::StdlibOverwrite], "{name}");
    }
}

#[test]
fn stdlib_named_modules_beside_console_scripts_are_stdlib_overwrites() {
    // A console script runs with its own directory (bin/) first on sys.path, so bin/json.py is
    // imported instead of the standard library's json by every script in the environment.
    for name in [
        "sj-1.0.data/scripts/json.py",
        "sj-1.0.data/scripts/typing.pyc",
        "sj-1.0.data/scripts/cProfile.py",
        "sj-1.0.data/scripts/json/__init__.py",
        "sj-1.0.data/scripts/_ssl.cpython-312-darwin.so",
        "sj-1.0.data/data/bin/re.py",
        "sj-1.0.data/data/Scripts/typing.pyd",
        "sj-1.0.data/data/Python312/Scripts/json.py",
    ] {
        assert_eq!(kinds(name), [HookKind::StdlibOverwrite], "{name}");
    }
}

#[test]
fn interpreter_and_activation_files_are_environment_overwrites() {
    for name in [
        "sj-1.0.data/scripts/activate",
        "sj-1.0.data/scripts/activate.fish",
        "sj-1.0.data/scripts/Activate.ps1",
        "sj-1.0.data/scripts/activate.bat",
        "sj-1.0.data/scripts/deactivate.bat",
        "sj-1.0.data/scripts/activate_this.py",
        "sj-1.0.data/scripts/python",
        "sj-1.0.data/scripts/python3",
        "sj-1.0.data/scripts/python3.12",
        "sj-1.0.data/scripts/python3.13t",
        "sj-1.0.data/scripts/python.exe",
        "sj-1.0.data/scripts/pythonw.exe",
        "sj-1.0.data/scripts/pypy3",
        "sj-1.0.data/data/bin/python3",
        "sj-1.0.data/data/Scripts/python.exe",
        "sj-1.0.data/data/pyvenv.cfg",
        "sj-1.0.data/data/python312.dll",
        "sj-1.0.data/data/python3.dll",
        "sj-1.0.data/data/python.exe",
        "sj-1.0.data/data/vcruntime140.dll",
        "sj-1.0.data/data/python312._pth",
    ] {
        assert_eq!(kinds(name), [HookKind::EnvironmentOverwrite], "{name}");
    }
}

#[test]
fn the_interpreters_own_library_and_binaries_are_environment_overwrites() {
    // An --enable-shared interpreter (the official Docker images) loads
    // <prefix>/lib/libpython3.12.so.1.0 through its RUNPATH at every start; a macOS framework
    // build loads <prefix>/Python and runs <prefix>/Resources/Python.app/Contents/MacOS/Python.
    for name in [
        "sj-1.0.data/data/lib/libpython3.12.so.1.0",
        "sj-1.0.data/data/lib/libpython3.12.so",
        "sj-1.0.data/data/lib/libpython3.12.dylib",
        "sj-1.0.data/data/lib/libpython3.so",
        "sj-1.0.data/data/lib/libpython3.7m.so.1.0",
        "sj-1.0.data/data/lib/libpython3.13t.so.1.0",
        "sj-1.0.data/data/lib64/libpython3.12.so.1.0",
        "sj-1.0.data/data/lib/libpypy3.10-c.so",
        "sj-1.0.data/data/LIB/LIBPYTHON3.12.DYLIB",
        "sj-1.0.data/data/Python",
        "sj-1.0.data/data/Resources/Python.app/Contents/MacOS/Python",
        "sj-1.0.data/data/Resources/Python.app/Contents/Info.plist",
        "sj-1.0.data/scripts/python3.7m",
        "sj-1.0.data/scripts/python3.7dm",
        "sj-1.0.data/data/bin/python3.7m",
    ] {
        assert_eq!(kinds(name), [HookKind::EnvironmentOverwrite], "{name}");
    }
}

#[test]
fn libraries_the_interpreter_and_its_stdlib_load_are_environment_overwrites() {
    // conda environments and python.org macOS builds load these from <prefix>/lib (RPATH
    // `$ORIGIN/../..`, absolute install names): a wheel's copy replaces the interpreter's.
    for name in [
        "sj-1.0.data/data/lib/libssl.so.3",
        "sj-1.0.data/data/lib/libcrypto.3.dylib",
        "sj-1.0.data/data/lib/libffi.so.8",
        "sj-1.0.data/data/lib/libz.so.1",
        "sj-1.0.data/data/lib/libbz2.so.1.0",
        "sj-1.0.data/data/lib/liblzma.so.5",
        "sj-1.0.data/data/lib/libzstd.so.1",
        "sj-1.0.data/data/lib/libsqlite3.so.0",
        "sj-1.0.data/data/lib/libmpdec.so.4",
        "sj-1.0.data/data/lib/libexpat.so.1",
        "sj-1.0.data/data/lib/libreadline.so.8",
        "sj-1.0.data/data/lib/libncursesw.so.6",
        "sj-1.0.data/data/lib/libtinfow.so.6",
        "sj-1.0.data/data/lib/libtcl8.6.dylib",
        "sj-1.0.data/data/lib/libtcl9tk9.0.so",
        "sj-1.0.data/data/lib/libtk8.6.so",
        "sj-1.0.data/data/lib/libicuuc.so.78",
        "sj-1.0.data/data/lib/libuuid.so.1",
        "sj-1.0.data/data/lib/libgdbm_compat.so.4",
        "sj-1.0.data/data/lib/libstdc++.so.6",
        "sj-1.0.data/data/lib/libgcc_s.so.1",
        "sj-1.0.data/data/lib/libc.so.6",
        "sj-1.0.data/data/lib/libm.so.6",
        "sj-1.0.data/data/lib/libssl-3-x64.dll",
        "sj-1.0.data/data/lib64/libffi.so.8",
    ] {
        assert_eq!(kinds(name), [HookKind::EnvironmentOverwrite], "{name}");
    }
}

#[test]
fn any_shared_library_in_a_multiarch_directory_is_an_environment_overwrite() {
    // Debian and Ubuntu list <prefix>/lib/<triplet> (prefix /usr/local) ahead of the system's
    // /lib/<triplet>, so after the next ldconfig it provides that library to every program.
    for name in [
        "sj-1.0.data/data/lib/x86_64-linux-gnu/libz.so.1",
        "sj-1.0.data/data/lib/aarch64-linux-gnu/libcurl.so.4",
        "sj-1.0.data/data/lib/arm-linux-gnueabihf/libsj.so",
    ] {
        assert_eq!(kinds(name), [HookKind::EnvironmentOverwrite], "{name}");
    }
}

#[test]
fn other_libraries_and_files_in_the_prefix_lib_are_not_hooks() {
    // Intel's mkl, intel-openmp, tbb and intel-cmplr-lib-rt wheels install dozens of libraries
    // in <prefix>/lib under their own names; nothing the interpreter loads is replaced.
    for name in [
        "sj-1.0.data/data/lib/libmkl_core.so.3",
        "sj-1.0.data/data/lib/libiomp5.so",
        "sj-1.0.data/data/lib/libtbb.so.12",
        "sj-1.0.data/data/lib/libimf.so",
        "sj-1.0.data/data/lib/libzmq.so.5",
        "sj-1.0.data/data/lib/libcurl.so.4",
        "sj-1.0.data/data/lib/libmagic.so",
        "sj-1.0.data/data/lib/libpython3.12.a",
        "sj-1.0.data/data/lib/libssl.a",
        "sj-1.0.data/data/lib/libsj.so.1.2",
        "sj-1.0.data/data/lib/sj/libssl.so.3",
        "sj-1.0.data/data/lib/x86_64-linux-gnu/pkgconfig/sj.pc",
        "sj-1.0.data/data/lib/x86_64-linux-gnu/libsj.a",
        "sj-1.0.data/data/share/libpython3.12.so",
        "sj-1.0.data/data/Library/bin/libiomp5md.dll",
        "sj-1.0.data/data/python-sj.txt",
        "sj-1.0.data/data/share/Python",
        "sj-1.0.data/data/Resources/sj.app/Contents/MacOS/Python",
        "sj-1.0.data/scripts/python3.7mx",
    ] {
        assert!(kinds(name).is_empty(), "{name}: {:?}", kinds(name));
    }
}

#[test]
fn the_windows_prefix_is_a_site_directory() {
    // On Windows site.getsitepackages() lists sys.prefix itself, so <dist>.data/data/x.pth
    // (installed at <prefix>\x.pth) is processed at every start, in venvs too.
    assert_eq!(kinds("sj-1.0.data/data/evil.pth"), [HookKind::PthImport]);
    assert_eq!(
        kinds("sj-1.0.data/data/sitecustomize.py"),
        [HookKind::CustomizeModule]
    );
    let start = zip(&[("sj-1.0.data/data/sj.start", b"sj.boot:run\n", false)]);
    let found = inspect_wheel(&start).unwrap().startup_hooks;
    assert_eq!(found[0].kind, HookKind::StartEntryPoint);
}

#[test]
fn ordinary_data_scripts_and_headers_are_not_hooks() {
    for name in [
        "sj-1.0.data/scripts/sj-tool",
        "sj-1.0.data/scripts/sj_tool.py",
        "sj-1.0.data/scripts/rst2html.py",
        "sj-1.0.data/scripts/json",
        "sj-1.0.data/scripts/pythonize",
        "sj-1.0.data/scripts/activate-global-python-argcomplete",
        "sj-1.0.data/scripts/sub/json.py",
        "sj-1.0.data/scripts/pip",
        "sj-1.0.data/data/bin/sj-tool",
        "sj-1.0.data/data/share/jupyter/kernels/sj/kernel.json",
        "sj-1.0.data/data/etc/sj.conf",
        "sj-1.0.data/data/include/sj.h",
        "sj-1.0.data/data/lib/libsj.so",
        "sj-1.0.data/data/lib/libsj.dylib",
        "sj-1.0.data/data/lib/pkgconfig/sj.pc",
        "sj-1.0.data/data/lib/cmake/sj/sjConfig.cmake",
        "sj-1.0.data/data/lib/python3.12/site-packages/sj/mod.py",
        "sj-1.0.data/data/Lib/site-packages/sj/mod.py",
        "sj-1.0.data/data/sj.dll",
        "sj-1.0.data/headers/sj.h",
        "sj-1.0.data/headers/lib/python3.12/site.py",
        "sj-1.0.data/purelib/lib/python3.12/site.py",
        "lib/python3.12/site.py",
        "sj/json.py",
    ] {
        assert!(kinds(name).is_empty(), "{name}: {:?}", kinds(name));
    }
}

#[test]
fn the_stdlib_name_list_is_sorted_lowercase_and_has_no_duplicates() {
    let names = super::stdlib::STDLIB_MODULES;
    assert!(names.windows(2).all(|w| w[0] < w[1]));
    assert!(names.iter().all(|n| *n == n.to_ascii_lowercase()));
    for name in [
        "json",
        "encodings",
        "site",
        "os",
        "typing",
        "_ssl",
        "cprofile",
    ] {
        assert!(super::stdlib::is_stdlib_module(name), "{name}");
    }
    assert!(!super::stdlib::is_stdlib_module("sitecustomize"));
}
