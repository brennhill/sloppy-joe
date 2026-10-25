//! Where wheel members land: names are read the way pip and uv install them
//! (`./`, `..`, `//`, backslashes, Windows trailing dots), and a name no
//! installer reads one way is refused instead of skipped.

use super::tests::zip;
use super::*;

fn hooks(entries: &[(&str, &[u8])]) -> Vec<StartupHook> {
    let entries: Vec<(&str, &[u8], bool)> = entries.iter().map(|(n, c)| (*n, *c, false)).collect();
    inspect_wheel(&zip(&entries)).unwrap().startup_hooks
}

fn hook_paths(entries: &[(&str, &[u8])]) -> Vec<String> {
    hooks(entries).into_iter().map(|h| h.path).collect()
}

const IMPORT: &[u8] = b"import os\n";

#[test]
fn dot_parent_and_doubled_separators_are_resolved_before_matching() {
    for name in [
        "./dotseg.pth",
        "sjparentseg/../parentseg.pth",
        "sjdblslash-1.0.data/purelib//dblslash.pth",
        ".//./x.pth",
        "pkg/./../x.pth",
        "sj-1.0.data/./platlib/x.pth",
    ] {
        assert_eq!(hook_paths(&[(name, IMPORT)]), [name], "{name}");
    }
}

#[test]
fn data_scheme_files_landing_in_a_site_packages_directory_are_hooks() {
    for name in [
        "sj-1.0.data/data/lib/python3.12/site-packages/datascheme.pth",
        "sj-1.0.data/data/Lib/site-packages/x.pth",
        "sj-1.0.data/data/lib/python3/dist-packages/x.pth",
        "sj-1.0.data/headers/../data/lib/python3.13t/site-packages/x.pth",
        "sj-1.0.DATA/PURELIB/x.pth",
    ] {
        assert_eq!(hook_paths(&[(name, IMPORT)]), [name], "{name}");
    }
    let customize = hooks(&[(
        "sj-1.0.data/data/lib/python3.12/site-packages/sitecustomize.py",
        b"x",
    )]);
    assert_eq!(customize[0].kind, HookKind::CustomizeModule);
}

#[test]
fn customize_modules_in_any_importable_form_are_hooks() {
    for name in [
        "sitecustomize/__init__.py",
        "usercustomize/sub/mod.py",
        "sitecustomize.cpython-312-darwin.so",
        "usercustomize.abi3.so",
        "sitecustomize.pyd",
        "sitecustomize.pyw",
        "SiteCustomize.py",
        "__pycache__/sitecustomize.cpython-312.pyc",
        "sj-1.0.data/purelib/sitecustomize/__init__.py",
        "./sitecustomize.py",
    ] {
        let found = hooks(&[(name, b"print(1)\n")]);
        assert_eq!(found.len(), 1, "{name}");
        assert_eq!(found[0].kind, HookKind::CustomizeModule, "{name}");
    }
}

#[test]
fn customize_names_below_the_top_level_are_not_hooks() {
    assert!(
        hooks(&[
            ("pkg/sitecustomize.py", b"x"),
            ("pkg/sitecustomize/__init__.py", b"x"),
            ("pkg/__pycache__/sitecustomize.cpython-312.pyc", b"x"),
            ("sj-1.0.data/scripts/sitecustomize.py", b"x"),
            ("pkg/site-packages/x.pth", IMPORT),
        ])
        .is_empty()
    );
}

#[test]
fn backslash_names_are_read_both_as_a_literal_character_and_as_a_separator() {
    // POSIX keeps `pkg\x.pth` as one top-level file name; Windows reads `pkg\..\x.pth` as x.pth.
    for name in [
        "pkg\\x.pth",
        "pkg\\..\\x.pth",
        "sj-1.0.data\\purelib\\x.pth",
    ] {
        assert_eq!(hook_paths(&[(name, IMPORT)]), [name], "{name}");
    }
    let found = hooks(&[("pkg\\..\\sitecustomize\\__init__.py", b"x")]);
    assert_eq!(found[0].kind, HookKind::CustomizeModule);
}

#[test]
fn windows_trailing_dots_and_spaces_are_dropped_before_matching() {
    for name in ["x.pth.", "x.pth ", "x.pth. ."] {
        assert_eq!(hook_paths(&[(name, IMPORT)]), [name], "{name}");
    }
    let found = hooks(&[("sitecustomize.py.", b"x")]);
    assert_eq!(found[0].kind, HookKind::CustomizeModule);
}

#[test]
fn ambiguous_names_make_the_wheel_unverifiable() {
    for name in [
        "/abs.pth",
        "\\abs.pth",
        "../escape.pth",
        "pkg/../../escape.py",
        "sj-1.0.data/data/../../../x.pth",
        "C:x.pth",
        "x.pth::$DATA",
        "pkg/ /x.py",
        "pkg/.../x.py",
    ] {
        let wheel = zip(&[(name, IMPORT, false)]);
        let error = inspect_wheel(&wheel).unwrap_err().to_string();
        assert!(error.contains(name), "{name}: {error}");
    }
}

#[test]
fn a_pth_that_only_adds_directories_is_a_path_hook() {
    // A directory a .pth adds to sys.path is searched for sitecustomize at startup, and another
    // wheel can supply that module, so a path line is reported even when this wheel ships none.
    let found = hooks(&[
        ("pathcustom.pth", b"# comment\nsjpathcustom_dir\n"),
        ("sjpathcustom_dir/usercustomize.py", b"x"),
    ]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, HookKind::PthPath);
    assert_eq!(found[0].code, ["sjpathcustom_dir"]);
}

#[test]
fn comment_only_and_empty_pth_files_are_not_hooks() {
    assert!(hooks(&[("a.pth", b""), ("b.pth", b"# only a comment\n\n   \n")]).is_empty());
}

#[test]
fn start_files_with_entry_points_are_hooks() {
    // Python 3.15 (PEP 829) calls every `pkg.mod:callable` in a top-level `*.start` file.
    let found = hooks(&[
        ("sj.start", b"# entry\nsj._boot:run\n"),
        ("empty.start", b"# nothing\n"),
        ("pkg/nested.start", b"pkg.mod:run\n"),
    ]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, "sj.start");
    assert_eq!(found[0].kind, HookKind::StartEntryPoint);
    assert_eq!(found[0].code, ["sj._boot:run"]);
}
