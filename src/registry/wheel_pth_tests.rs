//! `.pth` lines are split and stripped the way every supported Python reads
//! them: universal newlines (3.10-3.11), `str.splitlines` after a UTF-8 BOM
//! (3.12+), leading whitespace stripped before the `import` test (3.15), and
//! the locale-encoding fallback for files that are not UTF-8.

use super::tests::zip;
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

const HOOK: &str = "import os; os.system('x')";

fn pth_hook(content: &[u8]) -> Option<StartupHook> {
    let mut hooks = inspect_wheel(&zip(&[("t.pth", content, false)]))
        .unwrap()
        .startup_hooks;
    assert!(hooks.len() <= 1);
    hooks.pop()
}

fn runs_import(content: &[u8]) -> bool {
    pth_hook(content).is_some_and(|h| h.kind == HookKind::PthImport)
}

#[test]
fn every_python_line_break_starts_a_new_line() {
    for separator in [
        "\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\u{85}", "\u{2028}",
        "\u{2029}",
    ] {
        let content = format!("# comment{separator}{HOOK}\n");
        let hook = pth_hook(content.as_bytes()).unwrap();
        assert_eq!(hook.kind, HookKind::PthImport, "{separator:?}");
        assert_eq!(hook.code, [HOOK], "{separator:?}");
    }
}

#[test]
fn a_lone_carriage_return_file_is_read_line_by_line() {
    let hook = pth_hook(format!("# comment\r{HOOK}\r").as_bytes()).unwrap();
    assert_eq!(hook.code, [HOOK]);
}

#[test]
fn a_leading_utf8_bom_is_ignored() {
    let content = [b"\xef\xbb\xbf".as_slice(), HOOK.as_bytes(), b"\n"].concat();
    assert!(runs_import(&content));
}

#[test]
fn leading_python_whitespace_does_not_hide_an_import_line() {
    // Python 3.15 strips each line (str.strip) before testing for `import`.
    for lead in [" ", "\t", "\u{a0}", "\x1f", "\u{2003}", "\u{3000}"] {
        assert!(
            runs_import(format!("{lead}{HOOK}\n").as_bytes()),
            "{lead:?}"
        );
    }
}

#[test]
fn a_non_utf8_file_is_also_read_as_a_single_byte_locale_would() {
    // Not UTF-8, so site.py falls back to the locale encoding; in Latin-1 the
    // byte 0x85 is NEL, a line break.
    let content = [b"# c\x85".as_slice(), HOOK.as_bytes(), b"\n"].concat();
    assert!(runs_import(&content));
}

#[test]
fn unit_separator_is_whitespace_but_not_a_line_break() {
    // `# c\x1fimport os` is one comment line on every version.
    assert!(pth_hook(format!("# c\x1f{HOOK}\n").as_bytes()).is_none());
}

#[test]
fn start_entries_are_split_like_pth_lines() {
    let wheel = zip(&[("s.start", b"# c\rpkg.boot:run\x0c", false)]);
    let hooks = inspect_wheel(&wheel).unwrap().startup_hooks;
    assert_eq!(hooks[0].code, ["pkg.boot:run"]);
}

fn python3() -> Option<std::path::PathBuf> {
    let found = std::process::Command::new("python3")
        .args(["-I", "-c", "import sys; print(sys.executable)"])
        .output()
        .ok()?;
    let path = String::from_utf8(found.stdout).ok()?;
    found.status.success().then(|| path.trim().into())
}

fn temp_site() -> std::path::PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-pth-site-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Whether this machine's `python3` executes an import line of `content`
/// when `site` processes it as a `.pth` file.
fn python_runs(python: &std::path::Path, content: &[u8]) -> bool {
    let site = temp_site();
    let mark = site.join("ran");
    std::fs::write(site.join("t.pth"), content).unwrap();
    std::process::Command::new(python)
        .args([
            "-I",
            "-S",
            "-c",
            "import site, sys; site.addsitedir(sys.argv[1])",
        ])
        .arg(&site)
        .env("SJ_PTH_MARK", &mark)
        .output()
        .unwrap();
    let ran = mark.exists();
    std::fs::remove_dir_all(&site).ok();
    ran
}

#[test]
fn every_pth_the_local_python_executes_is_reported() {
    let Some(python) = python3() else {
        eprintln!("python3 not available; skipping the live site.py comparison");
        return;
    };
    let hook = "import os; open(os.environ['SJ_PTH_MARK'], 'w').close()";
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for prefix in ["", " ", "\t", "\u{a0}", "\x1f", "\u{feff}", "#", "# c\x1f"] {
        for separator in [
            "\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\u{85}", "\u{2028}",
            "\u{2029}", "\x1f", " ",
        ] {
            cases.push(format!("{prefix}# c{separator}{hook}\n").into_bytes());
            cases.push(format!("{prefix}{hook}{separator}").into_bytes());
        }
    }
    cases.push([b"# c\x85".as_slice(), hook.as_bytes()].concat());
    let mut checked = 0;
    for content in &cases {
        if python_runs(&python, content) {
            checked += 1;
            assert!(
                runs_import(content),
                "{} executed {:?} but the scan reported no import hook",
                python.display(),
                String::from_utf8_lossy(content)
            );
        }
    }
    assert!(checked > 0, "python3 executed none of the cases");
}
