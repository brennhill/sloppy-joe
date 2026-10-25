//! Round-5 red-team regressions: requirements parsing must read lines the way pip does.

use super::*;
use crate::parsers::test_utils::*;

fn names(content: &str) -> Vec<String> {
    let dir = setup_test_dir("req-round5", "requirements.txt", content);
    let deps = parse(&dir).unwrap();
    cleanup(&dir);
    deps.into_iter().map(|dep| dep.name).collect()
}

#[test]
fn the_leftmost_real_coding_declaration_decides_the_codec() {
    // `xcoding` is not a declaration, so the later `coding: utf-7` is the one pip honors.
    for line in [
        "# xcoding coding: utf-7",
        "# coding=utf_7",
        "#coding:   utf-16",
        "# -*- coding: cp037 -*-",
    ] {
        let dir = setup_test_dir(
            "req-coding",
            "requirements.txt",
            &format!("{line}\nsix==1.16.0\n"),
        );
        let err = parse(&dir).expect_err(line);
        assert!(
            err.to_string().contains("unsupported encoding"),
            "{line}: {err}"
        );
        cleanup(&dir);
    }
    for line in [
        "# coding: utf-8",
        "# xcoding only a word",
        "# coding: latin-1",
    ] {
        assert_eq!(names(&format!("{line}\nsix==1.16.0\n")), ["six"], "{line}");
    }
}

#[test]
fn a_continuation_needs_the_backslash_to_end_the_line() {
    // pip keeps these two requirements apart because the backslash is followed by spaces, so the
    // comment does not swallow the second one.
    assert_eq!(
        names("six==1.16.0 # note \\  \nevil-pkg==1.0\n"),
        ["six", "evil-pkg"]
    );
    // With the backslash last, the comment really does swallow the next line.
    assert_eq!(names("six==1.16.0 # note \\\nevil-pkg==1.0\n"), ["six"]);
}

#[test]
fn continued_parts_are_concatenated_without_a_separator() {
    // pip: "six==1.16.0" + "" -> one requirement; "foo\" + "bar==1" -> "foobar==1".
    assert_eq!(names("foo\\\nbar==1.0\n"), ["foobar"]);
    assert_eq!(names("six==1.16.0\\\n\nevil==1.0\n"), ["six", "evil"]);
}

#[test]
fn a_comment_line_ends_a_continuation_and_is_consumed() {
    assert_eq!(
        names("six==1.16.0 \\\n# note\nrequests==2.31.0\n"),
        ["six", "requests"]
    );
}

#[test]
fn constraint_only_requirement_files_are_not_pruned_as_includes() {
    let dir = empty_test_dir("req-constraint-prune");
    std::fs::write(
        dir.join("requirements.txt"),
        "-c requirements-extra.txt\nsix==1.16.0\n",
    )
    .unwrap();
    std::fs::write(dir.join("requirements-extra.txt"), "evil==1.0\n").unwrap();
    let included = included_paths(&dir.join("requirements.txt"), &dir).unwrap();
    assert!(included.is_empty(), "{included:?}");
    std::fs::write(dir.join("requirements.txt"), "-r requirements-extra.txt\n").unwrap();
    assert_eq!(
        included_paths(&dir.join("requirements.txt"), &dir)
            .unwrap()
            .len(),
        1
    );
    cleanup(&dir);
}

#[test]
fn a_latin1_next_line_byte_cannot_hide_a_requirement() {
    // Declared latin-1, byte 0x85 is a line break once pip decodes it; the file is not valid UTF-8,
    // so it must be rejected rather than read differently.
    let dir = empty_test_dir("req-latin1-nel");
    std::fs::write(
        dir.join("requirements.txt"),
        b"# coding: latin-1\nsix==1.16.0 # note\x85evil-pkg==1.0\n",
    )
    .unwrap();
    assert!(parse(&dir).is_err());
    cleanup(&dir);
}

fn scoped(content: &str) -> Vec<PythonScopedDependency> {
    let dir = setup_test_dir("req-scoped", "requirements.txt", content);
    let deps = parse_scoped_file(&dir.join("requirements.txt"), &dir).unwrap();
    cleanup(&dir);
    deps
}

#[test]
fn a_comment_starts_after_any_python_whitespace_like_pip() {
    // pip strips `(^|\s+)#.*$` with Python's `\s`, which also matches U+001F and NBSP. The
    // marker after the `#` is part of the comment, so pip installs the package everywhere.
    for separator in ['\u{1f}', '\u{a0}', '\t', ' '] {
        let deps = scoped(&format!(
            "evil-pkg==1.0{separator}#; sys_platform == \"win32\"\n"
        ));
        assert_eq!(deps.len(), 1, "{separator:?}");
        assert_eq!(deps[0].dependency.name, "evil-pkg", "{separator:?}");
        assert_eq!(
            deps[0].dependency.version.as_deref(),
            Some("==1.0"),
            "{separator:?}"
        );
        assert!(
            deps[0].marker.is_none(),
            "{separator:?}: {:?}",
            deps[0].marker
        );
    }
}

#[test]
fn a_hash_inside_quotes_still_starts_a_comment_like_pip() {
    // pip's comment pattern ignores quotes, so it reads the marker only up to ` #`.
    let deps = scoped("evil-pkg==1.0 ; python_version >= '3' or 'a #' == 'b'\n");
    assert_eq!(
        deps[0].marker.as_deref(),
        Some("python_version >= '3' or 'a")
    );
}

#[test]
fn a_comment_line_indented_with_python_whitespace_does_not_continue() {
    // `\u{1f}# note \` is a comment line for pip (its trailing backslash is not a continuation).
    let deps = scoped("\u{1f}# note \\\nevil-pkg==1.0\n");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].dependency.name, "evil-pkg");
}
