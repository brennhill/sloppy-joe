use super::*;

fn path() -> &'static std::path::Path {
    std::path::Path::new("fixture")
}

fn err(bytes: &[u8], format: Format) -> String {
    parse(bytes, format, path()).unwrap_err().to_string()
}

fn text(bytes: &[u8], format: Format) -> String {
    match parse(bytes, format, path()).unwrap() {
        Untrusted::Text(text) => text,
        other => panic!("expected text, got {other:?}"),
    }
}

#[test]
fn every_format_rejects_a_bom_a_nul_and_invalid_utf8() {
    for format in [
        Format::Line,
        Format::Properties,
        Format::Script,
        Format::Toml,
        Format::Json,
        Format::Yaml,
        Format::Xml,
        Format::Text,
    ] {
        assert!(err(b"\xef\xbb\xbfa = 1\n", format).contains("byte order mark"));
        assert!(err(b"a = 1\0\n", format).contains("NUL"));
        if format != Format::Properties {
            assert!(err(b"a = \xff\n", format).contains("UTF-8"));
        }
    }
}

#[test]
fn line_formats_reject_terminators_the_tool_honors_but_lines_does_not() {
    for format in [Format::Line, Format::Script, Format::Xml, Format::Yaml] {
        for bad in [
            "a\rb",
            "a\u{b}b",
            "a\u{c}b",
            "a\u{85}b",
            "a\u{2028}b",
            "a\u{2029}b",
        ] {
            assert!(
                err(bad.as_bytes(), format).contains("line terminator"),
                "{format:?} {bad:?}"
            );
        }
        assert_eq!(text(b"a\r\nb\n", Format::Line), "a\r\nb\n");
    }
}

#[test]
fn properties_keep_a_lone_cr_because_the_parser_models_it() {
    assert_eq!(text(b"a=1\rb=2\n", Format::Properties), "a=1\rb=2\n");
    // Properties files are ISO-8859-1: bytes above 0x7f are characters, not UTF-8 errors.
    assert_eq!(text(b"k=\xe9\n", Format::Properties), "k=\u{e9}\n");
}

#[test]
fn plain_text_only_gets_the_universal_checks() {
    assert_eq!(text(b"a\rb", Format::Text), "a\rb");
}

#[test]
fn json_duplicate_keys_are_rejected_at_any_depth() {
    assert!(err(br#"{"a":1,"a":2}"#, Format::Json).contains("duplicate"));
    assert!(err(br#"{"x":[{"a":1,"b":2,"a":3}]}"#, Format::Json).contains("duplicate"));
    match parse(br#"{"a":1,"b":{"c":[1,2]}}"#, Format::Json, path()).unwrap() {
        Untrusted::Json(value) => assert_eq!(value["b"]["c"][1], 2),
        other => panic!("{other:?}"),
    }
}

#[test]
fn toml_duplicate_keys_are_rejected_by_the_parser() {
    assert!(parse(b"a = 1\na = 2\n", Format::Toml, path()).is_err());
    assert!(matches!(
        parse(b"a = 1\n[t]\nb = 2\n", Format::Toml, path()).unwrap(),
        Untrusted::Toml(_)
    ));
}

#[test]
fn yaml_duplicate_keys_anchors_aliases_and_merge_keys_are_rejected() {
    assert!(err(b"a: 1\na: 2\n", Format::Yaml).contains("duplicate"));
    assert!(err(b"a: &x 1\nb: *x\n", Format::Yaml).contains("anchor"));
    assert!(err(b"a: &x {k: 1}\nb:\n  <<: *x\n", Format::Yaml).contains("anchor"));
    assert!(err(b"b:\n  <<: {k: 1}\n", Format::Yaml).contains("merge"));
    assert!(err(b"a: 1\n---\nb: 2\n", Format::Yaml).contains("document"));
}

#[test]
fn yaml_quoted_text_and_comments_may_contain_anchor_characters() {
    let doc = b"a: \"x &y *z\"\nb: 'p *q'\n# &c *d\nc: [1, 2]\n";
    match parse(doc, Format::Yaml, path()).unwrap() {
        Untrusted::Yaml(value) => assert_eq!(value["c"][1], 2),
        other => panic!("{other:?}"),
    }
}

#[test]
fn files_are_read_with_the_size_and_symlink_guards() {
    let dir = std::env::temp_dir().join(format!("sj-untrusted-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("a.txt");
    std::fs::write(&file, "hello\n").unwrap();
    assert_eq!(read_text(&file, Format::Line, 100).unwrap(), "hello\n");
    assert!(read_text(&file, Format::Line, 3).is_err());
    #[cfg(unix)]
    {
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_text(&link, Format::Line, 100).is_err());
    }
    assert!(read_text(&dir.join("missing"), Format::Line, 100).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn read_text_refuses_structured_formats() {
    let dir = std::env::temp_dir().join(format!("sj-untrusted-s-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("a.toml");
    std::fs::write(&file, "a = 1\n").unwrap();
    assert!(read_text(&file, Format::Toml, 100).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rows_split_like_lines_after_validation() {
    assert_eq!(rows("a\nb\r\nc").collect::<Vec<_>>(), ["a", "b", "c"]);
}
