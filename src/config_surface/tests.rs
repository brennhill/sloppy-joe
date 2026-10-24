use super::*;

const SURFACE: Surface = Surface {
    id: "uv",
    subject: "test setting",
    why: "test reason",
    allow: &[
        rule("safe", ValueRule::Bool),
        rule("mode", ValueRule::OneOf(&["a", "b"])),
        rule("nested.deep.ok", ValueRule::Str),
        rule("opaque", ValueRule::Any),
        rule("wild.*.leaf", ValueRule::Any),
        rule("tls", ValueRule::BoolIs(false)),
    ],
    deny: &["cache", "net.proxy"],
    deny_under: &["pip"],
    scope: &[],
};

fn run(toml_text: &str, allows: &[KeyAllow]) -> Result<Vec<AppliedAllow>> {
    let value: toml::Value = toml_text.parse().unwrap();
    check_toml(&SURFACE, &value, Path::new("x.toml"), allows)
}

fn allow(key: &str) -> KeyAllow {
    KeyAllow {
        file: "uv".to_string(),
        key: key.to_string(),
    }
}

#[test]
fn listed_keys_with_fitting_values_pass() {
    let applied = run(
        "safe = true\nmode = \"a\"\nopaque = { anything = [1, 2] }\ntls = false\n[nested.deep]\nok = \"x\"\n[wild.one]\nleaf = 1\n",
        &[],
    )
    .unwrap();
    assert!(applied.is_empty());
}

#[test]
fn an_unlisted_key_blocks_and_names_the_way_to_allow_it() {
    let err = run("surprise = 1\n", &[]).unwrap_err().to_string();
    assert!(err.contains("Unsupported test setting 'surprise'"), "{err}");
    assert!(err.contains("config_key_allow"), "{err}");
    assert!(run("[nested]\nother = 1\n", &[]).is_err());
    assert!(run("[nested.deep]\nok = \"x\"\nbad = 1\n", &[]).is_err());
    assert!(
        run("nested = true\n", &[]).is_err(),
        "a table rule needs a table"
    );
}

#[test]
fn a_value_that_does_not_fit_blocks_even_when_allowed() {
    for text in [
        "safe = \"yes\"\n",
        "mode = \"c\"\n",
        "tls = true\n",
        "[nested.deep]\nok = 1\n",
    ] {
        assert!(run(text, &[]).is_err(), "{text}");
    }
    assert!(run("safe = \"yes\"\n", &[allow("safe")]).is_err());
}

#[test]
fn denied_keys_block_and_config_cannot_allow_them() {
    for text in [
        "cache = \"x\"\n",
        "[net]\nproxy = \"p\"\n",
        "[pip]\ncache = \"x\"\n",
        "[cache]\na = 1\n",
    ] {
        assert!(run(text, &[]).is_err(), "{text}");
    }
    assert!(run("cache = \"x\"\n", &[allow("cache")]).is_err());
    assert!(run("[pip]\ncache = 1\n", &[allow("pip.cache")]).is_err());
}

#[test]
fn a_listed_user_allow_turns_an_unknown_key_into_a_warning() {
    let applied = run(
        "surprise = 1\n[nested]\nother = 2\n",
        &[allow("surprise"), allow("nested.other")],
    )
    .unwrap();
    assert_eq!(applied.len(), 2);
    let issues = issues(&applied);
    assert_eq!(issues[0].severity, Severity::Warning);
    assert_eq!(issues[0].check, crate::names::CONFIG_KEY_ALLOWED);
    assert!(
        issues
            .iter()
            .any(|issue| issue.message.contains("'surprise'"))
    );
    assert!(
        issues
            .iter()
            .any(|issue| issue.message.contains("'nested.other'"))
    );
    // Only the exact key and the named file count.
    assert!(run("surprise = 1\n", &[allow("surprise.x")]).is_err());
    let other_file = KeyAllow {
        file: "poetry.toml".to_string(),
        key: "surprise".to_string(),
    };
    assert!(run("surprise = 1\n", &[other_file]).is_err());
}

#[test]
fn allow_entries_are_validated() {
    assert!(allow("a.b").problems().is_empty());
    for key in ["", "a..b", ".a", "a.", "a.*"] {
        assert!(!allow(key).problems().is_empty(), "{key}");
    }
    let unknown = KeyAllow {
        file: "nope".to_string(),
        key: "a".to_string(),
    };
    assert!(!unknown.problems().is_empty());
}

#[test]
fn a_dotted_key_does_not_pose_as_a_nested_path() {
    // `"nested.deep.ok" = "x"` is one key, not the table path nested -> deep -> ok.
    assert!(run("\"nested.deep.ok\" = \"x\"\n", &[]).is_err());
}

#[test]
fn json_documents_are_checked_the_same_way() {
    let ok: Value = serde_json::json!({"safe": true});
    assert!(
        check_json(&SURFACE, &ok, Path::new("c.json"), &[])
            .unwrap()
            .is_empty()
    );
    let bad: Value = serde_json::json!({"cache": "x"});
    assert!(check_json(&SURFACE, &bad, Path::new("c.json"), &[]).is_err());
    assert!(check_json(&SURFACE, &serde_json::json!([1]), Path::new("c.json"), &[]).is_err());
}

#[test]
fn every_surface_id_is_known() {
    for id in ["uv", "poetry.toml", "composer.json"] {
        assert!(KNOWN_SURFACES.contains(&id), "{id}");
    }
}
