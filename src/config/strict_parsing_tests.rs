//! Policy typos must fail loudly: an ignored key silently weakens the policy.
use super::*;

fn repo_file(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

#[test]
fn unknown_top_level_config_key_is_rejected() {
    for content in [
        r#"{"internals": {"npm": ["@yourorg/*"]}}"#,
        r#"{"min_version_age_hour": 1}"#,
        r#"{"allow_host_local_cargo_config": true}"#,
        r#"{"active_local_overlay_relaxations": []}"#,
    ] {
        let error = parse_config_content(content, "test").expect_err(content);
        assert!(error.contains("unknown field"), "{content}: {error}");
    }
}

#[test]
fn unknown_nested_config_keys_are_rejected() {
    for content in [
        r#"{"similarity_exceptions":{"npm":[{"package":"a","candidate":"b","generator":"char-swap","reasn":"x"}]}}"#,
        r#"{"metadata_exceptions":{"npm":[{"package":"a","check":"metadata/maintainer-change","version":"1","previous_publisher":"p","current_publisher":"c","extra":1}]}}"#,
        r#"{"trusted_registries":{"cargo":[{"name":"c","source":"registry+https://x/index","sourc":"y"}]}}"#,
        r#"{"bootstrap_review":{"suggested_internals":{}}}"#,
        r#"{"bootstrap_review":{"candidate_canonical_groups":{"npm":[{"packages":["a"],"note":"x"}]}}}"#,
    ] {
        let error = parse_config_content(content, "test").expect_err(content);
        assert!(error.contains("unknown field"), "{content}: {error}");
    }
}

#[test]
fn duplicate_config_keys_are_rejected_at_every_level() {
    for content in [
        r#"{"min_version_age_hours": 1, "min_version_age_hours": 72}"#,
        r#"{"internal": {"npm": ["@a/*"], "npm": []}}"#,
        r#"{"canonical": {"npm": {"lodash": ["underscore"], "lodash": []}}}"#,
        r#"{"similarity_exceptions":{"npm":[{"package":"a","package":"b","candidate":"c","generator":"char-swap"}]}}"#,
    ] {
        let error = parse_config_content(content, "test").expect_err(content);
        assert!(error.contains("duplicate"), "{content}: {error}");
    }
}

#[test]
fn duplicate_local_overlay_keys_are_rejected() {
    let error = parse_local_overlay_content(
        r#"{"trusted_git_sources": {"cargo": ["https://a"], "cargo": []}}"#,
        "overlay",
    )
    .unwrap_err();
    assert!(error.contains("duplicate"), "{error}");
}

#[test]
fn shipped_example_config_still_parses() {
    parse_config_content(&repo_file("config.example.json"), "config.example.json").unwrap();
}

#[test]
fn rendered_templates_still_parse() {
    parse_config_content(
        &crate::bootstrap::render_config_json(&crate::bootstrap::template_config()),
        "template",
    )
    .unwrap();
    for ecosystem in ["npm", "pypi", "cargo"] {
        parse_config_content(
            &crate::bootstrap::greenfield_json(ecosystem).unwrap(),
            ecosystem,
        )
        .unwrap();
    }
}

#[test]
fn complete_json_examples_in_config_docs_still_parse() {
    let mut checked = 0;
    for file in ["CONFIG.md", "README.md", "docs/ecosystems/JAVASCRIPT.md"] {
        let doc = repo_file(file);
        for block in doc.split("```json").skip(1) {
            let block = block.split("```").next().unwrap();
            // Skip illustrative fragments such as `{ ... }` placeholders.
            if serde_json::from_str::<serde_json::Value>(block).is_err() {
                continue;
            }
            parse_config_content(block, file).unwrap_or_else(|e| panic!("{file}: {block}\n{e}"));
            checked += 1;
        }
    }
    assert!(
        checked > 3,
        "expected CONFIG.md to contain parseable config examples"
    );
}

#[test]
fn fixture_configs_still_parse() {
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")];
    let mut checked = 0;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "sloppy-joe.json") {
                let content = std::fs::read_to_string(&path).unwrap();
                parse_config_content(&content, &path.display().to_string())
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                checked += 1;
            }
        }
    }
    assert!(checked > 0);
}
