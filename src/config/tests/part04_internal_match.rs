use super::*;

fn config(patterns: &[&str]) -> SloppyJoeConfig {
    SloppyJoeConfig {
        internal: HashMap::from([(
            "npm".to_string(),
            patterns.iter().map(|p| p.to_string()).collect(),
        )]),
        ..Default::default()
    }
}

#[test]
fn internal_match_distinguishes_exact_names_from_prefixes() {
    let config = config(&["acme-*", "acme-core"]);
    assert_eq!(
        config.internal_match("npm", "acme-core"),
        Some(InternalMatch::Exact),
        "an exact entry wins over a prefix that also matches"
    );
    assert_eq!(
        config.internal_match("npm", "acme-utils"),
        Some(InternalMatch::Prefix("acme-*".to_string()))
    );
    assert_eq!(config.internal_match("npm", "other"), None);
    assert_eq!(config.internal_match("pypi", "acme-core"), None);
}

#[test]
fn internal_match_agrees_with_is_internal() {
    let config = config(&["@myorg/*", "exact-pkg"]);
    for name in ["@myorg/a", "exact-pkg", "exact-pkg2", "@other/a", "@myorg"] {
        assert_eq!(
            config.internal_match("npm", name).is_some(),
            config.is_internal("npm", name),
            "{name}"
        );
    }
}
