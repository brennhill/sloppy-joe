use super::*;

#[test]
fn config_key_allow_parses_and_validates_exact_entries() {
    let config = parse_config_content(
        r#"{"config_key_allow":[{"file":"uv","key":"keyring-provider"},{"file":"poetry.toml","key":"warnings.export"}]}"#,
        "test.json",
    )
    .unwrap();
    assert_eq!(config.config_key_allow.len(), 2);
    for bad in [
        r#"{"config_key_allow":[{"file":"nope","key":"a"}]}"#,
        r#"{"config_key_allow":[{"file":"uv","key":"*"}]}"#,
        r#"{"config_key_allow":[{"file":"uv","key":"a..b"}]}"#,
        r#"{"config_key_allow":[{"file":"uv","key":""}]}"#,
        r#"{"config_key_allow":[{"file":"uv","key":"a","extra":1}]}"#,
        r#"{"config_key_allow":[{"file":"uv"}]}"#,
    ] {
        assert!(parse_config_content(bad, "test.json").is_err(), "{bad}");
    }
}

#[test]
fn the_local_overlay_cannot_carry_config_key_allow() {
    let result = parse_local_overlay_content(
        r#"{"config_key_allow":[{"file":"uv","key":"keyring-provider"}]}"#,
        "overlay.json",
    );
    assert!(result.is_err());
}
