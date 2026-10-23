//! `max_npm_tarball_verifications`: per-scan npm tarball download cap.
use super::*;

#[test]
fn tarball_verification_cap_defaults_to_100() {
    assert_eq!(
        SloppyJoeConfig::default().max_npm_tarball_verifications,
        100
    );
    let config = parse_config_content("{}", "test").unwrap();
    assert_eq!(config.max_npm_tarball_verifications, 100);
}

#[test]
fn tarball_verification_cap_is_accepted_by_strict_parsing() {
    for value in [1, 250, 1000] {
        let content = format!(r#"{{"max_npm_tarball_verifications": {value}}}"#);
        let config = parse_config_content(&content, "test").unwrap();
        assert_eq!(config.max_npm_tarball_verifications, value);
    }
}

#[test]
fn tarball_verification_cap_out_of_bounds_is_rejected() {
    for value in ["0", "1001", "-1", "1.5", "\"100\""] {
        let content = format!(r#"{{"max_npm_tarball_verifications": {value}}}"#);
        let error = parse_config_content(&content, "test").expect_err(&content);
        assert!(
            error.contains("max_npm_tarball_verifications") || error.contains("invalid"),
            "{content}: {error}"
        );
    }
}

#[test]
fn tarball_verification_cap_cannot_be_set_by_local_overlay() {
    let error = parse_local_overlay_content(r#"{"max_npm_tarball_verifications": 5}"#, "overlay")
        .unwrap_err();
    assert!(error.contains("unknown field"), "{error}");
}
