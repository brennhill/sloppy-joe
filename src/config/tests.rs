use super::*;

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let unique = format!(
        "sloppy-joe-test-{}-{}",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn jvm_registry_config(name: &str, source: &str) -> SloppyJoeConfig {
    SloppyJoeConfig {
        trusted_registries: HashMap::from([(
            "jvm".to_string(),
            vec![TrustedRegistry {
                name: name.to_string(),
                source: source.to_string(),
            }],
        )]),
        ..Default::default()
    }
}

#[path = "tests/part01_is_internal_exact.rs"]
mod part01_is_internal_exact;

#[path = "tests/part02_parse_config_content.rs"]
mod part02_parse_config_content;

#[path = "tests/part03_config_key_allow.rs"]
mod part03_config_key_allow;
