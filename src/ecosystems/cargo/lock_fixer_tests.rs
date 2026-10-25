use super::*;

fn config(content: &str) -> std::result::Result<(), Refusal> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-cargo-fix-config-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(dir.join(".cargo")).unwrap();
    let path = dir.join(".cargo/config.toml");
    std::fs::write(&path, content).unwrap();
    let result = check_config(&path);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[test]
fn only_reviewed_cargo_settings_are_accepted() {
    assert!(config("[net]\nretry = 3\n").is_ok());
    assert!(config("[registries.company]\nindex = \"sparse+https://r.example/\"\n").is_ok());
    assert!(config("[term]\nverbose = true\n").is_ok());
    for refused in [
        "[build]\nrustc-wrapper = \"x\"\n",
        "[alias]\nb = \"build\"\n",
        "[source.crates-io]\nreplace-with = \"mirror\"\n",
        "[net]\ngit-fetch-with-cli = true\n",
        "[registries.company]\nindex = \"x\"\ncredential-provider = \"cargo:token-from-stdout ./steal\"\n",
        "[registry]\nglobal-credential-providers = [\"x\"]\n",
        "[target.x86_64-unknown-linux-gnu]\nrunner = \"x\"\n",
        "[env]\nRUSTFLAGS = \"x\"\n",
        "[http]\nproxy = \"http://proxy\"\n",
    ] {
        let refusal = config(refused).expect_err(refused);
        assert!(refusal.contains("sets '"), "{refusal}");
    }
}

#[test]
fn the_cargo_environment_clears_every_wrapper() {
    let env = cargo_env();
    for name in [
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
    ] {
        assert!(
            env.iter()
                .any(|(key, value)| *key == name && *value == EnvValue::Literal(String::new())),
            "{name}"
        );
    }
    assert!(
        env.iter()
            .any(|(key, value)| *key == "RUSTC" && *value == EnvValue::TrustedProgram("rustc"))
    );
}
