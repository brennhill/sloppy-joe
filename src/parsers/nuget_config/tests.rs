use super::*;
use crate::config_surface::KNOWN_SURFACES;

fn dir_with(content: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-nuget-surface-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("nuget.config"), content).unwrap();
    dir
}

fn run(content: &str, allows: &[KeyAllow]) -> Result<usize> {
    let dir = dir_with(content);
    reject_untrusted_nuget_config(&dir, &dir.join("a.csproj"), allows).map(|a| a.len())
}

fn allow(key: &str) -> KeyAllow {
    KeyAllow {
        file: "nuget.config".into(),
        key: key.into(),
    }
}

#[test]
fn the_surface_id_is_known() {
    assert!(KNOWN_SURFACES.contains(&NUGET_CONFIG.id));
}

#[test]
fn package_folder_settings_block_even_when_allowed() {
    for key in [
        "globalPackagesFolder",
        "repositoryPath",
        "GLOBALPACKAGESFOLDER",
    ] {
        let text = format!(
            r#"<configuration><config><add key="{key}" value="pkgs"/></config></configuration>"#
        );
        assert!(run(&text, &[]).is_err(), "{key}");
        assert!(
            run(
                &text,
                &[allow(&format!("config:{}", key.to_ascii_lowercase()))]
            )
            .is_err(),
            "allowed {key}"
        );
    }
}

#[test]
fn ordinary_settings_and_nuget_org_pass() {
    let text = r#"<configuration>
  <packageSources><clear/><add key="nuget" value="https://api.nuget.org/v3/index.json"/></packageSources>
  <packageSourceMapping><packageSource key="nuget"><package pattern="*"/></packageSource></packageSourceMapping>
  <config><add key="signatureValidationMode" value="require"/><add key="dependencyVersion" value="Highest"/></config>
  <disabledPackageSources><add key="x" value="true"/></disabledPackageSources>
</configuration>"#;
    assert_eq!(run(text, &[]).unwrap(), 0);
}

#[test]
fn foreign_feeds_and_trust_changes_block() {
    for text in [
        r#"<configuration><packageSources><add key="x" value="https://attacker.example/v3/index.json"/></packageSources></configuration>"#,
        "<configuration><fallbackPackageFolders><add key=\"a\" value=\"f\"/></fallbackPackageFolders></configuration>",
        "<configuration><trustedSigners><author name=\"a\"/></trustedSigners></configuration>",
        r#"<configuration><config><add key="signatureValidationMode" value="accept"/></config></configuration>"#,
        r#"<configuration><config><add key="https_proxy" value="http://p.invalid"/></config></configuration>"#,
    ] {
        assert!(run(text, &[]).is_err(), "{text}");
        assert!(run(text, &[allow("source")]).is_err(), "allowed: {text}");
    }
}

#[test]
fn an_unlisted_setting_blocks_until_the_operator_allows_that_exact_key() {
    let text = r#"<configuration><config><add key="defaultPushSource" value="https://x.example"/></config></configuration>"#;
    let err = run(text, &[]).unwrap_err().to_string();
    assert!(err.contains("config:defaultpushsource"), "{err}");
    assert_eq!(run(text, &[allow("config:defaultpushsource")]).unwrap(), 1);
}

#[test]
fn the_file_name_is_matched_case_insensitively() {
    let dir = dir_with("");
    std::fs::rename(dir.join("nuget.config"), dir.join("NuGet.Config")).unwrap();
    std::fs::write(
        dir.join("NuGet.Config"),
        r#"<configuration><config><add key="repositoryPath" value="p"/></config></configuration>"#,
    )
    .unwrap();
    assert!(reject_untrusted_nuget_config(&dir, &dir.join("a.csproj"), &[]).is_err());
}
