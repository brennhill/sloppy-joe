use super::*;

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

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

#[test]
fn template_config_keeps_similarity_exceptions_empty() {
    let config = template_config();
    assert!(
        config.similarity_exceptions.is_empty(),
        "public init template must not embed repo-specific similarity suppressions"
    );
}

#[test]
fn template_config_is_neutral_manual_baseline() {
    let config = template_config();
    assert!(config.canonical.is_empty());
    assert!(config.internal.is_empty());
    assert!(config.allowed.is_empty());
    assert!(config.bootstrap_review.is_empty());

    let rendered = template_json();
    assert!(!rendered.contains("@yourorg/*"));
    assert!(!rendered.contains("some-vetted-external-pkg"));
    assert!(!rendered.contains("\"axios\""));
    assert!(!rendered.contains("\"httpx\""));
}

#[test]
fn greenfield_config_npm_is_ecosystem_specific() {
    let config = greenfield_config("npm").expect("npm greenfield config should build");
    assert!(config.canonical.contains_key("npm"));
    assert!(!config.canonical.contains_key("cargo"));
    assert_eq!(
        config.canonical["npm"]["eslint"],
        vec!["tslint".to_string()]
    );
    assert!(config.internal.is_empty());
    assert!(config.allowed.is_empty());
}

#[test]
fn greenfield_config_cargo_is_ecosystem_specific() {
    let config = greenfield_config("cargo").expect("cargo greenfield config should build");
    assert!(config.canonical.contains_key("cargo"));
    assert!(!config.canonical.contains_key("npm"));
    assert_eq!(
        config.canonical["cargo"]["clap"],
        vec!["structopt".to_string()]
    );
}

#[test]
fn greenfield_config_rejects_not_yet_supported_ecosystem() {
    let err = greenfield_config("go").expect_err("unsupported greenfield ecosystems must fail");
    assert!(err.contains("not supported yet"));
    assert!(err.contains("npm"));
    assert!(err.contains("cargo"));
}

#[test]
fn greenfield_config_rejects_unknown_ecosystem() {
    let err = greenfield_config("elixir").expect_err("unsupported ecosystems must fail");
    assert!(err.contains("Unsupported ecosystem"));
    assert!(err.contains("npm"));
    assert!(err.contains("cargo"));
}

#[test]
fn discover_current_config_infers_npm_internal_scope_and_review_candidates() {
    let dir = unique_temp_dir("from-current-npm");
    write_file(
        &dir.join("packages/web/package.json"),
        r#"{
  "name": "@acme/web",
  "dependencies": {
"dayjs": "1.11.13",
"axios": "1.9.0"
  }
}"#,
    );
    write_file(
        &dir.join("packages/ui/package.json"),
        r#"{
  "name": "@acme/ui",
  "dependencies": {
"moment": "2.30.1",
"got": "14.4.8"
  }
}"#,
    );

    let config = discover_current_config(&dir).expect("discovery should inspect npm workspaces");
    assert_eq!(
        config.bootstrap_review.suggested_internal.get("npm"),
        Some(&vec!["@acme/ui".to_string(), "@acme/web".to_string()])
    );
    assert!(
        config.internal.is_empty(),
        "from-current should not silently trust discovered packages"
    );
    assert!(
        !config.canonical.contains_key("npm"),
        "from-current should not silently enforce canonical choices"
    );
    let groups = &config.bootstrap_review.candidate_canonical_groups["npm"];
    assert!(
        groups
            .iter()
            .any(|group| group.packages == vec!["dayjs".to_string(), "moment".to_string()])
    );
    assert!(
        groups
            .iter()
            .any(|group| { group.packages == vec!["axios".to_string(), "got".to_string()] })
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn discover_current_config_infers_cargo_local_provenance() {
    let sandbox = unique_temp_dir("from-current-cargo");
    let repo = sandbox.join("repo");
    let external = sandbox.join("shared-crate");

    write_file(
        &repo.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/app", "crates/lib"]
"#,
    );
    write_file(
        &repo.join("crates/app/Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
lib = { path = "../lib" }
shared = { path = "../../../shared-crate" }
"#,
    );
    write_file(
        &repo.join("crates/lib/Cargo.toml"),
        r#"[package]
name = "lib"
version = "0.1.0"
"#,
    );
    write_file(
        &external.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    );

    let config = discover_current_config(&repo).expect("discovery should inspect cargo manifests");
    let canonical_external = std::fs::canonicalize(&external).unwrap();
    assert_eq!(
        config.bootstrap_review.suggested_internal.get("cargo"),
        Some(&vec!["app".to_string(), "lib".to_string()])
    );
    assert_eq!(
        config
            .bootstrap_review
            .suggested_trusted_local_paths
            .get("cargo"),
        Some(&vec![canonical_external.to_string_lossy().to_string()])
    );
    assert!(
        config.trusted_local_paths.is_empty(),
        "from-current should not silently trust local cargo paths"
    );

    std::fs::remove_dir_all(&sandbox).unwrap();
}

#[test]
fn discover_current_config_rejects_unsupported_ecosystems() {
    let dir = unique_temp_dir("from-current-unsupported");
    write_file(&dir.join("requirements.txt"), "requests==2.32.3\n");

    let err = discover_current_config(&dir)
        .expect_err("unsupported ecosystems should fail until implemented");
    assert!(err.contains("supports only npm and cargo"));
    assert!(err.contains("pypi"));
    assert!(err.contains("not implemented yet"));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn discover_current_config_skips_vendor_and_fixture_trees() {
    let dir = unique_temp_dir("from-current-skips");
    write_file(
        &dir.join("app/package.json"),
        r#"{"name":"@acme/app","dependencies":{"dayjs":"1.11.13"}}"#,
    );
    write_file(
        &dir.join("vendor/third-party/package.json"),
        r#"{"name":"left-pad","dependencies":{"moment":"2.30.1"}}"#,
    );
    write_file(
        &dir.join("fixtures/sample/package.json"),
        r#"{"name":"@fixture/sample","dependencies":{"got":"14.4.8"}}"#,
    );

    let config = discover_current_config(&dir).expect("discovery should ignore vendored trees");
    assert_eq!(
        config.bootstrap_review.suggested_internal.get("npm"),
        Some(&vec!["@acme/app".to_string()])
    );
    let groups = config
        .bootstrap_review
        .candidate_canonical_groups
        .get("npm")
        .cloned()
        .unwrap_or_default();
    assert!(
        groups.is_empty(),
        "vendored fixtures must not leak into review suggestions"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn print_template_does_not_panic() {
    print_template();
}
