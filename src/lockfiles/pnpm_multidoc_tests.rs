//! pnpm writes a second YAML document when it manages its own version
//! (`packageManagerDependencies` / `configDependencies`): the first document
//! locks pnpm itself, the last is the project lockfile. The project lockfile is
//! validated as before, and the packages of the earlier documents, which are
//! installed and executed too, are scanned as transitives of the root.

use super::pnpm;
use super::{PNPM_ENV_PACKAGES_KEY, parse_pnpm_lock_guarded};
use std::path::Path;

const ENV_DOC: &str = r#"---
lockfileVersion: '9.0'

importers:

  .:
    configDependencies: {}
    packageManagerDependencies:
      pnpm:
        specifier: 12.14.0
        version: 12.14.0

packages:

  '@pnpm/exe.linux-x64@12.14.0':
    resolution: {integrity: sha512-AAAA}
    cpu: [x64]
    os: [linux]

  pnpm@12.14.0:
    resolution: {integrity: sha512-BBBB}

snapshots:

  pnpm@12.14.0:
    optionalDependencies:
      '@pnpm/exe.linux-x64': 12.14.0

  '@pnpm/exe.linux-x64@12.14.0': {}
"#;

const MAIN_DOC: &str = r#"---
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      left-pad:
        specifier: ^1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-CCCC}

snapshots:

  left-pad@1.3.0: {}
"#;

fn scanned(content: &str, importer: &str) -> Vec<String> {
    let parsed = parse_pnpm_lock_guarded(content).expect("lockfile should parse");
    let (deps, _issues) =
        pnpm::parse_for_importer_with_orphans(&parsed, importer, Path::new("pnpm-lock.yaml"))
            .unwrap();
    let mut names: Vec<String> = deps
        .into_iter()
        .map(|dep| format!("{}@{}", dep.name, dep.version.unwrap_or_default()))
        .collect();
    names.sort();
    names
}

#[test]
fn single_document_lockfiles_are_unchanged() {
    let parsed = parse_pnpm_lock_guarded(MAIN_DOC.trim_start_matches("---\n")).unwrap();
    assert!(parsed.get(PNPM_ENV_PACKAGES_KEY).is_none());
    assert_eq!(
        scanned(MAIN_DOC.trim_start_matches("---\n"), "."),
        vec!["left-pad@1.3.0"]
    );
}

#[test]
fn env_document_packages_are_scanned_alongside_the_project() {
    let content = format!("{ENV_DOC}{MAIN_DOC}");
    assert_eq!(
        scanned(&content, "."),
        vec![
            "@pnpm/exe.linux-x64@12.14.0",
            "left-pad@1.3.0",
            "pnpm@12.14.0"
        ]
    );
}

#[test]
fn project_importers_other_than_the_root_do_not_own_env_packages() {
    let main = MAIN_DOC.replace(
        "importers:\n\n  .:",
        "importers:\n\n  packages/a:\n    dependencies:\n      left-pad:\n        specifier: ^1.3.0\n        version: 1.3.0\n\n  .:",
    );
    let content = format!("{ENV_DOC}{main}");
    assert_eq!(scanned(&content, "packages/a"), vec!["left-pad@1.3.0"]);
    assert!(scanned(&content, ".").contains(&"pnpm@12.14.0".to_string()));
}

#[test]
fn env_package_from_a_non_registry_source_blocks() {
    for resolution in [
        "{tarball: 'https://evil.example/pnpm.tgz'}",
        "{directory: ../pnpm, type: directory}",
        "{type: git, repo: 'https://github.com/x/y', commit: abc}",
        "{integrity: sha512-AAAA, tarball: 'https://evil.example/pnpm.tgz'}",
    ] {
        let env = ENV_DOC.replace("{integrity: sha512-BBBB}", resolution);
        let err = parse_pnpm_lock_guarded(&format!("{env}{MAIN_DOC}")).unwrap_err();
        assert!(
            err.to_string().contains("registry"),
            "{resolution}: unexpected error {err}"
        );
    }
}

#[test]
fn env_package_without_an_integrity_hash_blocks() {
    let env = ENV_DOC.replace("resolution: {integrity: sha512-BBBB}", "cpu: [x64]");
    assert!(parse_pnpm_lock_guarded(&format!("{env}{MAIN_DOC}")).is_err());
}

#[test]
fn env_package_with_an_invalid_name_blocks() {
    let env = ENV_DOC.replace(
        "  pnpm@12.14.0:\n    resolution",
        "  'ev il@1.0.0':\n    resolution",
    );
    assert!(parse_pnpm_lock_guarded(&format!("{env}{MAIN_DOC}")).is_err());
}

#[test]
fn malformed_document_structure_blocks() {
    // earlier document without a lockfileVersion
    let bad_env = ENV_DOC.replace("lockfileVersion: '9.0'\n", "");
    assert!(parse_pnpm_lock_guarded(&format!("{bad_env}{MAIN_DOC}")).is_err());
    // project document (the last one) without importers
    let no_importers = "---\nlockfileVersion: '9.0'\npackages: {}\n";
    assert!(parse_pnpm_lock_guarded(&format!("{ENV_DOC}{no_importers}")).is_err());
    // an environment document is not a mapping
    assert!(parse_pnpm_lock_guarded(&format!("---\n- a\n- b\n{MAIN_DOC}")).is_err());
}

#[test]
fn too_many_documents_block() {
    let content = format!("{ENV_DOC}{ENV_DOC}{ENV_DOC}{ENV_DOC}{MAIN_DOC}");
    let err = parse_pnpm_lock_guarded(&content).unwrap_err();
    assert!(err.to_string().contains("documents"), "{err}");
}

fn transitive_issues(content: &str, name: &str, version: &str) -> (bool, Vec<String>) {
    let parsed = parse_pnpm_lock_guarded(content).expect("lockfile should parse");
    let dep = crate::Dependency {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: crate::Ecosystem::Npm,
        actual_name: None,
    };
    let result = pnpm::resolve_from_value(
        &parsed,
        std::slice::from_ref(&dep),
        ".",
        super::ResolutionMode::Transitive,
    )
    .unwrap();
    (
        result
            .exact_versions
            .get(&super::ResolutionKey::from(&dep))
            .is_some_and(|resolved| {
                resolved.version == version && resolved.source == super::ResolutionSource::Lockfile
            }),
        result.issues.iter().map(|i| i.check.clone()).collect(),
    )
}

#[test]
fn locked_transitives_resolve_without_an_importer_entry() {
    let content = format!("{ENV_DOC}{MAIN_DOC}").replace("left-pad@1.3.0: {}", "left-pad@1.3.0: {}\n  ms@2.1.2: {}")
        .replace(
            "  left-pad@1.3.0:\n    resolution: {integrity: sha512-CCCC}",
            "  left-pad@1.3.0:\n    resolution: {integrity: sha512-CCCC}\n\n  ms@2.1.2:\n    resolution: {integrity: sha512-DDDD}",
        );
    let (resolved, issues) = transitive_issues(&content, "ms", "2.1.2");
    assert!(resolved);
    assert!(issues.is_empty(), "{issues:?}");
    let (resolved, issues) = transitive_issues(&content, "pnpm", "12.14.0");
    assert!(resolved);
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn transitive_absent_from_the_lockfile_still_blocks() {
    let content = format!("{ENV_DOC}{MAIN_DOC}");
    let (resolved, issues) = transitive_issues(&content, "ms", "2.1.2");
    assert!(!resolved);
    assert!(
        issues
            .iter()
            .any(|c| c == "resolution/missing-lockfile-entry")
    );
}
