//! Collection of recorded integrity from npm-family lockfiles.

use super::*;
use crate::Dependency;
use crate::Ecosystem;
use crate::lockfiles::LockfileData;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-lock-integrity-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn registry(integrity: &str) -> LockedSource {
    LockedSource::Registry {
        integrity: Some(integrity.to_string()),
        sha1_hex: None,
    }
}

fn sources(collected: &NpmLockfileIntegrity, name: &str, version: &str) -> Vec<LockedSource> {
    collected
        .get(name, version)
        .unwrap_or_default()
        .iter()
        .map(|entry| entry.source.clone())
        .collect()
}

#[test]
fn npm_v3_packages_record_integrity_by_real_name_and_version() {
    let value = serde_json::json!({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/react": {"version": "18.3.1", "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz", "integrity": "sha512-react"},
            "node_modules/alias": {"name": "real", "version": "2.0.0", "resolved": "https://registry.npmjs.org/real/-/real-2.0.0.tgz", "integrity": "sha512-real"},
            "node_modules/a/node_modules/react": {"version": "18.3.1", "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz", "integrity": "sha512-other"},
            "node_modules/nointegrity": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/nointegrity/-/nointegrity-1.0.0.tgz"},
            "node_modules/linked": {"resolved": "packages/linked", "link": true},
            "node_modules/a/node_modules/bundled": {"version": "1.0.0", "inBundle": true},
            "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/acme/gitdep.git#abc"}
        }
    });
    let parsed = ParsedLockfile::Npm {
        value,
        file_name: "package-lock.json".into(),
        project_key: String::new(),
    };
    let collected = collect(&parsed).expect("npm lockfiles are covered");
    assert_eq!(collected.lockfile, "package-lock.json");
    assert_eq!(
        sources(&collected, "react", "18.3.1"),
        // Sorted by lockfile location: node_modules/a/node_modules/react first.
        vec![registry("sha512-other"), registry("sha512-react")]
    );
    assert_eq!(
        sources(&collected, "real", "2.0.0"),
        vec![registry("sha512-real")]
    );
    assert!(collected.get("alias", "2.0.0").is_none());
    assert_eq!(
        sources(&collected, "nointegrity", "1.0.0"),
        vec![LockedSource::Registry {
            integrity: None,
            sha1_hex: None
        }]
    );
    assert_eq!(
        sources(&collected, "bundled", "1.0.0"),
        vec![LockedSource::NotRegistry]
    );
    assert_eq!(
        sources(&collected, "gitdep", "1.0.0"),
        vec![LockedSource::NotRegistry]
    );
    assert!(collected.get("linked", "1.0.0").is_none());
}

#[test]
fn npm_v1_dependencies_are_walked_recursively() {
    let value = serde_json::json!({
        "lockfileVersion": 1,
        "dependencies": {
            "left": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/left/-/left-1.0.0.tgz",
                "integrity": "sha1-bGVmdA==",
                "dependencies": {
                    "right": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/right/-/right-2.0.0.tgz", "integrity": "sha512-right"}
                }
            },
            "alias": {"version": "npm:real@3.0.0", "resolved": "https://registry.npmjs.org/real/-/real-3.0.0.tgz", "integrity": "sha512-real"},
            "inside": {"version": "1.0.0", "bundled": true}
        }
    });
    let parsed = ParsedLockfile::NpmLegacy {
        value,
        file_name: "npm-shrinkwrap.json".into(),
    };
    let collected = collect(&parsed).unwrap();
    assert_eq!(
        sources(&collected, "left", "1.0.0"),
        vec![registry("sha1-bGVmdA==")]
    );
    assert_eq!(
        sources(&collected, "right", "2.0.0"),
        vec![registry("sha512-right")]
    );
    assert_eq!(
        sources(&collected, "real", "3.0.0"),
        vec![registry("sha512-real")]
    );
    assert_eq!(
        sources(&collected, "inside", "1.0.0"),
        vec![LockedSource::NotRegistry]
    );
}

#[test]
fn pnpm_packages_record_resolution_integrity() {
    let value: serde_yaml::Value = serde_yaml::from_str(
        r#"
lockfileVersion: '9.0'
packages:
  react@18.3.1:
    resolution: {integrity: sha512-react}
  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-scope}
  react-dom@19.0.0(react@19.0.0):
    resolution: {integrity: sha512-dom}
  local@1.0.0:
    resolution: {directory: ../local, type: directory}
"#,
    )
    .unwrap();
    let parsed = ParsedLockfile::Pnpm {
        value,
        importer_key: ".".into(),
        path: std::path::PathBuf::from("pnpm-lock.yaml"),
    };
    let collected = collect(&parsed).unwrap();
    assert_eq!(collected.lockfile, "pnpm-lock.yaml");
    assert_eq!(
        sources(&collected, "react", "18.3.1"),
        vec![registry("sha512-react")]
    );
    assert_eq!(
        sources(&collected, "@scope/pkg", "1.2.3"),
        vec![registry("sha512-scope")]
    );
    assert_eq!(
        sources(&collected, "react-dom", "19.0.0"),
        vec![registry("sha512-dom")]
    );
    assert_eq!(
        sources(&collected, "local", "1.0.0"),
        vec![LockedSource::NotRegistry]
    );
}

#[test]
fn bun_packages_record_fourth_element_integrity() {
    let value = serde_json::json!({
        "lockfileVersion": 1,
        "workspaces": {"": {"name": "app"}},
        "packages": {
            "lodash": ["lodash@4.17.21", "", {}, "sha512-lodash"],
            "alias": ["real@1.0.0", "", {}, "sha512-real"],
            "@scope/pkg": ["@scope/pkg@2.0.0", "", {}, "sha512-scope"],
            "gitdep": ["gitdep@github:acme/gitdep#abc", {}, "abc"],
            "app-lib": ["app-lib@workspace:packages/lib"]
        }
    });
    let parsed = ParsedLockfile::Bun {
        value,
        importer_key: String::new(),
    };
    let collected = collect(&parsed).unwrap();
    assert_eq!(collected.lockfile, "bun.lock");
    assert_eq!(
        sources(&collected, "lodash", "4.17.21"),
        vec![registry("sha512-lodash")]
    );
    assert_eq!(
        sources(&collected, "real", "1.0.0"),
        vec![registry("sha512-real")]
    );
    assert_eq!(
        sources(&collected, "@scope/pkg", "2.0.0"),
        vec![registry("sha512-scope")]
    );
    assert_eq!(collected.entries.len(), 3, "{:?}", collected.entries);
}

#[test]
fn yarn_classic_records_integrity_and_resolved_sha1_fragment() {
    let content = r#"
"react@^18.0.0", react@^18.3.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#4dd7a8ee69d7ca1ebe2f7c3e18c71b3f2d1b6a8c"
  integrity sha512-react

"alias@npm:real@^1.0.0":
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/real/-/real-1.0.0.tgz"
  integrity sha512-real
"#;
    let parsed = super::super::yarn::parse_lockfile(
        content,
        PathBuf::from("/repo/yarn.lock"),
        std::path::Path::new("/repo"),
    )
    .unwrap();
    let collected = collect(&ParsedLockfile::Yarn(parsed)).unwrap();
    assert_eq!(collected.lockfile, "yarn.lock");
    assert_eq!(
        sources(&collected, "react", "18.3.1"),
        vec![LockedSource::Registry {
            integrity: Some("sha512-react".into()),
            sha1_hex: Some("4dd7a8ee69d7ca1ebe2f7c3e18c71b3f2d1b6a8c".into()),
        }]
    );
    assert_eq!(
        sources(&collected, "real", "1.0.0"),
        vec![registry("sha512-real")]
    );
}

#[test]
fn yarn_berry_is_not_comparable() {
    let content = r#"
__metadata:
  version: 8

"react@npm:^18.3.0":
  version: 18.3.1
  resolution: "react@npm:18.3.1"
  checksum: 10c0/abcdef
  languageName: node
  linkType: hard
"#;
    let parsed = super::super::yarn::parse_lockfile(
        content,
        PathBuf::from("/repo/yarn.lock"),
        std::path::Path::new("/repo"),
    )
    .unwrap();
    assert!(collect(&ParsedLockfile::Yarn(parsed)).is_none());
}

#[test]
fn non_npm_lockfiles_are_not_collected() {
    assert!(collect(&ParsedLockfile::None).is_none());
    assert!(collect(&ParsedLockfile::Ruby(String::new())).is_none());
}

#[test]
fn lockfile_data_carries_integrity_for_direct_and_transitive_resolution() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package-lock.json"),
        serde_json::json!({
            "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
            "packages": {
                "": {"name": "app", "version": "1.0.0", "dependencies": {"left": "^1.0.0"}},
                "node_modules/left": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/left/-/left-1.0.0.tgz", "integrity": "sha512-left", "dependencies": {"right": "2.0.0"}},
                "node_modules/right": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/right/-/right-2.0.0.tgz", "integrity": "sha512-right"}
            }
        })
        .to_string(),
    )
    .unwrap();
    let direct = vec![Dependency {
        name: "left".into(),
        version: Some("^1.0.0".into()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    let direct_integrity = data
        .resolution
        .npm_integrity
        .as_ref()
        .expect("direct resolution carries lockfile integrity");
    assert_eq!(
        sources(direct_integrity, "left", "1.0.0"),
        vec![registry("sha512-left")]
    );
    let transitive = data.resolve_transitive(&data.transitive_deps).unwrap();
    let transitive_integrity = transitive
        .npm_integrity
        .as_ref()
        .expect("transitive resolution carries lockfile integrity");
    assert_eq!(
        sources(transitive_integrity, "right", "2.0.0"),
        vec![registry("sha512-right")]
    );
    let _ = std::fs::remove_dir_all(&dir);
}
