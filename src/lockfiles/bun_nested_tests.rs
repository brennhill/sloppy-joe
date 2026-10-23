//! bun.lock records a package installed under another package's own
//! node_modules with a nested key (`parent/child`). Bun resolves a dependency
//! from the nearest nested entry before falling back to the top-level one, so
//! the walker must do the same: otherwise the nested version (the one that is
//! actually installed) is swapped for the top-level one and never scanned.
//! Entries no workspace reaches must be scanned even when the lockfile has no
//! root (`""`) workspace to own them.

use super::bun;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-bun-nested-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn parse(lock: &str) -> serde_json::Value {
    json5::from_str(lock).unwrap()
}

fn scanned(lock: &serde_json::Value, importer: &str) -> Vec<String> {
    let mut names = bun::parse_all_from_value_for_importer(lock, importer)
        .unwrap()
        .into_iter()
        .map(|dep| format!("{}@{}", dep.name, dep.version.unwrap_or_default()))
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// Root depends on `a` and `lodash@4`; `a` needs `lodash@3`, installed nested
/// as `a/lodash`. Member `app` depends only on `a`.
const NESTED_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {"name": "root", "dependencies": {"a": "^1.0.0", "lodash": "^4.17.21"}},
    "packages/app": {"name": "app", "dependencies": {"a": "^1.0.0"}},
  },
  "packages": {
    "a": ["a@1.0.0", "", {"dependencies": {"lodash": "^3.0.0"}}, "sha512-a"],
    "a/lodash": ["lodash@3.10.1", "", {}, "sha512-b"],
    "lodash": ["lodash@4.17.21", "", {}, "sha512-c"],
    "app": ["app@workspace:packages/app"],
  },
}"#;

#[test]
fn nested_entry_shadows_top_level_for_its_parent() {
    let lock = parse(NESTED_LOCK);
    assert_eq!(
        scanned(&lock, "packages/app"),
        vec!["a@1.0.0".to_string(), "lodash@3.10.1".to_string()]
    );
}

#[test]
fn root_scans_nested_and_top_level_versions() {
    let lock = parse(NESTED_LOCK);
    let names = scanned(&lock, "");
    for expected in ["a@1.0.0", "lodash@3.10.1", "lodash@4.17.21"] {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
}

#[test]
fn deeper_nesting_resolves_through_the_nearest_ancestor() {
    // `a/b` needs `c`: bun looks for `a/b/c`, then `a/c`, then `c`.
    let lock = parse(
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {"name": "root", "dependencies": {"c": "2.0.0"}},
    "packages/app": {"name": "app", "dependencies": {"a": "1.0.0"}},
  },
  "packages": {
    "a": ["a@1.0.0", "", {"dependencies": {"b": "1.0.0"}}, "sha512-a"],
    "a/b": ["b@1.0.0", "", {"dependencies": {"c": "^1.0.0"}}, "sha512-b"],
    "b": ["b@9.0.0", "", {}, "sha512-x"],
    "a/c": ["c@1.0.0", "", {}, "sha512-c"],
    "c": ["c@2.0.0", "", {}, "sha512-d"],
  },
}"#,
    );
    assert_eq!(
        scanned(&lock, "packages/app"),
        vec![
            "a@1.0.0".to_string(),
            "b@1.0.0".to_string(),
            "c@1.0.0".to_string()
        ]
    );
}

#[test]
fn scoped_nested_keys_resolve() {
    let lock = parse(
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {"name": "root", "dependencies": {"@s/p": "1.0.0", "@t/q": "2.0.0"}},
    "packages/app": {"name": "app", "dependencies": {"@s/p": "1.0.0"}},
  },
  "packages": {
    "@s/p": ["@s/p@1.0.0", "", {"dependencies": {"@t/q": "^1.0.0"}}, "sha512-a"],
    "@s/p/@t/q": ["@t/q@1.0.0", "", {}, "sha512-b"],
    "@t/q": ["@t/q@2.0.0", "", {}, "sha512-c"],
  },
}"#,
    );
    assert_eq!(
        scanned(&lock, "packages/app"),
        vec!["@s/p@1.0.0".to_string(), "@t/q@1.0.0".to_string()]
    );
}

#[test]
fn workspace_specific_nested_entry_resolves_for_that_member() {
    // A member whose dependency differs from the hoisted version gets an
    // entry nested under its own package name.
    let lock = parse(
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {"name": "root", "dependencies": {"lodash": "^4.17.21"}},
    "packages/app": {"name": "app", "dependencies": {"lodash": "^3.0.0"}},
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", {}, "sha512-c"],
    "app/lodash": ["lodash@3.10.1", "", {}, "sha512-b"],
  },
}"#,
    );
    assert_eq!(
        scanned(&lock, "packages/app"),
        vec!["lodash@3.10.1".to_string()]
    );
    let deps = vec![crate::Dependency {
        name: "lodash".to_string(),
        version: Some("^3.0.0".to_string()),
        ecosystem: crate::Ecosystem::Npm,
        actual_name: None,
    }];
    let resolved = bun::resolve_from_value(&lock, &deps, "packages/app").unwrap();
    assert_eq!(resolved.exact_version(&deps[0]), Some("3.10.1"));
    assert!(resolved.issues.is_empty(), "{:?}", resolved.issues);
}

#[test]
fn orphans_are_scanned_when_lockfile_has_no_root_workspace() {
    let lock = parse(
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "packages/app": {"name": "app", "dependencies": {"lodash": "^4.17.21"}},
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", {}, "sha512-c"],
    "zzghost": ["zzghost@9.0.0", "", {}, "sha512-z"],
  },
}"#,
    );
    let names = scanned(&lock, "packages/app");
    assert!(names.contains(&"zzghost@9.0.0".to_string()), "{names:?}");
}

#[test]
fn member_leaves_orphans_to_the_root_workspace() {
    let lock = parse(
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {"name": "root"},
    "packages/app": {"name": "app", "dependencies": {"lodash": "^4.17.21"}},
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", {}, "sha512-c"],
    "zzghost": ["zzghost@9.0.0", "", {}, "sha512-z"],
  },
}"#,
    );
    assert_eq!(
        scanned(&lock, "packages/app"),
        vec!["lodash@4.17.21".to_string()]
    );
    assert!(scanned(&lock, "").contains(&"zzghost@9.0.0".to_string()));
}

#[test]
fn provenance_accepts_nested_keys_for_the_same_package() {
    let lock = parse(NESTED_LOCK);
    bun::validate_provenance(&lock, std::path::Path::new("bun.lock")).unwrap();
    let scoped = parse(
        r#"{"workspaces": {"": {"name": "root"}}, "packages": {
  "@s/p": ["@s/p@1.0.0", "", {}, "sha512-a"],
  "@s/p/@t/q": ["@t/q@1.0.0", "", {}, "sha512-b"],
  "a/@t/q": ["@t/q@1.0.0", "", {}, "sha512-b"],
}}"#,
    );
    bun::validate_provenance(&scoped, std::path::Path::new("bun.lock")).unwrap();
}

#[test]
fn provenance_rejects_nested_keys_claiming_another_package() {
    for packages in [
        r#""a/lodash": ["evil@1.0.0", "", {}, "sha512-b"]"#,
        r#""a/lodash": ["lodash-evil@1.0.0", "", {}, "sha512-b"]"#,
        r#""a/": ["lodash@1.0.0", "", {}, "sha512-b"]"#,
        r#""lodash/": ["lodash@1.0.0", "", {}, "sha512-b"]"#,
        r#""a//lodash": ["lodash@1.0.0", "", {}, "sha512-b"]"#,
        r#""@s/lodash": ["lodash@1.0.0", "", {}, "sha512-b"]"#,
    ] {
        let lock = parse(&format!(
            r#"{{"workspaces": {{"": {{"name": "root"}}}}, "packages": {{ {packages} }}}}"#
        ));
        assert!(
            bun::validate_provenance(&lock, std::path::Path::new("bun.lock")).is_err(),
            "{packages} must be rejected"
        );
    }
}

#[test]
fn nested_bun_lock_passes_preflight_and_scans_nested_version() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"bun@1.3.9","dependencies":{"a":"^1.0.0","lodash":"^4.17.21"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "workspaces": {"": {"name": "root", "dependencies": {"a": "^1.0.0", "lodash": "^4.17.21"}}},
  "packages": {
    "a": ["a@1.0.0", "", {"dependencies": {"lodash": "^3.0.0"}}, "sha512-a"],
    "a/lodash": ["lodash@3.10.1", "", {}, "sha512-b"],
    "lodash": ["lodash@4.17.21", "", {}, "sha512-c"],
  },
}"#,
    )
    .unwrap();
    crate::preflight_scan_inputs(&dir, Some("npm")).expect("nested bun.lock keys are valid");
    let _ = std::fs::remove_dir_all(&dir);
}
