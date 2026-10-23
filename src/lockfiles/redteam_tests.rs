//! Regression tests for lockfile red-team findings (parser level).

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-lockrt-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn npm_dep(name: &str, version: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }
}

#[test]
fn bun_transitives_include_optional_dependencies() {
    let dir = unique_dir();
    let lockfile = dir.join("bun.lock");
    std::fs::write(
        &lockfile,
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "app", "dependencies": { "lodash": "^4.17.21" } }
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", { "optionalDependencies": { "hidden-optional": "1.0.0" }, "peerDependencies": { "hidden-peer": "2.0.0" } }, "sha512-lodash"],
    "hidden-optional": ["hidden-optional@1.0.0", "", {}, "sha512-opt"],
    "hidden-peer": ["hidden-peer@2.0.0", "", {}, "sha512-peer"]
  }
}"#,
    )
    .unwrap();
    let deps = vec![npm_dep("lodash", "^4.17.21")];
    let lock = LockfileData::parse_for_kind_with_lockfile(
        &dir,
        Some(crate::ProjectInputKind::Npm),
        &deps,
        Some(&lockfile),
    )
    .expect("bun.lock should parse");
    let names = lock
        .transitive_deps
        .iter()
        .map(|dep| dep.package_name().to_string())
        .collect::<Vec<_>>();
    assert!(
        names.contains(&"hidden-optional".to_string()),
        "optional-only bun packages must be scanned: {names:?}"
    );
    assert!(
        names.contains(&"hidden-peer".to_string()),
        "peer-only bun packages must be scanned: {names:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
