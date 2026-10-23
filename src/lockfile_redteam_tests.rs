//! Regression tests for lockfile preflight/provenance red-team findings.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-lockpre-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_bun_project(dir: &std::path::Path, lockfile: &str) {
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","packageManager":"bun@1.3.9","dependencies":{"lodash":"^4.17.21"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("bun.lock"), lockfile).unwrap();
}

#[test]
fn bun_transitive_file_descriptor_outside_scan_root_blocks() {
    let dir = unique_dir();
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(dir.join("outside/evil")).unwrap();
    std::fs::write(dir.join("outside/evil/package.json"), r#"{"name":"evil"}"#).unwrap();
    write_bun_project(
        &project,
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "app", "dependencies": { "lodash": "^4.17.21" } }
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", { "dependencies": { "evil": "file:../outside/evil" } }, "sha512-lodash"],
    "evil": ["evil@file:../outside/evil", {}]
  }
}"#,
    );

    let err = preflight_scan_inputs(&project, Some("npm"))
        .expect_err("transitive Bun file: targets outside the scan root must block");
    assert!(err.to_string().contains("evil"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bun_transitive_file_descriptor_to_unscanned_dir_blocks() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("vendor/blob")).unwrap();
    write_bun_project(
        &dir,
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "app", "dependencies": { "lodash": "^4.17.21" } }
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", { "dependencies": { "blob": "file:vendor/blob" } }, "sha512-lodash"],
    "blob": ["blob@file:vendor/blob", {}]
  }
}"#,
    );

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("transitive Bun file: targets that are not scanned projects must block");
    let msg = err.to_string();
    assert!(msg.contains("blob"), "{msg}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bun_transitive_link_descriptor_to_unresolvable_target_blocks() {
    let dir = unique_dir();
    write_bun_project(
        &dir,
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "app", "dependencies": { "lodash": "^4.17.21" } }
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", { "dependencies": { "@evil/linked": "link:@evil/linked" } }, "sha512-lodash"],
    "@evil/linked": ["@evil/linked@link:@evil/linked", {}]
  }
}"#,
    );

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("transitive Bun link: targets must resolve to scanned projects");
    assert!(err.to_string().contains("@evil/linked"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bun_workspace_local_packages_resolving_to_scanned_members_are_accepted() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("packages/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"bun@1.3.9","workspaces":["packages/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/web/package.json"),
        r#"{"name":"web","dependencies":{"lib":"workspace:*"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("packages/lib/package.json"), r#"{"name":"lib"}"#).unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "root" },
    "packages/web": { "name": "web", "dependencies": { "lib": "workspace:*" } },
    "packages/lib": { "name": "lib" }
  },
  "packages": {
    "lib": ["lib@workspace:packages/lib"],
    "web": ["web@workspace:packages/web"]
  }
}"#,
    )
    .unwrap();

    preflight_scan_inputs(&dir, Some("npm"))
        .expect("Bun workspace entries resolving to scanned members should be accepted");

    let _ = std::fs::remove_dir_all(&dir);
}
