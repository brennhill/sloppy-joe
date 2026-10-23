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

fn write_npm_project(dir: &std::path::Path, lockfile_version: &str) {
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        format!(
            r#"{{
  "name": "app", "version": "1.0.0", {lockfile_version} "requires": true,
  "packages": {{
    "": {{"name":"app","version":"1.0.0","dependencies":{{"lodash":"^4.17.21"}}}},
    "node_modules/lodash": {{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-abc"}}
  }},
  "dependencies": {{
    "lodash": {{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-abc"}}
  }}
}}"#
        ),
    )
    .unwrap();
}

#[test]
fn npm_lockfile_version_integer_three_is_accepted() {
    let dir = unique_dir();
    write_npm_project(&dir, r#""lockfileVersion": 3,"#);
    preflight_scan_inputs(&dir, Some("npm")).expect("lockfileVersion 3 should be accepted");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn npm_lockfile_version_noncanonical_or_unknown_values_block() {
    for (label, field) in [
        ("float 1.0", r#""lockfileVersion": 1.0,"#),
        ("string 1", r#""lockfileVersion": "1","#),
        ("string 3", r#""lockfileVersion": "3","#),
        ("float 3.0", r#""lockfileVersion": 3.0,"#),
        ("null", r#""lockfileVersion": null,"#),
        ("zero", r#""lockfileVersion": 0,"#),
        ("future 4", r#""lockfileVersion": 4,"#),
        ("negative", r#""lockfileVersion": -1,"#),
        ("missing", ""),
    ] {
        let dir = unique_dir();
        write_npm_project(&dir, field);
        let err = preflight_scan_inputs(&dir, Some("npm"))
            .expect_err(&format!("lockfileVersion {label} must block"));
        assert!(
            err.to_string().contains("lockfileVersion"),
            "{label}: unexpected error {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn npm_lockfile_version_float_one_is_not_allowed_by_legacy_opt_in() {
    let dir = unique_dir();
    write_npm_project(&dir, r#""lockfileVersion": 1.0,"#);
    let config = config::SloppyJoeConfig {
        allow_legacy_npm_v1_lockfile: true,
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("npm"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("non-integer lockfileVersion must block even with the legacy opt-in");
    assert!(err.to_string().contains("lockfileVersion"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
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
