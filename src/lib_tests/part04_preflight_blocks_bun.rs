use super::*;

#[test]
fn preflight_blocks_bun_lock_with_wrong_package_identity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"bun@1.3.9","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "react": "18.3.1",
      },
    },
  },
  "packages": {
    "react": ["not-react@18.3.1", "", {}, "sha512-react"],
  }
}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("bun lockfiles with the wrong package identity should be rejected");
    assert!(err.to_string().contains("claims to resolve"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_standalone_bun_project_with_bun_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"bun@1.3.9","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "react": "18.3.1",
      },
    },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-react"],
    "loose-envify": ["loose-envify@1.4.0", "", { "dependencies": { "js-tokens": "^3.0.0 || ^4.0.0" } }, "sha512-loose"],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-js-tokens"],
  }
}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("standalone bun projects with bun.lock should be accepted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_bun_lock_for_alias_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"bun@1.3.9","dependencies":{"alias-react":"npm:react@^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "alias-react": "npm:react@^18.0.0",
      },
    },
  },
  "packages": {
    "alias-react": ["react@18.3.1", "", {}, "sha512-react"],
  }
}"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("bun alias direct dependencies should resolve through bun.lock");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    assert!(
        metadata_versions
            .lock()
            .unwrap()
            .contains(&Some("18.3.1".to_string()))
    );
    assert!(
        osv_versions
            .lock()
            .unwrap()
            .contains(&Some("18.3.1".to_string()))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_bun_workspace_child_with_root_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"bun@1.3.9","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "root",
    },
    "apps/web": {
      "name": "web",
      "dependencies": {
        "react": "^18.0.0",
      },
    },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-react"],
    "loose-envify": ["loose-envify@1.4.0", "", { "dependencies": { "js-tokens": "^3.0.0 || ^4.0.0" } }, "sha512-loose"],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-js-tokens"],
    "web": ["web@workspace:apps/web"],
  }
}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("bun workspace children should bind to the root bun.lock");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_shadow_child_bun_lock_inside_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"bun@1.3.9","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": { "name": "root" },
    "apps/web": { "name": "web" },
  },
  "packages": {
    "web": ["web@workspace:apps/web"],
  }
}"#,
    )
    .unwrap();
    std::fs::write(dir.join("apps/web/package.json"), r#"{"name":"web"}"#).unwrap();
    std::fs::write(
        dir.join("apps/web/bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": { "name": "web" },
  },
  "packages": {}
}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace children must not carry shadow bun lockfiles");
    let msg = err.to_string();
    assert!(msg.contains("apps/web/bun.lock"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_bun_lock_exact_versions_for_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"bun@1.3.9","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "react": "^18.0.0",
      },
    },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-react"],
    "loose-envify": ["loose-envify@1.4.0", "", { "dependencies": { "js-tokens": "^3.0.0 || ^4.0.0" } }, "sha512-loose"],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-js-tokens"],
  }
}"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("bun lockfiles should drive exact direct versions");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    let metadata_versions = metadata_versions.lock().unwrap().clone();
    let osv_versions = osv_versions.lock().unwrap().clone();
    assert!(metadata_versions.contains(&Some("18.3.1".to_string())));
    assert!(osv_versions.contains(&Some("18.3.1".to_string())));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bun_direct_resolution_uses_importer_binding_when_lockfile_has_multiple_versions() {
    let dir = unique_dir();
    let lockfile = dir.join("bun.lock");
    std::fs::write(
        &lockfile,
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "react": "^18.0.0",
      },
    },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": {} }, "sha512-react18"],
    "react-canary": ["react@19.0.0", "", { "dependencies": {} }, "sha512-react19"]
  }
}"#,
    )
    .unwrap();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let lock = crate::lockfiles::LockfileData::parse_for_kind_with_lockfile(
        &dir,
        Some(ProjectInputKind::Npm.lockfile_kind()),
        &deps,
        Some(&lockfile),
    )
    .expect("bun.lock should parse");

    assert_eq!(lock.resolution.exact_version(&deps[0]), Some("18.3.1"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bun_workspace_child_does_not_inherit_sibling_transitives() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    let lockfile = dir.join("bun.lock");
    std::fs::write(
        &lockfile,
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "apps/web": {
      "name": "web",
      "dependencies": {
        "react": "18.3.1"
      }
    },
    "apps/api": {
      "name": "api",
      "dependencies": {
        "axios": "1.7.0"
      }
    }
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "evil-web": "1.0.0" } }, "sha512-react"],
    "evil-web": ["evil-web@1.0.0", "", {}, "sha512-evil-web"],
    "axios": ["axios@1.7.0", "", { "dependencies": { "evil-api": "9.9.9" } }, "sha512-axios"],
    "evil-api": ["evil-api@9.9.9", "", {}, "sha512-evil-api"]
  }
}"#,
    )
    .unwrap();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("18.3.1".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let lock = crate::lockfiles::LockfileData::parse_for_kind_with_lockfile(
        &dir.join("apps/web"),
        Some(ProjectInputKind::Npm.lockfile_kind()),
        &deps,
        Some(&lockfile),
    )
    .expect("bun workspace child should parse with authoritative root lockfile");

    assert!(
        lock.transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-web")
    );
    assert!(
        !lock
            .transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-api" || dep.package_name() == "axios")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_standalone_yarn_classic_project_with_yarn_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@1.22.22","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"js-tokens@^3.0.0 || ^4.0.0":
  version "4.0.0"
  resolved "https://registry.yarnpkg.com/js-tokens/-/js-tokens-4.0.0.tgz#19203fb59991df98e3a287050d4647cdeaf32499"
  integrity sha512-js-tokens

loose-envify@^1.1.0:
  version "1.4.0"
  resolved "https://registry.yarnpkg.com/loose-envify/-/loose-envify-1.4.0.tgz#71ee51fa7be4caec1a63839f7e682d8132d30caf"
  integrity sha512-loose
  dependencies:
    js-tokens "^3.0.0 || ^4.0.0"

react@^18.0.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#49ab892009c53933625bd16b2533fc754cab2891"
  integrity sha512-react
  dependencies:
    loose-envify "^1.1.0"
"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("standalone Yarn classic projects with yarn.lock should be accepted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_yarn_classic_lock_exact_versions_for_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@1.22.22","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"js-tokens@^3.0.0 || ^4.0.0":
  version "4.0.0"
  resolved "https://registry.yarnpkg.com/js-tokens/-/js-tokens-4.0.0.tgz#19203fb59991df98e3a287050d4647cdeaf32499"
  integrity sha512-js-tokens

loose-envify@^1.1.0:
  version "1.4.0"
  resolved "https://registry.yarnpkg.com/loose-envify/-/loose-envify-1.4.0.tgz#71ee51fa7be4caec1a63839f7e682d8132d30caf"
  integrity sha512-loose
  dependencies:
    js-tokens "^3.0.0 || ^4.0.0"

react@^18.0.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#49ab892009c53933625bd16b2533fc754cab2891"
  integrity sha512-react
  dependencies:
    loose-envify "^1.1.0"
"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("Yarn classic lockfiles should drive exact direct versions");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    let metadata_versions = metadata_versions.lock().unwrap().clone();
    let osv_versions = osv_versions.lock().unwrap().clone();
    assert!(metadata_versions.contains(&Some("18.3.1".to_string())));
    assert!(osv_versions.contains(&Some("18.3.1".to_string())));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_standalone_yarn_berry_project_with_yarn_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@4.9.2","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"js-tokens@npm:^3.0.0 || ^4.0.0":
  version: 4.0.0
  resolution: "js-tokens@npm:4.0.0"
  checksum: 10c0/js-tokens
  languageName: node
  linkType: hard

"loose-envify@npm:^1.1.0":
  version: 1.4.0
  resolution: "loose-envify@npm:1.4.0"
  dependencies:
    js-tokens: "npm:^3.0.0 || ^4.0.0"
  checksum: 10c0/loose
  languageName: node
  linkType: hard

"react@npm:^18.0.0":
  version: 18.3.1
  resolution: "react@npm:18.3.1"
  dependencies:
    loose-envify: "npm:^1.1.0"
  checksum: 10c0/react
  languageName: node
  linkType: hard

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  dependencies:
    react: "npm:^18.0.0"
  languageName: unknown
  linkType: soft
"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("standalone Yarn Berry projects with yarn.lock should be accepted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_yarn_berry_lock_exact_versions_for_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@4.9.2","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"js-tokens@npm:^3.0.0 || ^4.0.0":
  version: 4.0.0
  resolution: "js-tokens@npm:4.0.0"
  checksum: 10c0/js-tokens
  languageName: node
  linkType: hard

"loose-envify@npm:^1.1.0":
  version: 1.4.0
  resolution: "loose-envify@npm:1.4.0"
  dependencies:
    js-tokens: "npm:^3.0.0 || ^4.0.0"
  checksum: 10c0/loose
  languageName: node
  linkType: hard

"react@npm:^18.0.0":
  version: 18.3.1
  resolution: "react@npm:18.3.1"
  dependencies:
    loose-envify: "npm:^1.1.0"
  checksum: 10c0/react
  languageName: node
  linkType: hard

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  dependencies:
    react: "npm:^18.0.0"
  languageName: unknown
  linkType: soft
"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("Yarn Berry lockfiles should drive exact direct versions");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    let metadata_versions = metadata_versions.lock().unwrap().clone();
    let osv_versions = osv_versions.lock().unwrap().clone();
    assert!(metadata_versions.contains(&Some("18.3.1".to_string())));
    assert!(osv_versions.contains(&Some("18.3.1".to_string())));

    let _ = std::fs::remove_dir_all(&dir);
}
