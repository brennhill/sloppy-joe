use super::*;

#[test]
fn preflight_blocks_go_projects_with_local_replace_targets() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire example.com/localdep v0.0.0\nreplace example.com/localdep => ../localdep\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("go"))
        .expect_err("go projects with local replace targets must fail closed");
    assert!(err.to_string().contains("local go.mod replace target"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_recurses_into_nested_projects() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("services/api")).unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"lockfileVersion":3}"#,
    )
    .unwrap();
    std::fs::write(dir.join("services/api/requirements.txt"), "flask==2.0\n").unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(paths.iter().any(|path| path == "apps/web/package.json"));
    assert!(
        paths
            .iter()
            .any(|path| path == "services/api/requirements.txt")
    );

    let npm_specs = detected_project_inputs(&dir, Some("npm")).unwrap();
    assert_eq!(npm_specs.len(), 1);
    assert_eq!(
        npm_specs[0]
            .manifest_path
            .strip_prefix(&dir)
            .unwrap()
            .display()
            .to_string(),
        "apps/web/package.json"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_discovers_alternate_python_requirements_files() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("services/api")).unwrap();
    std::fs::write(
        dir.join("services/api/requirements-dev.txt"),
        "flask==2.0\n",
    )
    .unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        paths
            .iter()
            .any(|path| path == "services/api/requirements-dev.txt"),
        "alternate requirements entrypoints must be discoverable from a repo-root scan"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_project_inputs_dedupes_requirement_files_included_by_other_entrypoints() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "-r requirements-base.txt\n").unwrap();
    std::fs::write(dir.join("requirements-base.txt"), "requests==2.31.0\n").unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default())
        .expect("included requirement files must not be scanned as standalone projects");

    assert_eq!(projects.len(), 1);
    assert_eq!(
        projects[0]
            .spec
            .manifest_path
            .strip_prefix(&dir)
            .unwrap()
            .display()
            .to_string(),
        "requirements.txt"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_do_not_skip_generic_directory_names() {
    for directory_name in [
        "vendor",
        "dist",
        "build",
        "third_party",
        "fixtures",
        "testdata",
        "target",
        ".venv",
        "venv",
        "__pycache__",
    ] {
        let dir = unique_dir();
        std::fs::create_dir_all(dir.join(directory_name).join("service")).unwrap();
        std::fs::write(
            dir.join(directory_name).join("service/package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();

        let specs = detected_project_inputs(&dir, None).unwrap();
        let paths: Vec<String> = specs
            .iter()
            .map(|spec| {
                spec.manifest_path
                    .strip_prefix(&dir)
                    .unwrap()
                    .display()
                    .to_string()
            })
            .collect();

        assert!(
            paths
                .iter()
                .any(|path| path == &format!("{directory_name}/service/package.json")),
            "root discovery must not silently skip source-controlled projects under {directory_name}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(unix)]
#[test]
fn detected_project_inputs_block_symlinked_dirs_outside_root() {
    let dir = unique_dir();
    let outside = unique_dir();
    std::fs::write(
        outside.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("linked-outside")).unwrap();

    let err = detected_project_inputs(&dir, None)
        .expect_err("symlinked directories outside the scan root must block discovery");

    assert!(err.to_string().contains("linked-outside"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&outside);
}

#[cfg(unix)]
#[test]
fn detected_project_inputs_block_ignored_name_symlinks_outside_root() {
    for directory_name in [
        "vendor",
        "dist",
        "build",
        "third_party",
        "fixtures",
        "testdata",
        "target",
        ".venv",
        "venv",
        "__pycache__",
    ] {
        let dir = unique_dir();
        let outside = unique_dir();
        std::fs::write(outside.join("requirements.txt"), "requests==2.31.0\n").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join(directory_name)).unwrap();

        let err = detected_project_inputs(&dir, None)
            .expect_err("outside-root symlinked directories must block discovery");
        assert!(err.to_string().contains(directory_name));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }
}

#[tokio::test]
async fn repo_root_scans_warn_for_legacy_python_manifests_instead_of_skipping_them() {
    let cases = [
        (
            "pyproject.toml",
            "[project]\nname = \"api\"\nversion = \"0.1.0\"\ndependencies = [\"flask==2.0.0\"]\n",
        ),
        (
            "Pipfile",
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n[packages]\nflask = \"==2.0.0\"\n",
        ),
        (
            "setup.cfg",
            "[metadata]\nname = api\nversion = 0.1.0\n[options]\ninstall_requires =\n    flask==2.0.0\n",
        ),
        (
            "setup.py",
            "from setuptools import setup\nsetup(name='api', version='0.1.0', install_requires=['flask==2.0.0'])\n",
        ),
    ];

    for (manifest_name, manifest_content) in cases {
        let dir = unique_dir();
        std::fs::create_dir_all(dir.join("apps/web")).unwrap();
        std::fs::create_dir_all(dir.join("services/api")).unwrap();
        std::fs::write(
            dir.join("apps/web/package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("apps/web/package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("services/api").join(manifest_name),
            manifest_content,
        )
        .unwrap();

        let report = scan_with_config(&dir, None, Default::default(), &ScanOptions::default())
            .await
            .expect("legacy Python manifests must be scanned, not ignored");

        assert!(report.issues.iter().any(|issue| {
            issue.severity == Severity::Warning
                && issue.message.contains(manifest_name)
                && issue.message.contains("Poetry with poetry.lock")
        }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn detected_project_inputs_prefer_poetry_projects_over_same_directory_legacy_manifests() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.11\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("requirements.txt"), "requests==2.30.0\n").unwrap();

    let specs = detected_project_inputs(&dir, Some("pypi"))
        .expect("same-directory Poetry and requirements manifests must be discoverable");

    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].kind, ProjectInputKind::PyProjectPoetry);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_reject_same_directory_legacy_pyproject_and_trusted_requirements() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("requirements.txt"),
        "requests==2.31.0 \\\n    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n",
    )
    .unwrap();

    let err = detected_project_inputs(&dir, Some("pypi"))
        .expect_err("same-directory legacy pyproject and trusted requirements must fail closed");
    assert!(err.to_string().contains("Ambiguous trusted Python roots"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_project_inputs_extracts_dependencies_from_legacy_python_manifests() {
    let cases = [
        (
            "requirements.txt",
            "requests==2.31.0\nurllib3==2.1.0\n",
            vec!["requests", "urllib3"],
        ),
        (
            "Pipfile",
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n[packages]\nrequests = \"==2.31.0\"\n[dev-packages]\npytest = \"==8.1.1\"\n",
            vec!["requests", "pytest"],
        ),
        (
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n[project.optional-dependencies]\ndev = [\"pytest==8.1.1\"]\n",
            vec!["requests"],
        ),
        (
            "setup.cfg",
            "[metadata]\nname = demo\nversion = 0.1.0\n[options]\ninstall_requires =\n    requests==2.31.0\n[options.extras_require]\ndev =\n    pytest==8.1.1\n",
            vec!["requests", "pytest"],
        ),
        (
            "setup.py",
            "from setuptools import setup\nsetup(name='demo', version='0.1.0', install_requires=['requests==2.31.0'], extras_require={'dev': ['pytest==8.1.1']})\n",
            vec!["requests", "pytest"],
        ),
    ];

    for (manifest_name, manifest_content, expected_names) in cases {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest_name), manifest_content).unwrap();

        let specs = detected_project_inputs(&dir, Some("pypi")).unwrap();
        let projects = parse_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default())
            .expect("legacy Python manifests must parse into dependencies");
        assert_eq!(projects.len(), 1);

        let names: Vec<&str> = projects[0]
            .deps
            .iter()
            .map(|dep| dep.name.as_str())
            .collect();
        for expected_name in expected_names {
            assert!(
                names.contains(&expected_name),
                "expected {manifest_name} to include dependency {expected_name}, got {names:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(unix)]
#[test]
fn detected_project_inputs_follow_symlinked_internal_directories() {
    use std::os::unix::fs::symlink;

    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("vendor/service")).unwrap();
    std::fs::write(
        dir.join("vendor/service/package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    symlink(dir.join("vendor"), dir.join("alias")).unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        paths
            .iter()
            .any(|path| path == "alias/service/package.json"),
        "symlinks to in-root directories must remain discoverable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_finds_hidden_projects_inside_checked_in_node_modules() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("examples/node_modules/hidden-app")).unwrap();
    std::fs::write(
        dir.join("examples/node_modules/hidden-app/package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("examples/node_modules/hidden-app/package-lock.json"),
        r#"{"name":"hidden-app","lockfileVersion":3,"packages":{"":{"name":"hidden-app","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let specs = detected_project_inputs(&dir, None)
        .expect("repo-root discovery must not let checked-in node_modules hide real projects");
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        paths
            .iter()
            .any(|path| path == "examples/node_modules/hidden-app/package.json"),
        "checked-in projects with their own lockfiles must still be discoverable under node_modules"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_finds_hidden_python_projects_inside_checked_in_node_modules() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("examples/node_modules/hidden-py")).unwrap();
    std::fs::write(
        dir.join("examples/node_modules/hidden-py/requirements.txt"),
        "requests==2.31.0\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("examples/node_modules/hidden-py/poetry.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
    )
    .unwrap();

    let specs = detected_project_inputs(&dir, None)
        .expect("supported non-npm projects under node_modules must not be silently skipped");
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        paths
            .iter()
            .any(|path| path == "examples/node_modules/hidden-py/requirements.txt"),
        "supported non-npm manifests under node_modules must still be discoverable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_ignore_installed_packages_inside_node_modules_without_project_lockfiles()
{
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("node_modules/react")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/react/package.json"),
        r#"{"name":"react","version":"18.3.1"}"#,
    )
    .unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        !paths
            .iter()
            .any(|path| path == "node_modules/react/package.json"),
        "discovery must not explode into installed npm packages"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn detected_project_inputs_ignore_installed_packages_inside_symlinked_node_modules() {
    use std::os::unix::fs::symlink;

    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("node_modules/react")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/react/package.json"),
        r#"{"name":"react","version":"18.3.1"}"#,
    )
    .unwrap();
    symlink(dir.join("node_modules"), dir.join("alias")).unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        !paths.iter().any(|path| path == "alias/react/package.json"),
        "symlinked paths into installed node_modules must not bypass installed-package suppression"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_ignores_python_vendor_manifests_inside_node_modules() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("node_modules/vendor-python")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/vendor-python/setup.py"),
        "from setuptools import setup\n",
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("vendored Python manifests inside node_modules must not block unrelated scans");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_local_file_npm_dependencies_outside_scan_root() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"local-lib":"file:../local-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"local-lib":"file:../local-lib"}},"node_modules/local-lib":{"resolved":"../local-lib","link":true}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("local npm dependencies outside the scan root must block scanning");
    let msg = err.to_string();
    assert!(msg.contains("outside the scan root"));
    assert!(msg.contains("local-lib"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_unresolved_workspace_npm_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"workspace-lib":"workspace:*"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"workspace-lib":"workspace:*"}},"node_modules/workspace-lib":{"resolved":"packages/workspace-lib","link":true}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("workspace npm dependencies must resolve to a scanned local project");
    let msg = err.to_string();
    assert!(msg.contains("workspace-lib"));
    assert!(msg.contains("workspaces"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_local_npm_dependencies_within_scan_root() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::create_dir_all(dir.join("packages/local-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*","packages/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*","packages/*"]},"apps/web":{"name":"web","dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../../packages/local-lib"}},"packages/workspace-lib":{"name":"workspace-lib","dependencies":{"react":"18.3.1"}},"packages/local-lib":{"name":"local-lib"},"node_modules/workspace-lib":{"resolved":"packages/workspace-lib","link":true},"node_modules/local-lib":{"resolved":"packages/local-lib","link":true},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../../packages/local-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/local-lib/package.json"),
        r#"{"name":"local-lib"}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("local npm dependencies within the scan root must be accepted when discoverable");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
