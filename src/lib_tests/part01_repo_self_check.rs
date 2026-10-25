use super::*;

#[test]
fn repo_self_check_config_is_valid_and_has_exact_similarity_suppressions() {
    let config_path = repo_root().join(".github/sloppy-joe-self-check.json");
    let config = config::load_config(Some(&config_path))
        .expect("checked-in self-check config should remain valid");
    let cargo_rules = config
        .similarity_exceptions
        .get("cargo")
        .expect("self-check config should define cargo similarity suppressions");

    let expected = [
        ("serde_json", "serde", "segment-overlap"),
        ("serde_json", "serde_kson", "keyboard-proximity"),
        ("serde_yaml", "serde", "segment-overlap"),
        ("clap", "coap", "keyboard-proximity"),
        ("clap", "flap", "keyboard-proximity"),
        ("async-trait", "trait-async", "word-reorder"),
        ("async-trait", "async_trait", "separator-swap"),
        ("colored", "colorer", "keyboard-proximity"),
        ("colored", "colorex", "keyboard-proximity"),
        ("futures", "future", "extra-char"),
        ("libc", "libx", "keyboard-proximity"),
        ("libc", "lib", "extra-char"),
        ("serde", "xerde", "keyboard-proximity"),
        ("serde", "srede", "char-swap"),
        ("strsim", "strim", "extra-char"),
        ("tokio", "toki", "extra-char"),
        ("tokio", "toio", "extra-char"),
        ("toml", "tomo", "keyboard-proximity"),
        ("toml", "tml", "extra-char"),
        ("json5", "json", "extra-char"),
    ];

    for (package, candidate, generator) in expected {
        assert!(
            cargo_rules.iter().any(|rule| {
                rule.package == package
                    && rule.candidate == candidate
                    && rule.generator == generator
            }),
            "missing self-check similarity suppression for {package} -> {candidate} ({generator})"
        );
    }
}

#[test]
fn repo_self_check_config_has_reviewed_cargo_metadata_exceptions() {
    let config_path = repo_root().join(".github/sloppy-joe-self-check.json");
    let config = config::load_config(Some(&config_path))
        .expect("checked-in self-check config should remain valid");
    let cargo_rules = config
        .metadata_exceptions
        .get("cargo")
        .expect("self-check config should define cargo metadata exceptions");

    let expected = [
        ("colored", "2.2.0", "kurtlawrence", "hwittenborn"),
        ("displaydoc", "0.2.5", "yaahc", "Manishearth"),
        ("crypto-common", "0.1.7", "tarcieri", "newpavlov"),
        ("cpufeatures", "0.2.17", "newpavlov", "tarcieri"),
        ("digest", "0.10.7", "newpavlov", "tarcieri"),
        ("icu_properties", "2.1.2", "sffc", "robertbastian"),
        (
            "icu_properties_data",
            "2.1.2",
            "Manishearth",
            "robertbastian",
        ),
        ("litemap", "0.8.1", "robertbastian", "Manishearth"),
        ("lazy_static", "1.5.0", "LukasKalbertodt", "cuviper"),
        ("redox_syscall", "0.5.18", "jackpot51", "4lDO2"),
        ("rustls-pki-types", "1.14.0", "ctz", "djc"),
        ("rustls-webpki", "0.103.10", "djc", "ctz"),
        ("rustls", "0.23.37", "djc", "cpu"),
        ("tower-layer", "0.3.3", "davidpdrsn", "LucioFranco"),
        ("tower-service", "0.3.3", "hawkw", "LucioFranco"),
        ("url", "2.5.8", "valenting", "Manishearth"),
        ("webpki-roots", "1.0.6", "cpu", "ctz"),
        ("zerotrie", "0.2.3", "robertbastian", "Manishearth"),
    ];

    for (package, version, previous_publisher, current_publisher) in expected {
        assert!(
            cargo_rules.iter().any(|rule| {
                rule.package == package
                    && rule.check == crate::names::METADATA_MAINTAINER_CHANGE
                    && rule.version == version
                    && rule.previous_publisher.as_deref() == Some(previous_publisher)
                    && rule.current_publisher.as_deref() == Some(current_publisher)
            }),
            "missing self-check metadata exception for {package} {version} {previous_publisher}->{current_publisher}"
        );
    }
}

#[test]
fn repo_cargo_manifest_pins_direct_dependencies_exactly() {
    let cargo_toml = std::fs::read_to_string(repo_root().join("Cargo.toml"))
        .expect("repo Cargo.toml must exist");
    let parsed: toml::Value = toml::from_str(&cargo_toml).expect("repo Cargo.toml must be valid");
    let deps = parsed
        .get("dependencies")
        .and_then(|value| value.as_table())
        .expect("repo Cargo.toml should have a [dependencies] table");

    for (name, value) in deps {
        let version = match value {
            toml::Value::String(version) => version.as_str(),
            toml::Value::Table(table) => table
                .get("version")
                .and_then(|version| version.as_str())
                .expect("dependency tables should carry explicit versions"),
            other => panic!("unexpected dependency shape for {name}: {other:?}"),
        };

        assert!(
            version.starts_with('='),
            "dependency {name} should use an exact version pin, found {version}"
        );
    }
}

#[test]
fn repo_ci_self_check_build_uses_locked_cargo_graph() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect("CI workflow must exist");
    assert!(
        workflow.contains("run: cargo build --release --locked"),
        "self-check CI must build with --locked so Cargo.lock cannot drift before scanning"
    );
}

#[test]
fn repo_ci_self_check_scans_repo_cargo_project_explicitly() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect("CI workflow must exist");
    assert!(
        workflow.contains("sloppy-joe check --ci --no-cache --type cargo --config"),
        "self-check CI should target the repo's Cargo project explicitly instead of auto-discovering fixture directories"
    );
}

#[test]
fn repo_ci_self_check_uses_isolated_cargo_workspace() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect("CI workflow must exist");
    assert!(
        workflow.contains("install -m 0644 Cargo.toml /tmp/sloppy-joe-self-check/Cargo.toml"),
        "self-check CI should stage an isolated Cargo.toml for repo-only scanning"
    );
    assert!(
        workflow.contains("install -m 0644 Cargo.lock /tmp/sloppy-joe-self-check/Cargo.lock"),
        "self-check CI should stage an isolated Cargo.lock for repo-only scanning"
    );
    assert!(
        workflow.contains("working-directory: /tmp/sloppy-joe-self-check"),
        "self-check CI should run from the isolated workspace instead of the repo root"
    );
}

#[test]
fn repo_cargo_lock_is_tracked_for_locked_ci_builds() {
    let tracked = tracked_repo_files();
    assert!(
        tracked.contains(&std::path::PathBuf::from("Cargo.lock")),
        "CI uses cargo build --locked, so the repository must track Cargo.lock"
    );
}

#[test]
fn fixture_files_are_tracked_in_git() {
    let repo = repo_root();
    let tracked = tracked_repo_files();

    let mut untracked = Vec::new();
    for path in collect_files(&repo.join("fixtures")) {
        let relative = path
            .strip_prefix(&repo)
            .expect("fixture path should live under repo root")
            .to_path_buf();
        if !tracked.contains(&relative) {
            untracked.push(relative);
        }
    }

    assert!(
        untracked.is_empty(),
        "all fixture files must be tracked in git so CI sees the same corpus: {:?}",
        untracked
    );
}

#[cfg(unix)]
#[test]
fn preflight_blocks_broken_detected_manifests_for_all_ecosystems() {
    let cases = [
        ("package.json", Some("npm")),
        ("requirements.txt", Some("pypi")),
        ("Cargo.toml", Some("cargo")),
        ("go.mod", Some("go")),
        ("Gemfile", Some("ruby")),
        ("composer.json", Some("php")),
        ("build.gradle", Some("jvm")),
        ("pom.xml", Some("jvm")),
        ("app.csproj", Some("dotnet")),
    ];

    for (manifest_name, project_type) in cases {
        let dir = unique_dir();
        symlink_path(
            &dir.join(manifest_name),
            &dir.join(format!("missing-{}", manifest_name)),
        );

        let err = preflight_scan_inputs(&dir, project_type)
            .expect_err("broken detected manifests must block scanning");
        let msg = err.to_string();
        assert!(
            msg.contains(manifest_name),
            "expected error to mention {manifest_name}, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn preflight_requires_manifest_for_explicit_project_types() {
    let cases = [
        (Some("npm"), "package.json"),
        (
            Some("pypi"),
            "Required Python manifest is missing for this project type.",
        ),
        (Some("cargo"), "Cargo.toml"),
        (Some("go"), "go.mod"),
        (Some("ruby"), "Gemfile"),
        (Some("php"), "composer.json"),
        (Some("jvm"), "build.gradle, build.gradle.kts, or pom.xml"),
        (Some("dotnet"), ".csproj"),
    ];

    for (project_type, expected) in cases {
        let dir = unique_dir();

        let err = preflight_scan_inputs(&dir, project_type)
            .expect_err("explicit project types must require a manifest");
        let msg = err.to_string();
        assert!(
            msg.contains(expected),
            "expected error to mention {expected}, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn preflight_requires_strict_lockfiles_for_supported_ecosystems() {
    let cases = [
        (
            Some("npm"),
            "package.json",
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
            "package-lock.json",
        ),
        (
            Some("pypi"),
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
            "poetry.lock",
        ),
        (
            Some("cargo"),
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
            "Cargo.lock",
        ),
        (
            Some("ruby"),
            "Gemfile",
            "source 'https://rubygems.org'\ngem 'rails'\n",
            "Gemfile.lock",
        ),
        (
            Some("php"),
            "composer.json",
            r#"{"require":{"laravel/framework":"^10.0"}}"#,
            "composer.lock",
        ),
        (
            Some("jvm"),
            "build.gradle",
            "plugins { id 'java' }\ndependencies { implementation 'org.slf4j:slf4j-api:2.0.0' }\n",
            "gradle.lockfile",
        ),
        (
            Some("dotnet"),
            "app.csproj",
            r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
            "packages.lock.json",
        ),
    ];

    for (project_type, manifest_name, manifest_content, expected_lockfile) in cases {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest_name), manifest_content).unwrap();

        let err = preflight_scan_inputs(&dir, project_type)
            .expect_err("missing required lockfiles must block scanning");
        let msg = err.to_string();
        assert!(
            msg.contains(expected_lockfile),
            "expected error to mention {expected_lockfile}, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn preflight_accepts_npm_shrinkwrap_as_required_lockfile() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("npm-shrinkwrap.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm")).unwrap();
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_malformed_npm_lockfiles() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("malformed npm lockfiles must block scanning");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));
    assert!(msg.contains("parse"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_peer_dependencies_in_npm_lockfile_roots() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"peerDependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","peerDependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm")).unwrap();
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_prefers_npm_shrinkwrap_over_package_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("npm-shrinkwrap.json"), "{not json").unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("npm-shrinkwrap.json must take precedence over package-lock.json");
    let msg = err.to_string();
    assert!(msg.contains("npm-shrinkwrap.json"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_out_of_sync_npm_lockfile_roots() {
    let dir = unique_dir();
    std::fs::write(dir.join("package.json"), r#"{"name":"demo"}"#).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("strict npm scans must block out-of-sync lockfile roots");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));
    assert!(msg.contains("out of sync"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_missing_poetry_lockfiles_for_poetry_projects() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("pypi"))
        .expect_err("Poetry projects must require poetry.lock");
    assert!(err.to_string().contains("poetry.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_malformed_poetry_lockfiles_for_poetry_projects() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("poetry.lock"), "not = [valid").unwrap();

    let err = preflight_scan_inputs(&dir, Some("pypi"))
        .expect_err("malformed trusted Python lockfiles must block scanning");
    let msg = err.to_string();
    assert!(msg.contains("poetry.lock"));
    assert!(msg.contains("parse"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_config_warns_for_legacy_requirements_projects_by_default() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "# legacy but allowed\n").unwrap();

    let report = scan_with_config(
        &dir,
        Some("pypi"),
        Default::default(),
        &ScanOptions::default(),
    )
    .await
    .expect("requirements.txt should be allowed in default Python mode");

    assert_eq!(report.packages_checked, 0);
    assert!(report.issues.iter().any(|issue| {
        issue.severity == Severity::Warning
            && issue.message.contains("requirements.txt")
            && issue.message.contains("Poetry with poetry.lock")
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_config_reports_active_local_overlay_relaxations() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

    let report = scan_with_config(
        &dir,
        Some("cargo"),
        config::SloppyJoeConfig {
            active_local_overlay_relaxations: vec!["host-local Cargo config trust".to_string()],
            ..Default::default()
        },
        &ScanOptions::default(),
    )
    .await
    .expect("local overlay relaxations should be reported as warnings, not block the scan");

    assert!(report.issues.iter().any(|issue| {
        issue.severity == Severity::Warning
            && issue.message.contains("local-only overlay")
            && issue.message.contains("host-local Cargo config trust")
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_config_warns_for_other_legacy_python_manifests_by_default() {
    let cases = [
        (
            "Pipfile",
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n[packages]\n",
        ),
        (
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        ),
        ("setup.cfg", "[metadata]\nname = demo\nversion = 0.1.0\n"),
        (
            "setup.py",
            "from setuptools import setup\nsetup(name='demo', version='0.1.0')\n",
        ),
    ];

    for (manifest_name, content) in cases {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest_name), content).unwrap();

        let report = scan_with_config(
            &dir,
            Some("pypi"),
            Default::default(),
            &ScanOptions::default(),
        )
        .await
        .expect("legacy Python manifests should warn and continue by default");

        assert!(report.issues.iter().any(|issue| {
            issue.severity == Severity::Warning
                && issue.message.contains(manifest_name)
                && issue.message.contains("Poetry with poetry.lock")
        }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[tokio::test]
async fn scan_with_config_respects_explicit_python_platform_during_python_preflight() {
    let dir = unique_dir();
    let host_platform =
        crate::parsers::python_scope::PythonProfile::runtime_for_current_host().target_platform;
    let selected_platform = if host_platform == "win32" {
        "linux"
    } else {
        "win32"
    };
    let pyproject = format!(
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
platform-helper = {{ version = "1.0.0", source = "private", markers = "sys_platform == '{host_platform}'" }}

[[tool.poetry.source]]
name = "private"
url = "https://private.example/simple"
priority = "explicit"
"#
    );
    write_poetry_project(
        &dir,
        &pyproject,
        r#"[[package]]
name = "platform-helper"
version = "1.0.0"
optional = false
python-versions = ">=3.8"
files = []

[package.source]
type = "explicit"
url = "https://private.example/simple"
reference = "private"

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let report = scan_with_config(
        &dir,
        Some("pypi"),
        config::SloppyJoeConfig::default(),
        &ScanOptions {
            python_platform: Some(selected_platform.to_string()),
            python_version: Some("3.12".to_string()),
            ..Default::default()
        },
    )
    .await
    .expect("explicit Python platform selection should flow through all preflight validation");

    assert_eq!(report.packages_checked, 0);
    assert!(!report.has_errors());
    assert!(
        !report.issues.iter().any(|issue| {
            issue.check == checks::names::RESOLUTION_PYTHON_IMPLICIT_RUNTIME_PROFILE
        })
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_config_blocks_legacy_python_manifests_in_poetry_only_mode() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "# legacy manifest\n").unwrap();

    let err = scan_with_config(
        &dir,
        Some("pypi"),
        python_config(config::PythonEnforcement::PoetryOnly),
        &ScanOptions::default(),
    )
    .await
    .expect_err("poetry_only mode must reject legacy Python manifests");

    let msg = err.to_string();
    assert!(msg.contains("Poetry"));
    assert!(msg.contains("requirements.txt"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_requires_go_sum_when_external_dependencies_exist() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("go"))
        .expect_err("go projects with external deps must require go.sum");
    let msg = err.to_string();
    assert!(msg.contains("go.sum"));
    assert!(msg.contains("go mod download all"), "{msg}");
    assert!(msg.contains("Go 1.21"), "{msg}");
    assert!(msg.contains("sloppy-joe fix-lockfile"), "{msg}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_requires_go_sum_when_only_indirect_external_dependencies_exist() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1 // indirect\n)\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("go"))
        .expect_err("go projects with indirect external deps must still require go.sum");
    let msg = err.to_string();
    assert!(msg.contains("go.sum"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_go_without_go_sum_for_stdlib_only_modules() {
    let dir = unique_dir();
    std::fs::write(dir.join("go.mod"), "module example.com/app\n\ngo 1.21\n").unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("go")).unwrap();
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
