//! A Poetry or uv dependency whose marker is false for the scan target is still a direct
//! dependency: it gets the canonical, similarity, existence and metadata checks every direct
//! dependency gets, in every scan mode. The target only chooses which versions are resolved.
use super::*;

const PYPI_FILES: &str = "https://files.pythonhosted.org/packages/aa";
const WIN_MARKER: &str = "sys_platform == 'win32'";

fn target<'a>(scan_mode: ScanMode) -> ScanOptions<'a> {
    ScanOptions {
        python_platform: Some("linux".to_string()),
        python_arch: Some("x86_64".to_string()),
        python_version: Some("3.12".to_string()),
        scan_mode,
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    }
}

fn sdist(name: &str) -> String {
    format!(
        "sdist = {{ url = \"{PYPI_FILES}/{name}-1.tar.gz\", hash = \"sha256:{hash}\" }}\n",
        hash = "a".repeat(64)
    )
}

/// uv project: `six` everywhere, `gated==version` only on Windows; both locked.
fn write_uv_project(dir: &std::path::Path, gated: &str, version: &str) {
    std::fs::write(
        dir.join("pyproject.toml"),
        format!(
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.10\"\ndependencies = [\"six==1.17.0\", \"{gated}=={version}; {WIN_MARKER}\"]\n\n[tool.uv]\npackage = false\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        format!(
            "version = 1\nrevision = 3\nrequires-python = \">=3.10\"\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = {{ virtual = \".\" }}\ndependencies = [\n    {{ name = \"{gated}\", marker = \"{WIN_MARKER}\" }},\n    {{ name = \"six\" }},\n]\n\n[package.metadata]\nrequires-dist = [{{ name = \"{gated}\", marker = \"{WIN_MARKER}\", specifier = \"=={version}\" }}, {{ name = \"six\", specifier = \"==1.17.0\" }}]\n\n[[package]]\nname = \"{gated}\"\nversion = \"{version}\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n{gated_sdist}\n[[package]]\nname = \"six\"\nversion = \"1.17.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n{six}",
            gated_sdist = sdist(gated),
            six = sdist("six"),
        ),
    )
    .unwrap();
}

/// Poetry project: `six` everywhere, `gated==version` only on Windows; both locked.
fn write_poetry_gated_project(dir: &std::path::Path, gated: &str, version: &str) {
    let hash = "b".repeat(64);
    write_poetry_project(
        dir,
        &format!(
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = [\"x <x@example.com>\"]\npackage-mode = false\n\n[tool.poetry.dependencies]\npython = \"^3.10\"\nsix = \"1.17.0\"\n{gated} = {{version = \"{version}\", markers = \"{WIN_MARKER}\"}}\n"
        ),
        &format!(
            "[[package]]\nname = \"{gated}\"\nversion = \"{version}\"\ndescription = \"\"\noptional = false\npython-versions = \">=2.7\"\ngroups = [\"main\"]\nmarkers = \"sys_platform == \\\"win32\\\"\"\nfiles = [{{file = \"{gated}-{version}-py3-none-any.whl\", hash = \"sha256:{hash}\"}}]\n\n[[package]]\nname = \"six\"\nversion = \"1.17.0\"\ndescription = \"\"\noptional = false\npython-versions = \">=2.7\"\ngroups = [\"main\"]\nfiles = [{{file = \"six-1.17.0-py2.py3-none-any.whl\", hash = \"sha256:{hash}\"}}]\n\n[metadata]\nlock-version = \"2.1\"\npython-versions = \"^3.10\"\ncontent-hash = \"__CONTENT_HASH__\"\n"
        ),
    );
}

async fn scan(
    dir: &std::path::Path,
    config: config::SloppyJoeConfig,
    registry: &FakeRegistry,
    opts: &ScanOptions<'_>,
) -> Vec<Issue> {
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), &config).unwrap();
    let mut issues = preflight_project_inputs_with_options(dir, &specs, &config, opts).unwrap();
    for project in parse_project_inputs_with_options(dir, &specs, &config, opts).unwrap() {
        let report = scan_parsed_project(&project, config.clone(), registry, &FakeOsvClient, opts)
            .await
            .unwrap();
        issues.extend(report.issues);
    }
    issues
}

fn registry_with(names: &[&str]) -> FakeRegistry {
    FakeRegistry {
        existing: names.iter().map(|name| name.to_string()).collect(),
    }
}

fn direct_issue<'a>(issues: &'a [Issue], package: &str, check: &str) -> Option<&'a Issue> {
    issues.iter().find(|issue| {
        issue.package == package
            && issue.check.starts_with(check)
            && issue.source.as_deref() == Some("direct")
    })
}

fn canonical_config() -> config::SloppyJoeConfig {
    let config_dir = unique_dir();
    let config_path = config_dir.join("config.json");
    std::fs::write(
        &config_path,
        r#"{"canonical":{"pypi":{"httpx":["requestz"]}},"internal":{},"allowed":{}}"#,
    )
    .unwrap();
    config::load_config(Some(config_path.as_path())).unwrap()
}

#[tokio::test]
async fn a_uv_dependency_behind_a_false_marker_gets_the_similarity_check() {
    let dir = unique_dir();
    write_uv_project(&dir, "requestz", "2.31.0");
    let registry = registry_with(&["six", "requests", "requestz"]);
    for mode in [ScanMode::Full, ScanMode::Ci] {
        let issues = scan(&dir, Default::default(), &registry, &target(mode)).await;
        assert!(
            direct_issue(&issues, "requestz", "similarity/").is_some(),
            "{mode:?}: {issues:#?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_poetry_dependency_behind_a_false_marker_gets_the_similarity_check() {
    let dir = unique_dir();
    write_poetry_gated_project(&dir, "requestz", "2.31.0");
    let registry = registry_with(&["six", "requests", "requestz"]);
    let issues = scan(&dir, Default::default(), &registry, &target(ScanMode::Full)).await;
    assert!(
        direct_issue(&issues, "requestz", "similarity/").is_some(),
        "{issues:#?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_dependency_behind_a_false_marker_gets_canonical_policy_in_fast_mode() {
    let uv = unique_dir();
    write_uv_project(&uv, "requestz", "2.31.0");
    let poetry = unique_dir();
    write_poetry_gated_project(&poetry, "requestz", "2.31.0");
    let registry = registry_with(&["six", "requests", "requestz", "httpx"]);
    for dir in [&uv, &poetry] {
        let issues = scan(dir, canonical_config(), &registry, &target(ScanMode::Fast)).await;
        let issue = direct_issue(&issues, "requestz", "canonical").unwrap_or_else(|| {
            panic!("{}: {issues:#?}", dir.display());
        });
        assert_eq!(issue.suggestion.as_deref(), Some("httpx"));
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[tokio::test]
async fn a_uv_dependency_behind_a_false_marker_gets_the_direct_existence_check() {
    let dir = unique_dir();
    write_uv_project(&dir, "zzz-not-a-real-pkg", "1.0.0");
    let registry = registry_with(&["six"]);
    let issues = scan(&dir, Default::default(), &registry, &target(ScanMode::Full)).await;
    let issue = direct_issue(&issues, "zzz-not-a-real-pkg", "existence")
        .unwrap_or_else(|| panic!("{issues:#?}"));
    assert_eq!(issue.severity, Severity::Error);
    // Checked once, as a direct dependency, not again as a transitive one.
    assert!(
        !issues
            .iter()
            .any(|issue| issue.package == "zzz-not-a-real-pkg"
                && issue.source.as_deref() == Some("transitive")),
        "{issues:#?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
