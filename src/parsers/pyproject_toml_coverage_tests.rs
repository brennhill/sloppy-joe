//! Red-team coverage regressions for pyproject.toml dependency declarations
//! that were previously dropped silently.

use super::*;
use crate::parsers::test_utils::*;

fn scoped_names(deps: &[PythonScopedDependency]) -> Vec<String> {
    deps.iter().map(|dep| dep.dependency.name.clone()).collect()
}

#[test]
fn poetry2_manifest_unions_pep621_project_dependencies() {
    let dir = setup_test_dir(
        "pyproject-poetry2-pep621",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["evil-pep621>=1.0", "requests"]

[project.optional-dependencies]
docs = ["evil-extra"]

[tool.poetry]
packages = [{include = "demo"}]

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
"#,
    );
    let path = dir.join("pyproject.toml");

    let deps = parse_poetry_scoped_file(&path).unwrap();
    let names = scoped_names(&deps);
    assert!(names.contains(&"evil-pep621".to_string()), "{names:?}");
    assert!(names.contains(&"requests".to_string()), "{names:?}");
    assert!(names.contains(&"evil-extra".to_string()), "{names:?}");
    assert!(names.contains(&"pytest".to_string()), "{names:?}");

    let evil = deps
        .iter()
        .find(|dep| dep.dependency.name == "evil-pep621")
        .unwrap();
    assert!(evil.runtime_default);
    let extra = deps
        .iter()
        .find(|dep| dep.dependency.name == "evil-extra")
        .unwrap();
    assert!(extra.extras.contains("docs"));

    let public = parse_poetry_file(&path).unwrap();
    assert!(public.iter().any(|dep| dep.name == "evil-pep621"));
    cleanup(&dir);
}

#[test]
fn poetry2_manifest_parses_pep735_dependency_groups() {
    let dir = setup_test_dir(
        "pyproject-poetry2-groups",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"

[tool.poetry]

[dependency-groups]
lint = ["evil-lint==1.0"]
"#,
    );
    let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let lint = deps
        .iter()
        .find(|dep| dep.dependency.name == "evil-lint")
        .expect("PEP 735 groups must be parsed in Poetry projects");
    assert!(lint.groups.contains("lint"));
    cleanup(&dir);
}

#[test]
fn poetry2_manifest_rejects_dynamic_project_dependencies_that_are_also_declared() {
    let dir = setup_test_dir(
        "pyproject-poetry2-dynamic-conflict",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dynamic = ["dependencies"]
dependencies = ["requests"]

[tool.poetry.dependencies]
flask = "*"
"#,
    );
    let err = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("dynamic"), "{err}");
    cleanup(&dir);
}

#[test]
fn poetry2_manifest_with_dynamic_dependencies_still_uses_tool_poetry_dependencies() {
    let dir = setup_test_dir(
        "pyproject-poetry2-dynamic",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dynamic = ["dependencies"]

[tool.poetry.dependencies]
requests = "*"
"#,
    );
    let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
    assert_eq!(scoped_names(&deps), vec!["requests".to_string()]);
    cleanup(&dir);
}

fn names(deps: &[Dependency]) -> Vec<String> {
    deps.iter().map(|dep| dep.name.clone()).collect()
}

#[test]
fn build_system_requires_are_reported_as_unlocked_tooling() {
    let dir = setup_test_dir(
        "pyproject-build-system",
        "pyproject.toml",
        r#"[build-system]
requires = ["evil-backend>=1", "setuptools"]
build-backend = "evil_backend.api"

[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests"]
"#,
    );
    let path = dir.join("pyproject.toml");
    let tooling = parse_unlocked_tooling_file(&path).unwrap();
    assert_eq!(
        names(&tooling),
        vec!["evil-backend".to_string(), "setuptools".to_string()]
    );
    assert_eq!(tooling[0].version.as_deref(), Some(">=1"));

    // Locked/scoped project dependencies stay separate from build tooling.
    let scoped = parse_legacy_scoped_file(&path).unwrap();
    assert_eq!(scoped_names(&scoped), vec!["requests".to_string()]);

    // The public, unscoped parser reports everything that gets installed.
    let all = parse_legacy_file(&path).unwrap();
    assert!(names(&all).contains(&"evil-backend".to_string()));
    assert!(names(&all).contains(&"requests".to_string()));
    cleanup(&dir);
}

#[test]
fn build_system_requires_are_reported_for_poetry_projects() {
    let dir = setup_test_dir(
        "pyproject-build-system-poetry",
        "pyproject.toml",
        r#"[build-system]
requires = ["poetry-core>=2.0", "evil-backend==1.0"]
build-backend = "poetry.core.masonry.api"

[tool.poetry.dependencies]
requests = "*"
"#,
    );
    let path = dir.join("pyproject.toml");
    let tooling = parse_unlocked_tooling_file(&path).unwrap();
    assert!(names(&tooling).contains(&"evil-backend".to_string()));
    assert!(names(&parse_poetry_file(&path).unwrap()).contains(&"evil-backend".to_string()));
    assert!(
        !scoped_names(&parse_poetry_scoped_file(&path).unwrap())
            .contains(&"evil-backend".to_string())
    );
    cleanup(&dir);
}

#[test]
fn build_system_requires_must_be_an_array_of_strings() {
    let dir = setup_test_dir(
        "pyproject-build-system-string",
        "pyproject.toml",
        "[build-system]\nrequires = \"evil-backend\"\n",
    );
    let err = parse_unlocked_tooling_file(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("build-system"), "{err}");
    cleanup(&dir);
}

#[test]
fn build_system_requires_reject_direct_references() {
    let dir = setup_test_dir(
        "pyproject-build-system-url",
        "pyproject.toml",
        "[build-system]\nrequires = [\"evil @ https://evil.example/evil.whl\"]\n",
    );
    assert!(parse_unlocked_tooling_file(&dir.join("pyproject.toml")).is_err());
    cleanup(&dir);
}

#[test]
fn uv_dev_dependencies_are_dev_group_scoped() {
    let dir = setup_test_dir(
        "pyproject-uv-dev",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests"]

[tool.uv]
dev-dependencies = ["evil-uv-dev>=1"]
constraint-dependencies = ["evil-constraint==1"]
override-dependencies = ["evil-override==1"]
"#,
    );
    let path = dir.join("pyproject.toml");
    let deps = parse_legacy_scoped_file(&path).unwrap();
    let dev = deps
        .iter()
        .find(|dep| dep.dependency.name == "evil-uv-dev")
        .expect("uv dev-dependencies must be parsed");
    assert!(dev.groups.contains("dev"));
    assert!(!dev.runtime_default);
    // Constraints and overrides only steer resolution; they are not lockfile roots.
    assert!(!scoped_names(&deps).contains(&"evil-constraint".to_string()));

    let tooling = names(&parse_unlocked_tooling_file(&path).unwrap());
    assert!(
        tooling.contains(&"evil-constraint".to_string()),
        "{tooling:?}"
    );
    assert!(
        tooling.contains(&"evil-override".to_string()),
        "{tooling:?}"
    );
    cleanup(&dir);
}

#[test]
fn uv_override_dependencies_reject_direct_references() {
    let dir = setup_test_dir(
        "pyproject-uv-override-url",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"

[tool.uv]
override-dependencies = ["requests @ https://evil.example/requests.whl"]
"#,
    );
    assert!(parse_unlocked_tooling_file(&dir.join("pyproject.toml")).is_err());
    cleanup(&dir);
}

#[test]
fn uv_dev_dependencies_must_be_an_array() {
    let dir = setup_test_dir(
        "pyproject-uv-dev-string",
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.uv]\ndev-dependencies = \"evil\"\n",
    );
    assert!(parse_legacy_scoped_file(&dir.join("pyproject.toml")).is_err());
    cleanup(&dir);
}

#[test]
fn pdm_dev_dependencies_and_hatch_env_dependencies_are_group_scoped() {
    let dir = setup_test_dir(
        "pyproject-pdm-hatch",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests"]

[tool.pdm.dev-dependencies]
dev = ["evil-pdm-dev>=1"]

[tool.hatch.envs.default]
dependencies = ["evil-hatch-env>=1"]
extra-dependencies = ["evil-hatch-extra>=1"]
"#,
    );
    let deps = parse_legacy_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let pdm = deps
        .iter()
        .find(|dep| dep.dependency.name == "evil-pdm-dev")
        .expect("PDM dev-dependencies must be parsed");
    assert!(pdm.groups.contains("dev"));
    let hatch = deps
        .iter()
        .find(|dep| dep.dependency.name == "evil-hatch-env")
        .expect("Hatch environment dependencies must be parsed");
    assert!(hatch.groups.contains("default"));
    assert!(!hatch.runtime_default);
    assert!(
        deps.iter()
            .any(|dep| dep.dependency.name == "evil-hatch-extra")
    );
    cleanup(&dir);
}

#[test]
fn hatch_env_overrides_that_declare_dependencies_fail_closed() {
    let dir = setup_test_dir(
        "pyproject-hatch-overrides",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"

[tool.hatch.envs.test.overrides]
matrix.version.dependencies = [{ value = "evil-matrix", if = ["3.12"] }]
"#,
    );
    let err = parse_legacy_scoped_file(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("overrides"), "{err}");
    cleanup(&dir);
}

#[test]
fn hatch_build_and_env_plugins_and_pdm_overrides_are_unlocked_tooling() {
    let dir = setup_test_dir(
        "pyproject-hatch-build",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"

[tool.hatch.env]
requires = ["evil-env-plugin"]

[tool.hatch.build.targets.wheel.hooks.custom]
dependencies = ["evil-build-hook==1.0"]

[tool.pdm.resolution.overrides]
evil-pdm-override = ">=1.0"
"#,
    );
    let tooling = names(&parse_unlocked_tooling_file(&dir.join("pyproject.toml")).unwrap());
    for expected in ["evil-env-plugin", "evil-build-hook", "evil-pdm-override"] {
        assert!(tooling.contains(&expected.to_string()), "{tooling:?}");
    }
    cleanup(&dir);
}

#[test]
fn pdm_override_urls_fail_closed() {
    let dir = setup_test_dir(
        "pyproject-pdm-override-url",
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.pdm.resolution.overrides]\nrequests = \"https://evil.example/requests.whl\"\n",
    );
    assert!(parse_unlocked_tooling_file(&dir.join("pyproject.toml")).is_err());
    cleanup(&dir);
}

#[test]
fn poetry_requires_plugins_are_unlocked_tooling() {
    let dir = setup_test_dir(
        "pyproject-poetry-plugins",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dynamic = ["dependencies"]

[tool.poetry]
requires-plugins = { "evil-poetry-plugin" = ">=1", "poetry-plugin-export" = { version = "1.8.0" } }

[tool.poetry.dependencies]
requests = "*"
"#,
    );
    let path = dir.join("pyproject.toml");
    let tooling = parse_unlocked_tooling_file(&path).unwrap();
    assert_eq!(
        names(&tooling),
        vec![
            "evil-poetry-plugin".to_string(),
            "poetry-plugin-export".to_string()
        ]
    );
    assert_eq!(tooling[1].version.as_deref(), Some("==1.8.0"));
    assert!(
        !scoped_names(&parse_poetry_scoped_file(&path).unwrap())
            .contains(&"evil-poetry-plugin".to_string())
    );
    cleanup(&dir);
}

#[test]
fn poetry_requires_plugins_reject_git_sources() {
    let dir = setup_test_dir(
        "pyproject-poetry-plugins-git",
        "pyproject.toml",
        "[tool.poetry.requires-plugins]\nevil = { git = \"https://evil.example/evil.git\" }\n",
    );
    assert!(parse_unlocked_tooling_file(&dir.join("pyproject.toml")).is_err());
    cleanup(&dir);
}

#[test]
fn poetry_requires_plugins_must_be_a_table() {
    let dir = setup_test_dir(
        "pyproject-poetry-plugins-array",
        "pyproject.toml",
        "[tool.poetry]\nrequires-plugins = [\"evil\"]\n",
    );
    assert!(parse_unlocked_tooling_file(&dir.join("pyproject.toml")).is_err());
    cleanup(&dir);
}
