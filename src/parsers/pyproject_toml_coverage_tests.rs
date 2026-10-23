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
