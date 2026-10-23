//! Red-team regressions: Pipenv installs custom package categories, so they must be scanned.

use super::*;
use crate::parsers::test_utils::*;

#[test]
fn custom_package_categories_are_scanned() {
    let dir = setup_test_dir(
        "pipfile-categories",
        "Pipfile",
        r#"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[packages]
requests = "*"

[dev-packages]
pytest = "*"

[docs]
evil-category = "*"

[requires]
python_version = "3.12"

[pipenv]
allow_prereleases = false

[scripts]
start = "python app.py"
"#,
    );
    let names: Vec<String> = parse(&dir).unwrap().into_iter().map(|d| d.name).collect();
    assert_eq!(
        names,
        vec![
            "requests".to_string(),
            "pytest".to_string(),
            "evil-category".to_string()
        ]
    );
    cleanup(&dir);
}

#[test]
fn custom_categories_apply_the_same_source_rules() {
    let dir = setup_test_dir(
        "pipfile-category-git",
        "Pipfile",
        "[docs]\nevil = { git = \"https://evil.example/evil.git\" }\n",
    );
    assert!(parse(&dir).is_err());
    cleanup(&dir);
}

#[test]
fn non_table_top_level_entries_fail_closed() {
    let dir = setup_test_dir("pipfile-non-table", "Pipfile", "evil = \"*\"\n");
    assert!(parse(&dir).is_err());
    cleanup(&dir);
}

fn parse_pipfile_packages(name: &str, packages: &str) -> Vec<crate::Dependency> {
    let dir = setup_test_dir(
        name,
        "Pipfile",
        &format!(
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n[packages]\n{packages}\n"
        ),
    );
    let deps = parse(&dir).unwrap();
    cleanup(&dir);
    deps
}

#[test]
fn bare_wildcard_version_means_equals_like_pipenv() {
    // Real-world: pypa/pipenv's own Pipfile has `gunicorn = {version = "26.2.*", ...}`.
    let deps = parse_pipfile_packages(
        "pipfile-bare-wildcard",
        "gunicorn = {version = \"26.2.*\", sys_platform = \"== 'linux'\"}",
    );
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "gunicorn");
}

#[test]
fn bare_plain_version_means_equals_like_pipenv() {
    let deps = parse_pipfile_packages("pipfile-bare-version", "requests = \"2.32.3\"");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version.as_deref(), Some("==2.32.3"));
}

#[test]
fn operator_versions_are_left_alone() {
    for spec in ["==1.0", ">=1.0,<2", "~=1.4.2", "!=1.5", "<3", "===1.0"] {
        let deps = parse_pipfile_packages("pipfile-operators", &format!("requests = \"{spec}\""));
        assert_eq!(deps.len(), 1, "{spec}");
        assert_eq!(deps[0].name, "requests", "{spec}");
    }
}
