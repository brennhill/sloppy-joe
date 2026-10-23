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
