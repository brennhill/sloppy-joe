//! `pipfile_hash` must reproduce pipenv's `Pipfile.get_hash()` exactly:
//! sha256 of the JSON (sorted keys, `(",", ":")` separators, ASCII-escaped) of
//! `{"_meta": {"sources", "requires"}, "default", "develop", <custom categories>}`.
//! Expected values come from running pipenv's published algorithm in Python
//! (and, for the first vector, from the real Pipfile.lock in kennethreitz/legit).

use super::pipfile_hash;

fn hash_of(source: &str) -> Option<String> {
    pipfile_hash(&toml::from_str::<toml::Value>(source).unwrap())
}

#[test]
fn matches_a_real_published_pipfile_lock() {
    let source = r#"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[dev-packages]
legit = {editable = true,path = "."}
coverage = "*"
flake8 = "*"
pytest = "*"
pytest-cov = "*"
pyinstaller = "*"
pypiwin32 = {version="*", sys_platform="=='win32'"}

[packages]
"#;
    assert_eq!(
        hash_of(source).as_deref(),
        Some("77a5be3d06cada5dce498cdcadd0739b3c818c5a231124117b0e53ea77283193")
    );
}

#[test]
fn custom_categories_and_requires_are_included() {
    let source = r#"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[packages]
requests = "==2.32.3"

[dev-packages]
pytest = "*"

[docs]
mkdocs = {version = "==1.6.0", markers = "python_version >= '3.8'"}

[requires]
python_version = "3.12"
"#;
    assert_eq!(
        hash_of(source).as_deref(),
        Some("af554b33cc1b162c8d75d1f68062c5db269f5a2df368cfecfdbd0ecd929b97ee")
    );
}

#[test]
fn non_ascii_and_control_characters_are_escaped_like_python() {
    let source = r##"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[packages]
requests = "*"
weird = {version = "*", markers = "platform_node != 'café☃😀'"}
quote = {version = "*", markers = "extra == 'a\"b\\c\u0001\u007f'"}
"##;
    assert_eq!(
        hash_of(source).as_deref(),
        Some("30ef5415e8891001c66f794755f807dbafc068e3e7caa7289fea509340747d37")
    );
}

#[test]
fn source_only_pipfile_hashes_empty_sections() {
    let source = r#"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true
"#;
    assert_eq!(
        hash_of(source).as_deref(),
        Some("ebffa69a1fa192d1cef7cb42ad79231ca976565c5ce371a70160b3048d3cbc06")
    );
}

#[test]
fn pipfile_without_a_source_cannot_be_hashed() {
    assert_eq!(hash_of("[packages]\nrequests = \"*\"\n"), None);
}

#[test]
fn values_pipenv_cannot_serialize_are_not_hashed() {
    let source = r#"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[packages]
x = {version = "*", when = 1979-05-27T07:32:00Z}
"#;
    assert_eq!(hash_of(source), None);
}

#[test]
fn pipfile_settings_table_does_not_affect_the_hash() {
    let source = r#"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[pipfile]
anything = "ignored"
"#;
    assert_eq!(
        hash_of(source).as_deref(),
        Some("ebffa69a1fa192d1cef7cb42ad79231ca976565c5ce371a70160b3048d3cbc06")
    );
}
