use super::*;
use crate::parsers::test_utils::*;

#[test]
fn classify_poetry_manifest() {
    let dir = setup_test_dir(
        "pyproject-poetry",
        "pyproject.toml",
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    );

    assert_eq!(
        classify_manifest(&dir.join("pyproject.toml")).unwrap(),
        PyprojectKind::Poetry
    );

    cleanup(&dir);
}

#[test]
fn parse_legacy_pep621_dependencies() {
    let dir = setup_test_dir(
        "pyproject-legacy",
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n[project.optional-dependencies]\ndev = [\"pytest==8.1.1\"]\n",
    );

    let deps = parse_legacy(&dir).unwrap();
    let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
    assert!(names.contains(&"requests"));
    assert!(names.contains(&"pytest"));

    cleanup(&dir);
}

#[test]
fn poetry_dev_dependencies_are_group_scoped() {
    let dir = setup_test_dir(
        "pyproject-poetry-dev-scope",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
fastapi = "^0.116"

[tool.poetry.dev-dependencies]
pytest = "^8"
"#,
    );

    let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let pytest = deps
        .iter()
        .find(|dep| dep.dependency.name == "pytest")
        .unwrap();
    assert!(pytest.groups.contains("dev"));
    assert!(!pytest.runtime_default);
    cleanup(&dir);
}

#[test]
fn poetry_table_dependency_preserves_requested_extras() {
    let dir = setup_test_dir(
        "pyproject-poetry-requested-extras",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
fastapi = { version = "0.116.0", extras = ["standard"] }
"#,
    );

    let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let fastapi = deps
        .iter()
        .find(|dep| dep.dependency.name == "fastapi")
        .unwrap();
    assert!(fastapi.requested_extras.contains("standard"));
    cleanup(&dir);
}

#[test]
fn poetry_table_dependency_preserves_markers() {
    let dir = setup_test_dir(
        "pyproject-poetry-table-markers",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
pywin32 = { version = "306", markers = "sys_platform == 'win32'" }
"#,
    );

    let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let pywin32 = deps
        .iter()
        .find(|dep| dep.dependency.name == "pywin32")
        .unwrap();
    assert_eq!(pywin32.marker.as_deref(), Some("sys_platform == 'win32'"));
    let linux = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
    assert!(!pywin32.is_in_scope(&linux).unwrap());
    cleanup(&dir);
}

#[test]
fn poetry_table_dependency_scopes_python_shorthand() {
    let dir = setup_test_dir(
        "pyproject-poetry-table-python-shorthand",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
pywin32 = { version = "306", python = "<3.13" }
"#,
    );

    let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let pywin32 = deps
        .iter()
        .find(|dep| dep.dependency.name == "pywin32")
        .unwrap();
    let py312 = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
    let py313 = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.13");
    assert!(pywin32.is_in_scope(&py312).unwrap());
    assert!(!pywin32.is_in_scope(&py313).unwrap());
    cleanup(&dir);
}

#[test]
fn poetry_table_dependency_scopes_platform_shorthand() {
    let dir = setup_test_dir(
        "pyproject-poetry-table-platform-shorthand",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
pyobjc = { version = "10.0", platform = "darwin" }
"#,
    );

    let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let pyobjc = deps
        .iter()
        .find(|dep| dep.dependency.name == "pyobjc")
        .unwrap();
    let macos = crate::parsers::python_scope::PythonProfile::for_target("darwin", "3.12");
    let linux = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
    assert!(pyobjc.is_in_scope(&macos).unwrap());
    assert!(!pyobjc.is_in_scope(&linux).unwrap());
    cleanup(&dir);
}

#[test]
fn legacy_poetry_extras_select_optional_dependencies() {
    let dir = setup_test_dir(
        "pyproject-poetry-legacy-extras",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.31.0"
uvicorn = { version = "0.30.0", optional = true }

[tool.poetry.extras]
standard = ["uvicorn"]
"#,
    );

    let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let requests = deps
        .iter()
        .find(|dep| dep.dependency.name == "requests")
        .unwrap();
    let uvicorn = deps
        .iter()
        .find(|dep| dep.dependency.name == "uvicorn")
        .unwrap();
    assert!(requests.runtime_default);
    assert!(!uvicorn.runtime_default);
    assert!(uvicorn.extras.contains("standard"));
    cleanup(&dir);
}

#[test]
fn pep621_optional_dependencies_are_extra_scoped() {
    let dir = setup_test_dir(
        "pyproject-pep621-extra-scope",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests==2.31.0"]

[project.optional-dependencies]
docs = ["mkdocs==1.6.0"]
"#,
    );

    let deps = parse_legacy_scoped_file(&dir.join("pyproject.toml")).unwrap();
    let mkdocs = deps
        .iter()
        .find(|dep| dep.dependency.name == "mkdocs")
        .unwrap();
    assert!(mkdocs.extras.contains("docs"));
    assert!(!mkdocs.runtime_default);
    cleanup(&dir);
}

#[test]
fn poetry_extracts_declared_sources() {
    let dir = setup_test_dir(
        "pyproject-poetry-source",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = { version = "^1.0.0", source = "internal" }

[[tool.poetry.source]]
name = "internal"
url = "https://packages.example.com/simple"
priority = "explicit"
"#,
    );

    let sources = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].name, "internal");
    assert_eq!(
        sources[0].normalized_url,
        "https://packages.example.com/simple/"
    );
    cleanup(&dir);
}

#[test]
fn poetry_extracts_dependency_source_intent() {
    let dir = setup_test_dir(
        "pyproject-poetry-source-intent",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = { version = "^1.0.0", source = "internal" }

[[tool.poetry.source]]
name = "internal"
url = "https://packages.example.com/simple"
"#,
    );

    let intents = parse_poetry_source_intents(&dir.join("pyproject.toml")).unwrap();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].package, "private-lib");
    assert_eq!(intents[0].source_name, "internal");
    assert_eq!(
        intents[0].normalized_url,
        "https://packages.example.com/simple/"
    );
    cleanup(&dir);
}

#[test]
fn poetry_rejects_source_binding_to_unknown_source_name() {
    let dir = setup_test_dir(
        "pyproject-poetry-source-unknown",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = { version = "^1.0.0", source = "internal" }
"#,
    );

    let err = parse_poetry_source_intents(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("unknown source"));
    cleanup(&dir);
}

#[test]
fn poetry_rejects_reserved_pypi_source_name_with_custom_url() {
    let dir = setup_test_dir(
        "pyproject-poetry-source-pypi-custom-url",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "pypi"
url = "https://packages.example.com/simple"
"#,
    );

    let err = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("reserved source name 'pypi'"));
    cleanup(&dir);
}

#[test]
fn poetry_rejects_default_pypi_url_under_non_pypi_alias() {
    let dir = setup_test_dir(
        "pyproject-poetry-source-pypi-alias",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "public"
url = "https://pypi.org/simple"
"#,
    );

    let err = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("rename PyPI"));
    cleanup(&dir);
}

#[test]
fn poetry_rejects_non_http_source_urls() {
    let dir = setup_test_dir(
        "pyproject-poetry-source-file-url",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "internal"
url = "file:///tmp/internal"
"#,
    );

    let err = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("http:// and https://"));
    cleanup(&dir);
}

#[test]
fn poetry_rejects_duplicate_source_names() {
    let dir = setup_test_dir(
        "pyproject-poetry-source-duplicate",
        "pyproject.toml",
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "internal"
url = "https://packages.example.com/simple"

[[tool.poetry.source]]
name = "internal"
url = "https://mirror.example.com/simple"
"#,
    );

    let err = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("duplicate source names"));
    cleanup(&dir);
}

#[test]
fn parse_poetry_exact_versions_as_exact_pins() {
    let dir = setup_test_dir(
        "pyproject-poetry-versions",
        "pyproject.toml",
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    );

    let deps = parse_poetry(&dir).unwrap();
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version.as_deref(), Some("==2.31.0"));

    cleanup(&dir);
}

#[test]
fn reject_setuptools_dynamic_dependencies() {
    let dir = setup_test_dir(
        "pyproject-setuptools-dynamic",
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.setuptools.dynamic]\ndependencies = { file = [\"requirements.txt\"] }\n",
    );

    let err = parse_legacy(&dir).unwrap_err();
    assert!(err.to_string().contains("dynamic"));

    cleanup(&dir);
}

#[test]
fn classify_uv_manifest() {
    let dir = setup_test_dir(
        "pyproject-uv",
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.uv]\n",
    );

    assert_eq!(
        classify_manifest(&dir.join("pyproject.toml")).unwrap(),
        PyprojectKind::Uv
    );

    cleanup(&dir);
}

#[test]
fn classify_mixed_poetry_and_uv_manifest_fails() {
    let dir = setup_test_dir(
        "pyproject-mixed",
        "pyproject.toml",
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.uv]\n",
    );

    let err = classify_manifest(&dir.join("pyproject.toml"))
        .expect_err("mixed Poetry and uv metadata must fail closed");
    assert!(
        err.to_string()
            .contains("Ambiguous Python project metadata")
    );

    cleanup(&dir);
}

#[test]
fn uv_extracts_declared_sources() {
    let dir = setup_test_dir(
        "pyproject-uv-sources",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[tool.uv.sources]
torch = { index = "pytorch" }

[[tool.uv.index]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"
"#,
    );

    let sources = parse_uv_sources(&dir.join("pyproject.toml")).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].name, "pytorch");
    assert_eq!(
        sources[0].normalized_url,
        "https://download.pytorch.org/whl/cu124/"
    );
    cleanup(&dir);
}

#[test]
fn uv_extracts_dependency_source_intent() {
    let dir = setup_test_dir(
        "pyproject-uv-source-intent",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[tool.uv.sources]
torch = { index = "pytorch" }

[[tool.uv.index]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"
"#,
    );

    let intents = parse_uv_source_intents(&dir.join("pyproject.toml")).unwrap();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].package, "torch");
    assert_eq!(intents[0].source_name, "pytorch");
    assert_eq!(
        intents[0].normalized_url,
        "https://download.pytorch.org/whl/cu124/"
    );
    cleanup(&dir);
}

#[test]
fn uv_extracts_marker_scoped_source_intents_from_arrays() {
    let dir = setup_test_dir(
        "pyproject-uv-source-marker",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[tool.uv.sources]
torch = [{ index = "pytorch", marker = "sys_platform == 'darwin'" }]

[[tool.uv.index]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"

[[tool.uv.index]]
name = "cpu"
url = "https://download.pytorch.org/whl/cpu"
"#,
    );

    let intents = parse_uv_source_intents_scoped(&dir.join("pyproject.toml")).unwrap();
    assert_eq!(intents.len(), 1);
    let darwin = crate::parsers::python_scope::PythonProfile::for_target("darwin", "3.12");
    assert!(intents[0].is_in_scope(&darwin).unwrap());
    assert_eq!(intents[0].intent.source_name, "pytorch");
    cleanup(&dir);
}

#[test]
fn uv_extracts_multiple_marker_scoped_source_intents_from_arrays() {
    let dir = setup_test_dir(
        "pyproject-uv-source-marker-multi",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[tool.uv.sources]
torch = [
  { index = "pytorch", marker = "sys_platform == 'darwin'" },
  { index = "cpu", marker = "sys_platform == 'linux'" },
]

[[tool.uv.index]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"

[[tool.uv.index]]
name = "cpu"
url = "https://download.pytorch.org/whl/cpu"
"#,
    );

    let intents = parse_uv_source_intents_scoped(&dir.join("pyproject.toml")).unwrap();
    assert_eq!(intents.len(), 2);
    let linux = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
    let linux_intents: Vec<_> = intents
        .iter()
        .filter_map(|intent| {
            intent
                .is_in_scope(&linux)
                .unwrap()
                .then_some(&intent.intent)
        })
        .collect();
    assert_eq!(linux_intents.len(), 1);
    assert_eq!(linux_intents[0].source_name, "cpu");
    cleanup(&dir);
}

#[test]
fn uv_rejects_non_http_index_urls() {
    let dir = setup_test_dir(
        "pyproject-uv-source-file-url",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[[tool.uv.index]]
name = "internal"
url = "file:///tmp/internal"
"#,
    );

    let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("http:// and https://"));
    cleanup(&dir);
}

#[test]
fn uv_rejects_reserved_pypi_index_name_with_custom_url() {
    let dir = setup_test_dir(
        "pyproject-uv-source-pypi-custom-url",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[[tool.uv.index]]
name = "pypi"
url = "https://packages.example.com/simple"
"#,
    );

    let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("reserved index name 'pypi'"));
    cleanup(&dir);
}

#[test]
fn uv_rejects_default_pypi_url_under_non_pypi_alias() {
    let dir = setup_test_dir(
        "pyproject-uv-source-pypi-alias",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[[tool.uv.index]]
name = "public"
url = "https://pypi.org/simple"
"#,
    );

    let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("rename PyPI"));
    cleanup(&dir);
}

#[test]
fn uv_rejects_duplicate_index_names() {
    let dir = setup_test_dir(
        "pyproject-uv-source-duplicate",
        "pyproject.toml",
        r#"[project]
name = "demo"
version = "0.1.0"

[[tool.uv.index]]
name = "internal"
url = "https://packages.example.com/simple"

[[tool.uv.index]]
name = "internal"
url = "https://mirror.example.com/simple"
"#,
    );

    let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("duplicate index names"));
    cleanup(&dir);
}

#[test]
fn uv_settings_that_redirect_resolution_block() {
    let base = "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n";
    for extra in [
        "[tool.uv]\nindex-url = \"https://evil.example/simple\"\n",
        "[tool.uv]\nfind-links = [\"./wheels\"]\n",
        "[tool.uv.pip]\nextra-index-url = [\"https://evil.example/simple\"]\n",
        "[tool.uv]\npython-install-mirror = \"https://evil.example/pythons\"\n",
        "[tool.uv]\npython-downloads-json-url = \"https://evil.example/dl.json\"\n",
        "[tool.uv]\npypy-install-mirror = \"https://evil.example/pypy\"\n",
    ] {
        let dir = setup_test_dir(
            "pyproject-uv-legacy",
            "pyproject.toml",
            &format!("{base}{extra}"),
        );
        let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(
            err.to_string().contains("Unsupported uv setting"),
            "{extra}: {err}"
        );
        cleanup(&dir);
    }
}

#[test]
fn a_uv_toml_with_index_settings_blocks_even_without_tool_uv() {
    let dir = setup_test_dir(
        "pyproject-uv-toml",
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    );
    std::fs::write(
        dir.join("uv.toml"),
        "no-index = true\nfind-links = [\"./wheels\"]\n",
    )
    .unwrap();
    assert!(parse_uv_sources(&dir.join("pyproject.toml")).is_err());
    std::fs::write(dir.join("uv.toml"), "native-tls = true\n").unwrap();
    assert!(parse_uv_sources(&dir.join("pyproject.toml")).is_ok());
    cleanup(&dir);
}

#[test]
fn uv_cache_and_build_dependency_settings_block() {
    let base = "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n";
    for extra in [
        "[tool.uv]\ncache-dir = \"./.uvcache\"\n",
        "[tool.uv.extra-build-dependencies]\nsix = [\"evil\"]\n",
    ] {
        let dir = setup_test_dir(
            "pyproject-uv-cache",
            "pyproject.toml",
            &format!("{base}{extra}"),
        );
        let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(
            err.to_string().contains("Unsupported uv setting"),
            "{extra}: {err}"
        );
        cleanup(&dir);
    }
}

#[test]
fn a_parent_pyproject_uv_redirect_blocks_a_child_project() {
    let parent = setup_test_dir(
        "pyproject-uv-parent",
        "pyproject.toml",
        "[tool.uv]\nindex-url = \"https://evil.example/simple\"\n",
    );
    let child = parent.join("sub");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(
        child.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let err = reject_uv_toml_redirects(&child.join("pyproject.toml")).unwrap_err();
    assert!(err.to_string().contains("index-url"), "{err}");
    cleanup(&parent);
}
