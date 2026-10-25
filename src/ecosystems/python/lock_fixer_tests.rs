use super::*;

fn toml(text: &str) -> toml::Value {
    toml::from_str(text).unwrap()
}

fn uv_spec() -> ProjectInputSpec {
    ProjectInputSpec {
        kind: ProjectInputKind::PyProjectUv,
        manifest_path: std::env::temp_dir().join("sj-no-such-project/pyproject.toml"),
        lockfile_path_override: None,
        js_binding: None,
    }
}

#[test]
fn uv_index_sources_are_accepted_and_code_sources_refused() {
    let index = toml("[project]\nname='a'\n[tool.uv.sources]\ntorch = { index = 'pytorch' }\n");
    assert!(uv_preconditions(&uv_spec(), &index, None).is_ok());
    for source in [
        "x = { git = 'https://github.com/a/b' }",
        "x = { path = '../x' }",
        "x = { url = 'https://e/x.whl' }",
        "x = { workspace = true }",
    ] {
        let pyproject = toml(&format!("[project]\nname='a'\n[tool.uv.sources]\n{source}\n"));
        assert!(uv_preconditions(&uv_spec(), &pyproject, None).is_err(), "{source}");
    }
    let dynamic = toml("[project]\nname='a'\ndynamic = ['dependencies']\n");
    assert!(uv_preconditions(&uv_spec(), &dynamic, None).is_err());
}

#[test]
fn locked_packages_without_wheels_are_listed() {
    let lock = toml(
        "[[package]]\nname='app'\nversion='0.1.0'\nsource={ virtual = '.' }\n\n[[package]]\nname='sdist-only'\nversion='1.0'\nsource={ registry = 'https://pypi.org/simple' }\nsdist={ url='u', hash='sha256:a' }\n\n[[package]]\nname='good'\nversion='2.0'\nwheels=[{ url='w', hash='sha256:b' }]\n",
    );
    let missing = packages_without_wheels(&lock, |package| {
        package.get("source").and_then(|s| s.get("virtual")).is_some()
            || package.get("wheels").is_some()
    });
    assert_eq!(missing, vec!["sdist-only@1.0".to_string()]);
}

#[test]
fn poetry_plugins_are_refused() {
    let spec = ProjectInputSpec {
        kind: ProjectInputKind::PyProjectPoetry,
        ..uv_spec()
    };
    let pyproject = toml("[tool.poetry]\nname='a'\n[tool.poetry.requires-plugins]\npoetry-plugin-x = '1.0'\n");
    let refusal = poetry_preconditions(&spec, &pyproject, Some(&toml(""))).unwrap_err();
    assert!(refusal.contains("plugins"), "{refusal}");
}
