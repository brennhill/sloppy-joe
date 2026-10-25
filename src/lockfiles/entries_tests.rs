use super::*;

#[test]
fn npm_v3_packages_carry_integrity_and_resolved() {
    let lock: serde_json::Value = serde_json::from_str(
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},
        "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-a"},
        "node_modules/a/node_modules/@s/b":{"version":"2.0.0","integrity":"sha512-b"},
        "node_modules/ws":{"link":true,"resolved":"packages/ws"}}}"#,
    )
    .unwrap();
    let packages = npm_packages(&lock);
    assert_eq!(packages.len(), 2, "{packages:?}");
    assert!(packages.contains(&LockedPackage {
        name: "left-pad".into(),
        version: "1.3.0".into(),
        integrity: Some("sha512-a".into()),
        source: Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into()),
    }));
    assert!(packages.iter().any(|p| p.name == "@s/b" && p.version == "2.0.0"));
}

#[test]
fn npm_v1_packages_walk_nested_dependencies_and_aliases() {
    let lock: serde_json::Value = serde_json::from_str(
        r#"{"dependencies":{"a":{"version":"1.0.0","integrity":"sha1-x","dependencies":{"b":{"version":"2.0.0"}}},
        "alias":{"version":"npm:real@3.0.0"}}}"#,
    )
    .unwrap();
    let mut out = Vec::new();
    npm_v1_packages(lock["dependencies"].as_object().unwrap(), &mut out);
    let ids: Vec<_> = out.iter().map(|p| format!("{}@{}", p.name, p.version)).collect();
    assert!(ids.contains(&"a@1.0.0".to_string()), "{ids:?}");
    assert!(ids.contains(&"b@2.0.0".to_string()), "{ids:?}");
    assert!(ids.contains(&"real@3.0.0".to_string()), "{ids:?}");
}

#[test]
fn legacy_pnpm_keys_of_every_format_split_into_name_and_version() {
    assert_eq!(
        legacy_pnpm_key("/left-pad/1.3.0"),
        Some(("left-pad".into(), "1.3.0".into()))
    );
    assert_eq!(
        legacy_pnpm_key("/@scope/pkg/1.0.0_react@18.0.0"),
        Some(("@scope/pkg".into(), "1.0.0".into()))
    );
    assert_eq!(
        legacy_pnpm_key("/@scope/pkg@1.0.0(react@18.0.0)"),
        Some(("@scope/pkg".into(), "1.0.0".into()))
    );
    assert_eq!(
        legacy_pnpm_key("left-pad@1.3.0"),
        Some(("left-pad".into(), "1.3.0".into()))
    );
    assert_eq!(legacy_pnpm_key("/"), None);
}

#[test]
fn legacy_pnpm_packages_read_a_6_0_lockfile() {
    let content = "lockfileVersion: '6.0'\npackages:\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-a}\n  /@s/b@2.0.0:\n    resolution: {integrity: sha512-b}\n";
    let packages = pnpm_legacy_packages(content).unwrap();
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].name, "@s/b");
    assert_eq!(packages[1].integrity.as_deref(), Some("sha512-a"));
}

#[test]
fn legacy_pnpm_packages_refuse_an_unknown_key() {
    let content = "lockfileVersion: '6.0'\npackages:\n  nonsense:\n    resolution: {integrity: sha512-a}\n";
    assert!(pnpm_legacy_packages(content).is_err());
}

#[test]
fn cargo_packages_read_checksum_and_source() {
    let lock: toml::Value = toml::from_str(
        "version = 4\n[[package]]\nname = \"itoa\"\nversion = \"1.0.10\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc\"\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let packages = cargo_packages(&lock);
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].integrity.as_deref(), Some("abc"));
    assert_eq!(packages[1].source, None);
}

#[test]
fn uv_and_poetry_names_are_normalized_and_hashes_sorted() {
    let uv: toml::Value = toml::from_str(
        "version = 1\n[[package]]\nname = \"Typing_Extensions\"\nversion = \"4.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"u\", hash = \"sha256:b\" }\nwheels = [{ url = \"w\", hash = \"sha256:a\" }]\n",
    )
    .unwrap();
    let packages = uv_packages(&uv);
    assert_eq!(packages[0].name, "typing-extensions");
    assert_eq!(packages[0].integrity.as_deref(), Some("sha256:a,sha256:b"));
    let poetry: toml::Value = toml::from_str(
        "[[package]]\nname = \"Requests\"\nversion = \"2.0.0\"\nfiles = [{file = \"r.whl\", hash = \"sha256:z\"}]\n",
    )
    .unwrap();
    assert_eq!(poetry_packages(&poetry)[0].name, "requests");
}

#[test]
fn composer_packages_join_dist_and_source() {
    let lock: serde_json::Value = serde_json::from_str(
        r#"{"packages":[{"name":"a/b","version":"1.0.0","dist":{"url":"https://x/a.zip","shasum":"s","reference":"r"}}],"packages-dev":[{"name":"c/d","version":"2.0.0","source":{"url":"https://g/c.git","reference":"q"}}]}"#,
    )
    .unwrap();
    let packages = composer_packages(&lock);
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].integrity.as_deref(), Some("r,s"));
    assert_eq!(packages[1].source.as_deref(), Some("https://g/c.git"));
}
