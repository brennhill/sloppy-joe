use super::*;
use crate::config_surface::{KNOWN_SURFACES, KeyAllow, resolve_deferred};

fn dir_with(name: &str, content: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-js-surface-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), content).unwrap();
    dir
}

fn allow(file: &str, key: &str) -> KeyAllow {
    KeyAllow {
        file: file.into(),
        key: key.into(),
    }
}

#[test]
fn every_surface_id_is_known() {
    for surface in [&YARNRC, &BUNFIG, &PNPM_WORKSPACE] {
        assert!(KNOWN_SURFACES.contains(&surface.id), "{}", surface.id);
    }
}

#[test]
fn ordinary_yarnrc_settings_pass() {
    let dir = dir_with(
        ".yarnrc.yml",
        "nodeLinker: node-modules\nenableTelemetry: false\nenableImmutableInstalls: true\nchecksumBehavior: throw\n",
    );
    let deferred = check_yarnrc_yml(&dir).unwrap();
    assert!(deferred.is_empty());
}

#[test]
fn yarnrc_redirects_block_now_and_cannot_be_allowed() {
    for text in [
        "npmRegistryServer: https://attacker.example\n",
        "npmScopes:\n  corp:\n    npmRegistryServer: https://attacker.example\n",
        "yarnPath: .yarn/releases/yarn.cjs\n",
        "plugins:\n  - ./plugin.cjs\n",
        "cacheFolder: ./cache\n",
        "enableGlobalCache: false\n",
        "packageExtensions:\n  a@*:\n    dependencies:\n      b: '*'\n",
        "unsafeHttpWhitelist:\n  - evil.example\n",
    ] {
        let dir = dir_with(".yarnrc.yml", text);
        assert!(check_yarnrc_yml(&dir).is_err(), "{text}");
    }
}

#[test]
fn weakening_values_block_even_for_listed_yarnrc_keys() {
    for text in [
        "checksumBehavior: ignore\n",
        "enableImmutableInstalls: false\n",
        "enableScripts: true\n",
    ] {
        let dir = dir_with(".yarnrc.yml", text);
        assert!(check_yarnrc_yml(&dir).is_err(), "{text}");
    }
}

#[test]
fn an_unlisted_yarnrc_key_is_deferred_and_blocks_until_allowed() {
    let dir = dir_with(".yarnrc.yml", "supportedArchitectures:\n  os: [linux]\n");
    let deferred = check_yarnrc_yml(&dir).unwrap();
    assert_eq!(deferred.len(), 1);
    let err = resolve_deferred(&deferred, &[]).unwrap_err().to_string();
    assert!(err.contains("supportedArchitectures.os"), "{err}");
    let applied = resolve_deferred(
        &deferred,
        &[allow(".yarnrc.yml", "supportedArchitectures.os")],
    )
    .unwrap();
    assert_eq!(applied.len(), 1);
}

#[test]
fn a_yarnrc_that_is_not_a_mapping_blocks() {
    let dir = dir_with(".yarnrc.yml", "registry=https://attacker.example\n");
    assert!(check_yarnrc_yml(&dir).is_err());
}

#[test]
fn yaml_aliasing_in_a_settings_file_blocks() {
    let dir = dir_with(
        ".yarnrc.yml",
        "base: &b\n  nodeLinker: pnp\nnodeLinker: *b\n",
    );
    assert!(check_yarnrc_yml(&dir).is_err());
}

#[test]
fn bunfig_install_redirects_block_and_plain_settings_pass() {
    let ok = dir_with(
        "bunfig.toml",
        "[install]\nexact = true\nlinker = \"isolated\"\n",
    );
    assert!(check_bunfig(&ok).unwrap().is_empty());
    for text in [
        "[install]\nregistry = \"https://attacker.example\"\n",
        "[install.scopes]\nmy = \"https://attacker.example\"\n",
        "[install.cache]\ndir = \"./cache\"\n",
        "preload = [\"./evil.ts\"]\n",
        "registry=https://attacker.example\n",
    ] {
        let dir = dir_with("bunfig.toml", text);
        assert!(check_bunfig(&dir).is_err(), "{text}");
    }
    let unknown = dir_with("bunfig.toml", "[install]\nsecurity = true\n");
    let deferred = check_bunfig(&unknown).unwrap();
    assert_eq!(deferred.len(), 1);
    assert!(resolve_deferred(&deferred, &[]).is_err());
    assert!(resolve_deferred(&deferred, &[allow("bunfig.toml", "install.security")]).is_ok());
}

#[test]
fn pnpm_workspace_package_lists_pass_and_rewrites_block() {
    let ok = dir_with(
        "pnpm-workspace.yaml",
        "packages:\n  - 'apps/*'\ncatalog:\n  react: ^18.0.0\nnodeLinker: hoisted\n",
    );
    assert!(check_pnpm_workspace(&ok).unwrap().is_empty());
    for text in [
        "packages: ['a']\noverrides:\n  lodash: 1.0.0\n",
        "packages: ['a']\npatchedDependencies:\n  a@1: p.patch\n",
        "packages: ['a']\nconfigDependencies:\n  x: 1.0.0\n",
        "packages: ['a']\nstoreDir: ./store\n",
        "packages: ['a']\nregistries:\n  default: https://attacker.example\n",
        "packages: ['a']\npackageExtensions:\n  a@*:\n    dependencies:\n      b: '*'\n",
    ] {
        let dir = dir_with("pnpm-workspace.yaml", text);
        assert!(check_pnpm_workspace(&dir).is_err(), "{text}");
    }
    let unknown = dir_with(
        "pnpm-workspace.yaml",
        "packages: ['a']\nminimumReleaseAge: 1440\n",
    );
    let deferred = check_pnpm_workspace(&unknown).unwrap();
    assert_eq!(deferred.len(), 1);
    assert!(resolve_deferred(&deferred, &[]).is_err());
}

fn read_npmrc(text: &str) -> anyhow::Result<crate::npm_config::NpmRegistries> {
    let dir = dir_with(".npmrc", text);
    let mut registries = crate::npm_config::NpmRegistries::default();
    registries.read(&dir.join(".npmrc"))?;
    Ok(registries)
}

#[test]
fn npmrc_flags_pass_and_unlisted_keys_are_deferred() {
    let ok =
        read_npmrc("audit=false\nfund=false\nsave-exact=true\n//host/:_authToken=x\n").unwrap();
    assert!(ok.1.is_empty());
    let unknown = read_npmrc("update-notifier=false\nmessage=hello\n").unwrap();
    assert_eq!(unknown.1.len(), 1);
    assert!(resolve_deferred(&unknown.1, &[]).is_err());
    assert!(resolve_deferred(&unknown.1, &[allow(".npmrc", "message")]).is_ok());
}

#[test]
fn npmrc_cache_trust_and_integrity_settings_block() {
    for text in [
        "cache=./npm-cache\n",
        "prefix=./prefix\n",
        "globalconfig=./c\n",
        "userconfig=./c\n",
        "cafile=./ca.pem\n",
        "proxy=http://p.invalid\n",
        "https-proxy=http://p.invalid\n",
        "store-dir=./store\n",
        "script-shell=./sh\n",
        "strict-ssl=false\n",
        "package-lock=false\n",
    ] {
        assert!(read_npmrc(text).is_err(), "{text}");
    }
}
