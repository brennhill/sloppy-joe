//! Allowlists for the repo-controlled settings files of the JS package managers that are not
//! `.npmrc`: Yarn Berry's `.yarnrc.yml`, Bun's `bunfig.toml` and `pnpm-workspace.yaml`. The files
//! are read while projects are bound to their package manager, before the operator's config is
//! available, so unlisted keys are *deferred* (see `config_surface::resolve_deferred`) and block
//! when the plugin parses the project unless `config_key_allow` lists them (file ids
//! `.yarnrc.yml`, `bunfig.toml`, `pnpm-workspace.yaml`). Classic `.yarnrc` and `.pnpmfile.cjs`
//! stay blocked outright: they are code or an unstructured registry/yarn-path file.
//!
//! Decisions (all three): keys that redirect a registry, relocate a cache/store/home, load a
//! plugin/script/hook, rewrite or extend dependencies, or weaken integrity/TLS are **denied**
//! and cannot be allowed; presentation, linker and install-selection switches are **allowed**.

use crate::config_surface::{
    DeferredKey, Surface, ValueRule::*, check_toml_deferred, check_yaml_deferred, rule,
};
use anyhow::Result;
use std::path::Path;

/// `.yarnrc.yml`: Berry settings.
const YARNRC: Surface = Surface {
    id: ".yarnrc.yml",
    subject: "Yarn setting",
    why: "it redirects a registry, moves the cache, loads a plugin or script, rewrites dependencies or weakens integrity or TLS checks, so the scanned lockfile no longer describes what is installed",
    allow: &[
        rule("nodeLinker", OneOf(&["node-modules", "pnp", "pnpm"])),
        rule("nmMode", Str),
        rule(
            "nmHoistingLimits",
            OneOf(&["none", "workspaces", "dependencies"]),
        ),
        rule("pnpMode", Str),
        rule("enableTelemetry", Bool),
        rule("enableColors", Bool),
        rule("enableHyperlinks", Bool),
        rule("enableInlineBuilds", Bool),
        rule("enableMessageNames", Bool),
        rule("enableProgressBars", Bool),
        rule("enableTimers", Bool),
        rule("enableTransparentWorkspaces", Bool),
        rule("preferInteractive", Bool),
        rule("progressBarStyle", Str),
        rule("defaultSemverRangePrefix", OneOf(&["^", "~", ""])),
        rule("compressionLevel", Any),
        rule("logFilters", Any),
        rule("enableImmutableInstalls", BoolIs(true)),
        rule("checksumBehavior", OneOf(&["throw"])),
        rule("enableScripts", BoolIs(false)),
    ],
    deny: &[
        "npmRegistryServer",
        "npmScopes",
        "npmRegistries",
        "npmAuth",
        "npmAlwaysAuth",
        "yarnPath",
        "plugins",
        "cacheFolder",
        "globalFolder",
        "virtualFolder",
        "installStatePath",
        "pnpDataPath",
        "lockfileFilename",
        "enableGlobalCache",
        "enableMirror",
        "enableNetwork",
        "enableOfflineMode",
        "enableStrictSsl",
        "unsafeHttpWhitelist",
        "httpProxy",
        "httpsProxy",
        "caFilePath",
        "packageExtensions",
        "injectEnvironmentFiles",
        "rcFilename",
    ],
    deny_under: &[],
    scope: &[],
};

/// `bunfig.toml`: Bun settings. Only the install section matters for what gets installed.
const BUNFIG: Surface = Surface {
    id: "bunfig.toml",
    subject: "Bun setting",
    why: "it redirects a registry, moves the cache or global directories, preloads code or changes what is installed, so the scanned lockfile no longer describes what is installed",
    allow: &[
        rule("install.exact", Bool),
        rule("install.dev", Bool),
        rule("install.optional", Bool),
        rule("install.peer", Bool),
        rule("install.production", Bool),
        rule("install.frozenLockfile", Bool),
        rule("install.saveTextLockfile", Bool),
        rule("install.linker", OneOf(&["hoisted", "isolated"])),
        rule("install.lockfile.save", Bool),
        rule("install.lockfile.print", OneOf(&["yarn"])),
        rule("logLevel", OneOf(&["debug", "warn", "error"])),
        rule("telemetry", Bool),
        rule("smol", Bool),
    ],
    deny: &[
        "install.registry",
        "install.scopes",
        "install.cache",
        "install.ca",
        "install.cafile",
        "install.globalDir",
        "install.globalBinDir",
        "install.lockfile.path",
        "install.trustedDependencies",
        "install.auto",
        "preload",
        "run",
    ],
    deny_under: &[],
    scope: &[],
};

/// `pnpm-workspace.yaml`: the workspace package list plus pnpm settings.
const PNPM_WORKSPACE: Surface = Surface {
    id: "pnpm-workspace.yaml",
    subject: "pnpm workspace setting",
    why: "it rewrites or extends dependencies, patches packages, runs hooks, installs configuration dependencies or relocates the store, so the scanned lockfile no longer describes what is installed",
    allow: &[
        rule("packages", Any),
        rule("catalog", Any),
        rule("catalogs", Any),
        rule("nodeLinker", OneOf(&["isolated", "hoisted", "pnp"])),
        rule("shamefullyHoist", Bool),
        rule("hoist", Bool),
        rule("hoistPattern", Any),
        rule("publicHoistPattern", Any),
        rule("autoInstallPeers", Bool),
        rule("strictPeerDependencies", Bool),
        rule("dedupePeerDependents", Bool),
        rule("engineStrict", Bool),
        rule("preferWorkspacePackages", Bool),
        rule("saveWorkspaceProtocol", Any),
        rule("linkWorkspacePackages", Any),
        rule("onlyBuiltDependencies", Any),
        rule("ignoredBuiltDependencies", Any),
        rule("neverBuiltDependencies", Any),
    ],
    deny: &[
        "overrides",
        "packageExtensions",
        "patchedDependencies",
        "configDependencies",
        "registries",
        "registry",
        "storeDir",
        "cacheDir",
        "virtualStoreDir",
        "stateDir",
        "globalDir",
        "pnpmfile",
        "globalPnpmfile",
        "hooks",
        "ignorePnpmfile",
        "strictSsl",
        "ca",
        "cafile",
        "httpProxy",
        "httpsProxy",
    ],
    deny_under: &[],
    scope: &[],
};

fn read_yaml(path: &Path) -> Result<serde_yaml::Value> {
    match crate::untrusted::read(
        path,
        crate::untrusted::Format::Yaml,
        crate::fsutil::MAX_MANIFEST_BYTES,
    )? {
        crate::untrusted::Untrusted::Yaml(value) => Ok(value),
        _ => unreachable!("YAML reads produce YAML"),
    }
}

/// `.yarnrc.yml` in `dir`, if any. Denied settings block now; unlisted ones come back deferred.
pub(super) fn check_yarnrc_yml(dir: &Path) -> Result<Vec<DeferredKey>> {
    let path = dir.join(".yarnrc.yml");
    if !crate::parsers::path_detected(&path)? {
        return Ok(Vec::new());
    }
    check_yaml_deferred(&YARNRC, &read_yaml(&path)?, &path)
}

/// `pnpm-workspace.yaml` in `dir`, if any.
pub(super) fn check_pnpm_workspace(dir: &Path) -> Result<Vec<DeferredKey>> {
    let path = dir.join("pnpm-workspace.yaml");
    if !crate::parsers::path_detected(&path)? {
        return Ok(Vec::new());
    }
    check_yaml_deferred(&PNPM_WORKSPACE, &read_yaml(&path)?, &path)
}

/// `bunfig.toml` in `dir`, if any.
pub(super) fn check_bunfig(dir: &Path) -> Result<Vec<DeferredKey>> {
    let path = dir.join("bunfig.toml");
    if !crate::parsers::path_detected(&path)? {
        return Ok(Vec::new());
    }
    match crate::untrusted::read(
        &path,
        crate::untrusted::Format::Toml,
        crate::fsutil::MAX_MANIFEST_BYTES,
    )? {
        crate::untrusted::Untrusted::Toml(value) => check_toml_deferred(&BUNFIG, &value, &path),
        _ => unreachable!("TOML reads produce TOML"),
    }
}

#[cfg(test)]
mod tests;
