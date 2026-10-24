//! Repository files npm, Yarn, pnpm and Bun read beside a JavaScript project.

use crate::ecosystems::ambient::{AmbientInput as Row, Disposition::*, Scope::*};

// Yarn Plug'n'Play: `.pnp.cjs` is generated code that node runs at start-up and that maps package
// names to locations; a committed copy is not checked against the lockfile.
const PNP_WHY: &str = "a committed Plug'n'Play map is executable code that decides where packages load from and is not checked against the lockfile. Fix: do not commit it; let `yarn install` generate it in CI.";

pub(super) const AMBIENT: &[Row] = &[
    Row::new(
        ".npmrc",
        ProjectDir,
        ModeledElsewhere(
            "npm_config and js::config_surfaces (.npmrc allowlist), with config_key_allow",
        ),
    ),
    Row::new(
        ".yarnrc.yml",
        AncestorsToRepoRoot,
        ModeledElsewhere("js::config_surfaces (.yarnrc.yml allowlist), with config_key_allow"),
    ),
    Row::new(
        ".yarnrc",
        ProjectDir,
        Blocked(
            "classic Yarn config can set registries and a yarn-path binary the scan cannot vet",
        ),
    ),
    Row::new(
        ".pnpmfile.*",
        ProjectDir,
        Blocked(
            "a pnpmfile runs code at install and can rewrite any package manifest or lockfile entry",
        ),
    ),
    Row::new(
        "pnpm-workspace.yaml",
        ProjectDir,
        ModeledElsewhere(
            "js::config_surfaces (pnpm-workspace.yaml allowlist), with config_key_allow",
        ),
    ),
    Row::new(
        "bunfig.toml",
        ProjectDir,
        ModeledElsewhere("js::config_surfaces (bunfig.toml allowlist), with config_key_allow"),
    ),
    Row::new(".pnp.cjs", ProjectDir, BlockedIfTracked(PNP_WHY)),
    Row::new(".pnp.loader.mjs", ProjectDir, BlockedIfTracked(PNP_WHY)),
    // Yarn only runs a release or plugin that `.yarnrc.yml` names through `yarnPath` or
    // `plugins`, and both keys are denied by the .yarnrc.yml allowlist.
    Row::new(
        ".yarn/releases/*",
        ProjectDir,
        Irrelevant(
            "Yarn runs a committed release only when .yarnrc.yml sets yarnPath, which the allowlist denies",
        ),
    ),
    Row::new(
        ".yarn/plugins/*",
        ProjectDir,
        Irrelevant(
            "Yarn loads a committed plugin only when .yarnrc.yml lists it under plugins, which the allowlist denies",
        ),
    ),
    // Zero-install archives are checked against the checksums in yarn.lock on every install
    // (`checksumBehavior: ignore` is denied), so a swapped archive fails the install.
    Row::new(
        ".yarn/cache",
        ProjectDir,
        Irrelevant(
            "committed archives are verified against the yarn.lock checksums; weakening that behavior is denied in .yarnrc.yml",
        ),
    ),
];
