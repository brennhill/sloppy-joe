//! Repository files npm, Yarn, pnpm and Bun read beside a JavaScript project.

use crate::ecosystems::ambient::{AmbientInput as Row, Disposition::*, Scope::*};

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
];
