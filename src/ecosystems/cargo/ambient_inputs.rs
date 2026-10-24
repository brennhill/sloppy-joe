//! Repository files cargo and rustup read beside a Rust project.

use super::*;
use crate::ecosystems::ambient::{AmbientInput as Row, Disposition::*, Scope::*};

pub(super) const AMBIENT: &[Row] = &[
    Row::new(
        ".cargo/config.toml",
        AncestorsToRepoRoot,
        ModeledElsewhere(
            "config_file and cargo_surface (source replacement, patches, programs, env), with config_key_allow",
        ),
    ),
    Row::new(
        ".cargo/config",
        AncestorsToRepoRoot,
        ModeledElsewhere(
            "config_file and cargo_surface (the extensionless name cargo still reads)",
        ),
    ),
    // rustup runs a cargo and rustc from `[toolchain] path` in these files.
    Row::new(
        "rust-toolchain.toml",
        AncestorsToRepoRoot,
        Modeled(program_settings::reject_toolchain_file_path),
    ),
    Row::new(
        "rust-toolchain",
        AncestorsToRepoRoot,
        Modeled(program_settings::reject_toolchain_file_path),
    ),
    Row::new(
        ".cargo/credentials.toml",
        AncestorsToRepoRoot,
        Irrelevant(
            "holds registry tokens only; where a registry is fetched from is set in config.toml",
        ),
    ),
    Row::new(
        ".cargo/credentials",
        AncestorsToRepoRoot,
        Irrelevant(
            "holds registry tokens only; where a registry is fetched from is set in config.toml",
        ),
    ),
    Row::new(
        "build.rs",
        ProjectDir,
        Irrelevant(
            "the project's own build script runs the project's own code, not a fetched package; dependency build scripts are not an ambient input",
        ),
    ),
];
