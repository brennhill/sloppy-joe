//! `fix-lockfile` for Cargo (docs/specs/fix-lockfile.md): `cargo generate-lockfile` when the
//! lockfile is absent, otherwise `cargo update --workspace`, which keeps every locked version of a
//! non-workspace package and only adds what is missing. Cargo resolves without building, but it
//! runs `rustc -vV` through any configured wrapper, so wrappers are cleared and only a reviewed
//! subset of Cargo configuration reaches the scratch copy.

use super::*;
use crate::ecosystems::fixer::{EnvValue, FixCtx, FixPlan, Problem, Recipe, Refusal, literal_env};
use crate::remedy::{self, Remedy};

/// Cargo configuration tables (and their keys) the fixer copies; anything else is refused.
const CONFIG_ALLOWED: &[(&str, Option<&[&str]>)] = &[
    ("registries", Some(&["index", "protocol"])),
    ("registry", Some(&["default"])),
    ("net", Some(&["retry"])),
    ("term", None),
    ("cargo-new", None),
];

pub(super) fn lockfile_fixer(
    ctx: &FixCtx<'_>,
    spec: &ProjectInputSpec,
    problems: &[Problem],
) -> Result<FixPlan> {
    let problems = fixer::attach_issue_remedies(problems, &remedy::CARGO_UPDATE_WORKSPACE);
    fixer::plan(&problems, |remedy| recipe(ctx, spec, remedy))
}

fn recipe(
    ctx: &FixCtx<'_>,
    spec: &ProjectInputSpec,
    remedy: &'static Remedy,
) -> Result<std::result::Result<Option<Recipe>, Refusal>> {
    if remedy.id != remedy::CARGO_GENERATE_LOCKFILE.id
        && remedy.id != remedy::CARGO_UPDATE_WORKSPACE.id
    {
        return Ok(Ok(None));
    }
    let lockfile =
        authoritative_cargo_lockfile_path(ctx.scan_root, &spec.manifest_path, ctx.config)?;
    let root = lockfile
        .parent()
        .expect("a lockfile has a directory")
        .to_path_buf();
    let configs = match accepted_configs(ctx.scan_root, &root) {
        Ok(configs) => configs,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let manifests = workspace_manifests(ctx, &root, &lockfile)?;
    let existing_lock = std::fs::metadata(&lockfile).is_ok_and(|m| m.len() > 0);
    let (display, args): (&str, &[&str]) = if existing_lock {
        (
            remedy::CARGO_UPDATE_WORKSPACE.command,
            &["update", "--workspace"],
        )
    } else {
        (
            remedy::CARGO_GENERATE_LOCKFILE.command,
            &["generate-lockfile"],
        )
    };
    let mut recipe =
        Recipe::new(display, root.clone()).tool("cargo", (1, 50, 0), "cargo 1.50", args);
    recipe.outputs = vec![lockfile.clone()];
    recipe.placeholders = package_placeholders(&manifests)?;
    recipe.env = cargo_env();
    Ok(Ok(Some(
        recipe
            .inputs_if_present(manifests)
            .inputs_if_present(configs)
            .inputs_if_present([lockfile]),
    )))
}

fn cargo_env() -> Vec<(&'static str, EnvValue)> {
    let mut env = literal_env(&[
        ("RUSTC_WRAPPER", ""),
        ("RUSTC_WORKSPACE_WRAPPER", ""),
        ("CARGO_BUILD_RUSTC_WRAPPER", ""),
        ("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", ""),
        ("CARGO_NET_GIT_FETCH_WITH_CLI", "false"),
        ("CARGO_TERM_COLOR", "never"),
        ("CARGO_TERM_PROGRESS_WHEN", "never"),
    ]);
    env.extend([
        ("CARGO_HOME", EnvValue::ScratchDir("cargo")),
        ("CARGO_TARGET_DIR", EnvValue::ScratchDir("cargo-target")),
        ("RUSTC", EnvValue::TrustedProgram("rustc")),
        ("RUSTUP_HOME", EnvValue::UserPath(".rustup")),
    ]);
    env
}

/// Every Cargo manifest Cargo reads for this lockfile: the root, its workspace members, and the
/// scanned projects bound to the same lockfile (local path dependencies).
fn workspace_manifests(ctx: &FixCtx<'_>, root: &Path, lockfile: &Path) -> Result<Vec<PathBuf>> {
    let root_manifest = root.join("Cargo.toml");
    let mut manifests = vec![root_manifest.clone()];
    if parsers::path_detected(&root_manifest)? {
        let manifest = parsers::cargo_toml::parse_manifest_file(&root_manifest)?;
        let canonical_root = std::fs::canonicalize(root)?;
        for member in workspace::workspace_member_manifests(ctx.scan_root, &manifest)? {
            let relative = member.strip_prefix(&canonical_root).unwrap_or(&member);
            manifests.push(root.join(relative));
        }
    }
    for spec in ctx.specs {
        if spec.kind == ProjectInputKind::Cargo
            && spec.lockfile_path_override.as_deref() == Some(lockfile)
            && !manifests.contains(&spec.manifest_path)
        {
            manifests.push(spec.manifest_path.clone());
        }
    }
    Ok(manifests)
}

/// Cargo refuses a package without a target, and the scratch copy holds no source: an empty
/// `src/lib.rs` (created by the fixer, never copied) satisfies it. Resolution never compiles it.
fn package_placeholders(manifests: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut placeholders = Vec::new();
    for manifest in manifests {
        if !parsers::path_detected(manifest)? {
            continue;
        }
        let value = crate::untrusted::read(
            manifest,
            crate::untrusted::Format::Toml,
            parsers::MAX_MANIFEST_BYTES,
        )?;
        if let crate::untrusted::Untrusted::Toml(value) = value
            && value.get("package").is_some()
        {
            let dir = manifest.parent().expect("a manifest has a directory");
            placeholders.push(dir.join("src/lib.rs"));
        }
    }
    Ok(placeholders)
}

/// The Cargo configuration files between the workspace root and the scan root, each limited to the
/// reviewed keys. Wrappers, build settings, credential providers, aliases, source replacement and
/// git-over-CLI all run or redirect code, so a file with any of them is refused.
fn accepted_configs(scan_root: &Path, root: &Path) -> std::result::Result<Vec<PathBuf>, Refusal> {
    let mut configs = Vec::new();
    let mut dir = Some(root);
    while let Some(current) = dir {
        for name in [".cargo/config.toml", ".cargo/config"] {
            let path = current.join(name);
            if parsers::path_detected(&path).unwrap_or(false) {
                check_config(&path)?;
                configs.push(path);
            }
        }
        if current == scan_root || !current.starts_with(scan_root) {
            break;
        }
        dir = current.parent();
    }
    Ok(configs)
}

fn check_config(path: &Path) -> std::result::Result<(), Refusal> {
    let value = crate::untrusted::read(
        path,
        crate::untrusted::Format::Toml,
        parsers::MAX_MANIFEST_BYTES,
    )
    .map_err(|e| format!("{e:#}"))?;
    let crate::untrusted::Untrusted::Toml(toml::Value::Table(table)) = value else {
        return Err(format!("{} is not a TOML table", path.display()));
    };
    let refuse = |key: &str| {
        Err(format!(
            "{} sets '{}', which can run code or redirect where crates come from",
            path.display(),
            crate::report::sanitize_for_terminal(key)
        ))
    };
    for (key, value) in &table {
        let Some((_, allowed)) = CONFIG_ALLOWED.iter().find(|(name, _)| name == key) else {
            return refuse(key);
        };
        let Some(allowed) = allowed else { continue };
        let nested = |table: &toml::value::Table| {
            table
                .keys()
                .find(|k| !allowed.contains(&k.as_str()))
                .cloned()
        };
        let offending = match (key.as_str(), value.as_table()) {
            ("registries", Some(registries)) => registries
                .values()
                .filter_map(|registry| registry.as_table())
                .find_map(nested),
            (_, Some(table)) => nested(table),
            (_, None) => Some(key.clone()),
        };
        if let Some(offending) = offending {
            return refuse(&format!("{key}.{offending}"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "lock_fixer_tests.rs"]
mod tests;
