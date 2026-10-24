//! Config bootstrapping: neutral templates, greenfield configs and repo discovery.
//! Lives above `config` and `parsers` because discovery reads project manifests.
use crate::config::{CanonicalGroupSuggestion, SloppyJoeConfig};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Build the template config used by init.
///
/// This is a manual starting point, not a finished policy for an existing repo.
/// Future onboarding should prefer explicit greenfield presets or a
/// `--from-current` discovery flow over one generic example blob.
pub(crate) fn template_config() -> SloppyJoeConfig {
    SloppyJoeConfig::default()
}

pub(crate) fn render_config_json(config: &SloppyJoeConfig) -> String {
    serde_json::to_string_pretty(config).expect("SloppyJoeConfig should always serialize")
}

pub(crate) fn supported_bootstrap_ecosystems() -> &'static [&'static str] {
    &["npm", "pypi", "cargo", "go", "ruby", "php", "jvm", "dotnet"]
}

pub fn greenfield_config(ecosystem: &str) -> Result<SloppyJoeConfig, String> {
    let mut config = template_config();
    match ecosystem {
        "npm" => {
            config.canonical.insert(
                "npm".to_string(),
                HashMap::from([
                    ("eslint".to_string(), vec!["tslint".to_string()]),
                    ("dayjs".to_string(), vec!["moment".to_string()]),
                ]),
            );
        }
        "pypi" => {
            config.canonical.insert(
                "pypi".to_string(),
                HashMap::from([(
                    "ruff".to_string(),
                    vec![
                        "flake8".to_string(),
                        "pylint".to_string(),
                        "pyflakes".to_string(),
                    ],
                )]),
            );
        }
        "cargo" => {
            config.canonical.insert(
                "cargo".to_string(),
                HashMap::from([
                    (
                        "thiserror".to_string(),
                        vec!["failure".to_string(), "error-chain".to_string()],
                    ),
                    ("clap".to_string(), vec!["structopt".to_string()]),
                ]),
            );
        }
        "go" | "ruby" | "php" | "jvm" | "dotnet" => {
            return Err(format!(
                "Greenfield bootstrap for '{}' is not supported yet. Current greenfield presets exist for: npm, pypi, cargo.",
                ecosystem
            ));
        }
        other => {
            return Err(format!(
                "Unsupported ecosystem '{}'. Expected one of: {}.",
                other,
                supported_bootstrap_ecosystems().join(", ")
            ));
        }
    }

    Ok(config)
}

pub fn greenfield_json(ecosystem: &str) -> Result<String, String> {
    greenfield_config(ecosystem).map(|config| render_config_json(&config))
}

#[derive(Default)]
struct DiscoveryState {
    npm_local_packages: BTreeSet<String>,
    npm_dependency_usage: BTreeSet<String>,
    cargo_local_packages: BTreeSet<String>,
    cargo_external_paths: BTreeSet<String>,
    unsupported_ecosystems: BTreeSet<String>,
    saw_supported_ecosystem: bool,
}

impl DiscoveryState {
    fn into_config(self) -> SloppyJoeConfig {
        let mut config = template_config();

        let npm_internal: Vec<String> = self.npm_local_packages.into_iter().collect();
        if !npm_internal.is_empty() {
            config
                .bootstrap_review
                .suggested_internal
                .insert("npm".to_string(), npm_internal);
        }

        if !self.cargo_local_packages.is_empty() {
            config.bootstrap_review.suggested_internal.insert(
                "cargo".to_string(),
                self.cargo_local_packages.into_iter().collect(),
            );
        }

        if !self.cargo_external_paths.is_empty() {
            config
                .bootstrap_review
                .suggested_trusted_local_paths
                .insert(
                    "cargo".to_string(),
                    self.cargo_external_paths.into_iter().collect(),
                );
        }

        let npm_groups = candidate_canonical_groups(
            &self.npm_dependency_usage,
            &[
                &["dayjs", "moment", "luxon"],
                &["axios", "got", "node-fetch", "superagent"],
                &["eslint", "tslint"],
                &["jest", "vitest", "mocha", "ava"],
            ],
            "Multiple packages from the same solution family are already in use. Review whether one should become canonical.",
        );
        if !npm_groups.is_empty() {
            config
                .bootstrap_review
                .candidate_canonical_groups
                .insert("npm".to_string(), npm_groups);
        }

        config
    }
}

fn candidate_canonical_groups(
    used_packages: &BTreeSet<String>,
    families: &[&[&str]],
    reason: &str,
) -> Vec<CanonicalGroupSuggestion> {
    let mut groups = Vec::new();
    for family in families {
        let packages: Vec<String> = family
            .iter()
            .filter(|package| used_packages.contains(**package))
            .map(|package| (*package).to_string())
            .collect();
        if packages.len() >= 2 {
            groups.push(CanonicalGroupSuggestion {
                packages,
                reason: Some(reason.to_string()),
            });
        }
    }
    groups
}

fn discover_repo_state(
    current_dir: &Path,
    root: &Path,
    visited: &mut BTreeSet<PathBuf>,
    state: &mut DiscoveryState,
) -> Result<(), String> {
    let canonical_current = std::fs::canonicalize(current_dir).map_err(|err| {
        format!(
            "Failed to inspect {} while seeding config from the current repo: {}",
            current_dir.display(),
            err
        )
    })?;

    if !canonical_current.starts_with(root) {
        return Err(format!(
            "Refusing to follow directory '{}' outside the current repo root.",
            current_dir.display()
        ));
    }

    if !visited.insert(canonical_current) {
        return Ok(());
    }

    for entry in sorted_entries(current_dir)? {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "Failed to inspect {} while seeding config from the current repo: {}",
                path.display(),
                err
            )
        })?;

        if !file_type.is_dir() {
            record_manifest(&path, root, state)?;
            continue;
        }
        let skipped = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(is_skipped_directory);
        if !skipped {
            discover_repo_state(&path, root, visited, state)?;
        }
    }

    Ok(())
}

fn sorted_entries(dir: &Path) -> Result<Vec<std::fs::DirEntry>, String> {
    let unreadable = |err: std::io::Error| {
        format!(
            "Failed to inspect {} while seeding config from the current repo: {}",
            dir.display(),
            err
        )
    };
    let mut entries = std::fs::read_dir(dir)
        .map_err(unreadable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(unreadable)?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn is_skipped_directory(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".planning"
            | "node_modules"
            | "target"
            | "vendor"
            | "dist"
            | "build"
            | "third_party"
            | "fixtures"
            | "testdata"
    )
}

/// Ecosystem a manifest file name belongs to when discovery cannot inspect it yet.
fn unsupported_ecosystem_for(path: &Path) -> Option<&'static str> {
    let name = path.file_name().and_then(|name| name.to_str());
    match name {
        Some("pyproject.toml" | "Pipfile" | "setup.py" | "setup.cfg" | "requirements.txt") => {
            Some("pypi")
        }
        Some(name) if name.starts_with("requirements") && name.ends_with(".txt") => Some("pypi"),
        Some("go.mod") => Some("go"),
        Some("Gemfile") => Some("ruby"),
        Some("composer.json") => Some("php"),
        Some("build.gradle" | "build.gradle.kts" | "pom.xml") => Some("jvm"),
        _ if path.extension().is_some_and(|ext| ext == "csproj") => Some("dotnet"),
        _ => None,
    }
}

fn record_manifest(path: &Path, root: &Path, state: &mut DiscoveryState) -> Result<(), String> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("package.json") => {
            state.saw_supported_ecosystem = true;
            inspect_package_json(path, state)
        }
        Some("Cargo.toml") => {
            state.saw_supported_ecosystem = true;
            inspect_cargo_manifest(path, root, state)
        }
        _ => {
            if let Some(ecosystem) = unsupported_ecosystem_for(path) {
                state.unsupported_ecosystems.insert(ecosystem.to_string());
            }
            Ok(())
        }
    }
}

fn inspect_package_json(path: &Path, state: &mut DiscoveryState) -> Result<(), String> {
    let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)
        .map_err(|err| {
            format!(
                "Failed to read {} while seeding config: {}",
                path.display(),
                err
            )
        })?;
    let parsed: serde_json::Value = serde_json::from_str(&content).map_err(|err| {
        format!(
            "Failed to parse {} while seeding config: {}",
            path.display(),
            err
        )
    })?;

    if let Some(name) = parsed.get("name").and_then(|value| value.as_str()) {
        let name = name.trim();
        if !name.is_empty() {
            state.npm_local_packages.insert(name.to_string());
        }
    }

    let deps =
        crate::parsers::package_json::parse_manifest_value(path, &parsed).map_err(|err| {
            format!(
                "Failed to inspect {} while seeding config: {}",
                path.display(),
                err
            )
        })?;
    for dep in deps {
        let observed = dep.actual_name.as_deref().unwrap_or(dep.name.as_str());
        state.npm_dependency_usage.insert(observed.to_string());
    }

    Ok(())
}

fn cargo_package_name(path: &Path) -> Result<Option<String>, String> {
    let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)
        .map_err(|err| {
            format!(
                "Failed to read {} while seeding config: {}",
                path.display(),
                err
            )
        })?;
    let parsed: toml::Value = toml::from_str(&content).map_err(|err| {
        format!(
            "Failed to parse {} while seeding config: {}",
            path.display(),
            err
        )
    })?;
    Ok(parsed
        .get("package")
        .and_then(|value| value.as_table())
        .and_then(|table| table.get("name"))
        .and_then(|value| value.as_str())
        .map(str::to_string))
}

fn inspect_cargo_manifest(
    path: &Path,
    root: &Path,
    state: &mut DiscoveryState,
) -> Result<(), String> {
    if let Some(package_name) = cargo_package_name(path)? {
        state.cargo_local_packages.insert(package_name);
    }

    let manifest = crate::parsers::cargo_toml::parse_manifest_file(path).map_err(|err| {
        format!(
            "Failed to inspect {} while seeding config: {}",
            path.display(),
            err
        )
    })?;
    let project_dir = path.parent().ok_or_else(|| {
        format!(
            "Cargo manifest '{}' has no parent directory.",
            path.display()
        )
    })?;

    for dependency in manifest
        .dependencies
        .iter()
        .chain(manifest.workspace_dependencies.values())
    {
        if let crate::parsers::cargo_toml::CargoSourceSpec::Path(local_path) = &dependency.source {
            let resolved = std::fs::canonicalize(project_dir.join(local_path)).map_err(|err| {
                format!(
                    "Failed to resolve Cargo path dependency '{}' from {} while seeding config: {}",
                    local_path,
                    path.display(),
                    err
                )
            })?;
            if !resolved.starts_with(root) {
                state
                    .cargo_external_paths
                    .insert(resolved.to_string_lossy().to_string());
            }
        }
    }

    Ok(())
}

pub fn discover_current_config(project_dir: &Path) -> Result<SloppyJoeConfig, String> {
    let root = std::fs::canonicalize(project_dir).map_err(|err| {
        format!(
            "Failed to inspect {} while seeding config from the current repo: {}",
            project_dir.display(),
            err
        )
    })?;
    let mut visited = BTreeSet::new();
    let mut state = DiscoveryState::default();
    discover_repo_state(project_dir, &root, &mut visited, &mut state)?;
    if !state.unsupported_ecosystems.is_empty() {
        return Err(format!(
            "`sloppy-joe init --from-current` currently supports only npm and cargo repos. Detected unsupported ecosystems: {}. Support for those ecosystems is not implemented yet.",
            state
                .unsupported_ecosystems
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !state.saw_supported_ecosystem {
        return Err(
            "`sloppy-joe init --from-current` currently supports only npm and cargo repos. No supported manifests were detected.".to_string(),
        );
    }
    Ok(state.into_config())
}

pub fn discover_current_json(project_dir: &Path) -> Result<String, String> {
    discover_current_config(project_dir).map(|config| render_config_json(&config))
}

/// Return a template config as a pretty-printed JSON string.
pub fn template_json() -> String {
    render_config_json(&template_config())
}

/// Print a template config to stdout.
pub fn print_template() {
    println!("{}", template_json());
}

#[cfg(test)]
mod tests;
