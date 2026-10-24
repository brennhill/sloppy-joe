pub mod cargo_toml;
pub mod composer_json;
pub mod csproj;
pub mod gemfile;
pub mod go_mod;
pub mod jvm;
mod nuget_config;
pub mod package_json;
pub mod pipfile;
pub mod pyproject_toml;
pub mod python_scope;
pub(crate) mod python_version;
pub mod requirements;
pub mod setup_cfg;
pub mod setup_py;

use crate::Dependency;
use anyhow::{Result, bail};
use std::path::Path;

#[cfg(test)]
pub(crate) use crate::fsutil::extract_xml_value;
pub(crate) use crate::fsutil::{
    MAX_MANIFEST_BYTES, read_bytes_limited, read_file_limited, read_line_oriented_limited,
};

pub(crate) fn path_detected(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Auto-detect the project type and parse dependencies, or use the specified type.
pub fn parse_dependencies(
    project_dir: &Path,
    project_type: Option<&str>,
) -> Result<Vec<Dependency>> {
    match project_type {
        Some("npm") => package_json::parse(project_dir),
        Some("pypi") => parse_python_project(project_dir),
        Some("cargo") => cargo_toml::parse(project_dir),
        Some("go") => go_mod::parse(project_dir),
        Some("ruby") => gemfile::parse(project_dir),
        Some("php") => composer_json::parse(project_dir),
        Some("jvm") => jvm::parse(project_dir),
        Some("dotnet") => csproj::parse(project_dir),
        Some(other) => bail!("Unknown project type: {}", other),
        None => auto_detect(project_dir),
    }
}

/// Detect ALL ecosystems present in a project directory.
/// Returns one Vec<Dependency> per detected ecosystem.
/// Used by monorepo scanning to ensure no ecosystem is missed.
pub fn parse_all_ecosystems(project_dir: &Path) -> Result<Vec<Vec<Dependency>>> {
    let mut results = Vec::new();
    let mut errors = Vec::new();
    let root = std::fs::canonicalize(project_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            project_dir.display(),
            err
        )
    })?;
    let mut visited = std::collections::HashSet::new();
    parse_all_ecosystems_inner(
        project_dir,
        &root,
        &mut visited,
        &mut results,
        &mut errors,
        false,
    )?;

    if !errors.is_empty() {
        bail!("Broken manifest(s) detected:\n  {}", errors.join("\n  "));
    }

    Ok(results)
}

fn parse_all_ecosystems_inner(
    current_dir: &Path,
    root: &Path,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    results: &mut Vec<Vec<Dependency>>,
    errors: &mut Vec<String>,
    inside_node_modules: bool,
) -> Result<()> {
    let canonical_current = std::fs::canonicalize(current_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            current_dir.display(),
            err
        )
    })?;
    if !canonical_current.starts_with(root) {
        bail!(
            "Refusing to follow symlinked directory '{}' outside the scan root.",
            current_dir.display()
        );
    }
    if !visited.insert(canonical_current) {
        return Ok(());
    }

    parse_directory_manifests(current_dir, inside_node_modules, results, errors)?;

    let inspect_error = |err: std::io::Error| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            current_dir.display(),
            err
        )
    };
    let mut entries: Vec<_> = std::fs::read_dir(current_dir)
        .map_err(inspect_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(inspect_error)?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        if let Some((path, nested_in_node_modules)) =
            child_directory(&entry, root, inside_node_modules)?
        {
            parse_all_ecosystems_inner(
                &path,
                root,
                visited,
                results,
                errors,
                nested_in_node_modules,
            )?;
        }
    }

    Ok(())
}

/// Record a manifest parse outcome: dependencies are kept, failures are collected with their path.
fn record_parse(
    path: &Path,
    parsed: Result<Vec<Dependency>>,
    results: &mut Vec<Vec<Dependency>>,
    errors: &mut Vec<String>,
) {
    match parsed {
        Ok(deps) if !deps.is_empty() => results.push(deps),
        Ok(_) => {}
        Err(err) => errors.push(format!("{}: {}", path.display(), err)),
    }
}

/// Parse every manifest kind present directly in `current_dir`.
fn parse_directory_manifests(
    current_dir: &Path,
    inside_node_modules: bool,
    results: &mut Vec<Vec<Dependency>>,
    errors: &mut Vec<String>,
) -> Result<()> {
    type Parser = (&'static str, fn(&Path) -> Result<Vec<Dependency>>);
    let parsers: Vec<Parser> = if inside_node_modules {
        if has_npm_lockfile(current_dir) {
            vec![("package.json", package_json::parse)]
        } else {
            Vec::new()
        }
    } else {
        vec![
            ("package.json", package_json::parse),
            ("Cargo.toml", cargo_toml::parse),
            ("go.mod", go_mod::parse),
            ("Gemfile", gemfile::parse),
            ("composer.json", composer_json::parse),
        ]
    };

    for (manifest, parser) in parsers {
        let path = current_dir.join(manifest);
        if path_detected(&path)? {
            record_parse(&path, parser(current_dir), results, errors);
        }
    }

    if let Some(path) = first_python_manifest(current_dir)? {
        record_parse(&path, parse_python_project(current_dir), results, errors);
    }

    let jvm_manifest = ["build.gradle", "build.gradle.kts", "pom.xml"]
        .iter()
        .map(|name| current_dir.join(name))
        .find_map(|path| match path_detected(&path) {
            Ok(true) => Some(Ok(path)),
            Ok(false) => None,
            Err(err) => Some(Err(err)),
        })
        .transpose()?;
    if let Some(path) = jvm_manifest {
        record_parse(&path, jvm::parse(current_dir), results, errors);
    }
    if let Some(path) = first_csproj(current_dir)? {
        record_parse(&path, csproj::parse(current_dir), results, errors);
    }
    Ok(())
}

/// Directory to descend into for `entry` (real or symlinked), with whether it sits in `node_modules`.
fn child_directory(
    entry: &std::fs::DirEntry,
    root: &Path,
    inside_node_modules: bool,
) -> Result<Option<(std::path::PathBuf, bool)>> {
    let name = entry.file_name();
    let path = entry.path();
    let file_type = entry.file_type()?;
    if file_type.is_dir() {
        if name.to_str() == Some(".git") {
            return Ok(None);
        }
        let nested = inside_node_modules || name.to_str() == Some("node_modules");
        return Ok(Some((path, nested)));
    }
    if !file_type.is_symlink() {
        return Ok(None);
    }
    let target = std::fs::canonicalize(&path).map_err(|err| {
        anyhow::anyhow!(
            "Failed to resolve symlinked path '{}': {}",
            path.display(),
            err
        )
    })?;
    if !target.is_dir() {
        return Ok(None);
    }
    if !target.starts_with(root) {
        bail!(
            "Refusing to follow symlinked directory '{}' outside the scan root.",
            path.display()
        );
    }
    let nested = inside_node_modules
        || target
            .strip_prefix(root)
            .ok()
            .is_some_and(|relative| relative.components().any(ignored_directory_component));
    Ok(Some((path, nested)))
}

fn ignored_directory_name(name: &std::ffi::OsStr) -> bool {
    matches!(name.to_str(), Some("node_modules"))
}

fn ignored_directory_component(component: std::path::Component<'_>) -> bool {
    match component {
        std::path::Component::Normal(name) => ignored_directory_name(name),
        _ => false,
    }
}

fn has_npm_lockfile(dir: &Path) -> bool {
    ["npm-shrinkwrap.json", "package-lock.json"]
        .iter()
        .any(|name| path_detected(&dir.join(name)).unwrap_or(false))
}

fn auto_detect(project_dir: &Path) -> Result<Vec<Dependency>> {
    if path_detected(&project_dir.join("package.json"))? {
        return package_json::parse(project_dir);
    }
    if first_python_manifest(project_dir)?.is_some() {
        return parse_python_project(project_dir);
    }
    if path_detected(&project_dir.join("Cargo.toml"))? {
        return cargo_toml::parse(project_dir);
    }
    if path_detected(&project_dir.join("go.mod"))? {
        return go_mod::parse(project_dir);
    }
    if path_detected(&project_dir.join("Gemfile"))? {
        return gemfile::parse(project_dir);
    }
    if path_detected(&project_dir.join("composer.json"))? {
        return composer_json::parse(project_dir);
    }
    if path_detected(&project_dir.join("build.gradle"))?
        || path_detected(&project_dir.join("build.gradle.kts"))?
        || path_detected(&project_dir.join("pom.xml"))?
    {
        return jvm::parse(project_dir);
    }
    if first_csproj(project_dir)?.is_some() {
        return csproj::parse(project_dir);
    }
    bail!(
        "Could not detect project type. Use --type to specify one of: \
         npm, pypi, cargo, go, ruby, php, jvm, dotnet"
    );
}

fn first_csproj(dir: &Path) -> Result<Option<std::path::PathBuf>> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .find(|path| {
                    csproj::is_project_file(path)
                        || path.file_name() == Some("packages.config".as_ref())
                })
        })
        .map_err(Into::into)
}

fn parse_python_project(project_dir: &Path) -> Result<Vec<Dependency>> {
    if path_detected(&project_dir.join("pyproject.toml"))? {
        return match pyproject_toml::classify_manifest(&project_dir.join("pyproject.toml"))? {
            pyproject_toml::PyprojectKind::Poetry => pyproject_toml::parse_poetry(project_dir),
            pyproject_toml::PyprojectKind::Uv => pyproject_toml::parse_legacy(project_dir),
            pyproject_toml::PyprojectKind::Legacy => pyproject_toml::parse_legacy(project_dir),
        };
    }
    if let Some(path) = first_requirements_file(project_dir)? {
        return requirements::parse_file(&path, project_dir);
    }
    if path_detected(&project_dir.join("Pipfile"))? {
        return pipfile::parse(project_dir);
    }
    if path_detected(&project_dir.join("setup.cfg"))? {
        return setup_cfg::parse(project_dir);
    }
    if path_detected(&project_dir.join("setup.py"))? {
        return setup_py::parse(project_dir);
    }
    bail!(
        "Could not detect Python project manifest in {}",
        project_dir.display()
    );
}

fn first_python_manifest(dir: &Path) -> Result<Option<std::path::PathBuf>> {
    if path_detected(&dir.join("pyproject.toml"))? {
        return Ok(Some(dir.join("pyproject.toml")));
    }
    if let Some(path) = first_requirements_file(dir)? {
        return Ok(Some(path));
    }
    for manifest in ["Pipfile", "setup.cfg", "setup.py"] {
        let path = dir.join(manifest);
        if path_detected(&path)? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

pub(crate) fn first_requirements_file(dir: &Path) -> Result<Option<std::path::PathBuf>> {
    let mut candidates = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name == "requirements.txt"
                        || (name.starts_with("requirements") && name.ends_with(".txt"))
                })
        })
        .collect::<Vec<_>>();
    candidates.sort();
    if candidates.is_empty() {
        return Ok(None);
    }
    if let Some(primary) = candidates
        .iter()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some("requirements.txt"))
    {
        return Ok(Some(primary.clone()));
    }
    if candidates.len() == 1 {
        return Ok(candidates.into_iter().next());
    }

    anyhow::bail!(
        "Ambiguous Python requirements manifests in {}: found {} but no requirements.txt. Fix: rename the primary file to requirements.txt or scan an explicit manifest.",
        dir.display(),
        candidates
            .iter()
            .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub(crate) fn validate_dependency(dep: &Dependency, source_path: &Path) -> Result<()> {
    if !dep.ecosystem.supports_package_name_length(&dep.name) {
        bail!(
            "Scan not supported: oversized package name in {}",
            source_path.display()
        );
    }
    let escaped_name: String = dep
        .name
        .chars()
        .flat_map(|ch| ch.escape_default())
        .collect();

    if !crate::ecosystem::validate_package_name(&dep.name) {
        bail!(
            "invalid package name '{}' in {}",
            escaped_name,
            source_path.display()
        );
    }

    if !crate::ecosystem::validate_package_name_for_ecosystem(&dep.name, dep.ecosystem) {
        bail!(
            "invalid package name '{}' in {}: unexpected shape for {}",
            escaped_name,
            source_path.display(),
            dep.ecosystem
        );
    }

    Ok(())
}

/// Shared test utilities for parser tests.
#[cfg(test)]
pub(crate) mod test_utils {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a unique temp directory and write a manifest file into it.
    pub fn setup_test_dir(prefix: &str, filename: &str, content: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-{}-{}-{}", prefix, std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(filename), content).unwrap();
        dir
    }

    /// Create a unique temp directory without writing any file.
    pub fn empty_test_dir(prefix: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-{}-{}-{}", prefix, std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Clean up a test directory.
    pub fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod tests;
