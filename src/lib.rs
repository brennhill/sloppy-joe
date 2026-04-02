#![forbid(unsafe_code)]

pub mod cache;
pub mod checks;
pub mod ecosystem;
pub use ecosystem::Ecosystem;
pub mod config;
pub(crate) mod lockfiles;
pub mod parsers;
pub mod registry;
pub mod report;
mod version;

use anyhow::Result;
use checks::malicious::OsvClient;
use registry::Registry;
use report::{Issue, ScanReport, Severity};

/// Run all checks on the detected or specified project type.
///
/// `config_path` must point to a file outside the project directory.
/// If None, only existence and similarity checks run (no canonical check).
///
/// Three tiers of packages:
/// - **internal**: skip ALL checks (your org's packages, change constantly)
/// - **allowed**: skip existence + similarity, still subject to canonical + age gate
/// - **everything else**: full checks
///
/// Run all checks, loading config from a file path or URL.
/// Prefer this over `scan()` — it supports `--config https://...`.
pub async fn scan_with_source(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    deep: bool,
) -> Result<ScanReport> {
    scan_with_source_full(
        project_dir,
        project_type,
        config_source,
        deep,
        false,
        false,
        None,
    )
    .await
}

/// Warm the cache by running a full scan without the manifest hash skip.
/// Returns the report so callers can show how many packages were indexed.
pub async fn warm_cache(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    deep: bool,
    paranoid: bool,
    cache_dir: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let config = config::load_config_from_source(config_source, Some(project_dir))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let opts = ScanOptions {
        deep,
        paranoid,
        no_cache: false,
        cache_dir,
        disable_osv_disk_cache: false,
        skip_hash_check: true,
        review_exceptions: false,
    };
    scan_with_config(project_dir, project_type, config, &opts).await
}

pub async fn scan_with_source_full(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    deep: bool,
    paranoid: bool,
    no_cache: bool,
    cache_dir: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let opts = ScanOptions {
        deep,
        paranoid,
        no_cache,
        cache_dir,
        disable_osv_disk_cache: false,
        skip_hash_check: false,
        review_exceptions: false,
    };
    scan_with_source_full_options(project_dir, project_type, config_source, &opts).await
}

pub async fn scan_with_source_full_options(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    let config = config::load_config_from_source(config_source, Some(project_dir))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    scan_with_config(project_dir, project_type, config, opts).await
}

pub async fn scan(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_path: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let config = config::load_config_with_project(config_path, Some(project_dir))
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    scan_with_config(project_dir, project_type, config, &ScanOptions::default()).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectInputKind {
    Npm,
    PyProjectPoetry,
    PyRequirements,
    PyProjectLegacy,
    PyPipfile,
    PySetupPy,
    PySetupCfg,
    Cargo,
    Go,
    Ruby,
    Php,
    Gradle,
    Maven,
    Dotnet,
}

#[derive(Clone, Debug)]
struct ProjectInputSpec {
    kind: ProjectInputKind,
    manifest_path: std::path::PathBuf,
}

#[derive(Clone, Debug)]
struct ParsedProject {
    spec: ProjectInputSpec,
    deps: Vec<Dependency>,
}

impl ProjectInputSpec {
    fn project_dir(&self) -> &std::path::Path {
        self.manifest_path
            .parent()
            .expect("manifest paths should always have a parent directory")
    }
}

impl ProjectInputKind {
    fn is_python(self) -> bool {
        matches!(
            self,
            Self::PyProjectPoetry
                | Self::PyRequirements
                | Self::PyProjectLegacy
                | Self::PyPipfile
                | Self::PySetupPy
                | Self::PySetupCfg
        )
    }

    fn is_legacy_python(self) -> bool {
        matches!(
            self,
            Self::PyRequirements
                | Self::PyProjectLegacy
                | Self::PyPipfile
                | Self::PySetupPy
                | Self::PySetupCfg
        )
    }

    fn manifest_label(self) -> &'static str {
        match self {
            Self::Npm => "package.json",
            Self::PyProjectPoetry | Self::PyProjectLegacy => "pyproject.toml",
            Self::PyRequirements => "requirements*.txt",
            Self::PyPipfile => "Pipfile",
            Self::PySetupPy => "setup.py",
            Self::PySetupCfg => "setup.cfg",
            Self::Cargo => "Cargo.toml",
            Self::Go => "go.mod",
            Self::Ruby => "Gemfile",
            Self::Php => "composer.json",
            Self::Gradle => "build.gradle or build.gradle.kts",
            Self::Maven => "pom.xml",
            Self::Dotnet => "*.csproj",
        }
    }

    fn missing_lockfile_help(&self) -> Option<&'static str> {
        match self {
            Self::Npm => Some(
                "Run `npm install --package-lock-only` or `npm shrinkwrap`, then commit the lockfile.",
            ),
            Self::Cargo => Some("Run `cargo generate-lockfile` and commit Cargo.lock."),
            Self::Go => Some("Run `go mod tidy` so Go records dependency checksums in go.sum."),
            Self::Ruby => Some("Run `bundle lock` or `bundle install`, then commit Gemfile.lock."),
            Self::Php => {
                Some("Run `composer update` or `composer install`, then commit composer.lock.")
            }
            Self::Gradle => Some(
                "Enable Gradle dependency locking and run `./gradlew dependencies --write-locks`, then commit gradle.lockfile.",
            ),
            Self::Dotnet => {
                Some("Run `dotnet restore --use-lock-file` and commit packages.lock.json.")
            }
            Self::PyProjectPoetry => {
                Some("Run `poetry lock` and commit poetry.lock alongside pyproject.toml.")
            }
            Self::PyRequirements
            | Self::PyProjectLegacy
            | Self::PyPipfile
            | Self::PySetupPy
            | Self::PySetupCfg
            | Self::Maven => None,
        }
    }
}

#[cfg(test)]
fn preflight_scan_inputs(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
) -> Result<Vec<Issue>> {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(project_dir, project_type, &config)?;
    preflight_project_inputs(project_dir, &specs, &config)
}

fn preflight_project_inputs(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Issue>> {
    let canonical_root = std::fs::canonicalize(scan_root).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            scan_root.display(),
            err
        )
    })?;
    let npm_manifests = load_npm_manifests(specs)?;
    let npm_index = index_npm_projects(&npm_manifests)?;
    let mut warnings = Vec::new();

    for spec in specs {
        let manifest_content =
            parsers::read_file_limited(&spec.manifest_path, parsers::MAX_MANIFEST_BYTES).map_err(
                |err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                },
            )?;

        match spec.kind {
            ProjectInputKind::PyProjectPoetry => {
                parsers::pyproject_toml::parse_poetry_file(&spec.manifest_path).map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
            }
            ProjectInputKind::PyRequirements => {
                parsers::requirements::parse_file(&spec.manifest_path, scan_root).map_err(
                    |err| {
                        anyhow::anyhow!(
                            "Broken manifest '{}': {}",
                            spec.manifest_path.display(),
                            err
                        )
                    },
                )?;
            }
            ProjectInputKind::PyProjectLegacy => {
                parsers::pyproject_toml::parse_legacy_file(&spec.manifest_path).map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
            }
            ProjectInputKind::PyPipfile => {
                parsers::pipfile::parse_file(&spec.manifest_path).map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
            }
            ProjectInputKind::PySetupPy => {
                parsers::setup_py::parse_file(&spec.manifest_path).map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
            }
            ProjectInputKind::PySetupCfg => {
                parsers::setup_cfg::parse_file(&spec.manifest_path).map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
            }
            ProjectInputKind::Gradle | ProjectInputKind::Maven => {
                parsers::jvm::validate_manifest(&spec.manifest_path).map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
            }
            ProjectInputKind::Dotnet => {
                parsers::csproj::parse_file(&spec.manifest_path).map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
            }
            _ => {}
        }

        match spec.kind {
            ProjectInputKind::Npm => ensure_one_lockfile_readable(
                spec.project_dir(),
                &["npm-shrinkwrap.json", "package-lock.json"],
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::PyProjectPoetry => ensure_lockfile_readable(
                &spec.project_dir().join("poetry.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::PyRequirements
            | ProjectInputKind::PyProjectLegacy
            | ProjectInputKind::PyPipfile
            | ProjectInputKind::PySetupPy
            | ProjectInputKind::PySetupCfg => {
                if config.python_enforcement == config::PythonEnforcement::PoetryOnly {
                    anyhow::bail!(
                        "Legacy Python manifest '{}' is not allowed in poetry_only mode. Migrate this project to Poetry with pyproject.toml + poetry.lock, or relax python_enforcement to prefer_poetry.",
                        spec.manifest_path.display()
                    );
                }
                warnings.push(python_legacy_warning(spec));
            }
            ProjectInputKind::Cargo => ensure_lockfile_readable(
                &spec.project_dir().join("Cargo.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Go => {
                if parsers::go_mod::requires_go_sum(&manifest_content) {
                    ensure_lockfile_readable(
                        &spec.project_dir().join("go.sum"),
                        spec.kind.missing_lockfile_help().unwrap(),
                    )?;
                }
            }
            ProjectInputKind::Ruby => ensure_lockfile_readable(
                &spec.project_dir().join("Gemfile.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Php => ensure_lockfile_readable(
                &spec.project_dir().join("composer.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Gradle => ensure_lockfile_readable(
                &spec.project_dir().join("gradle.lockfile"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Dotnet => ensure_lockfile_readable(
                &spec.manifest_path.with_file_name("packages.lock.json"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Maven => warnings.push(
                Issue::new(
                    "<lockfile>",
                    checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE,
                    Severity::Warning,
                )
                .message(format!(
                    "Maven manifest '{}' has no trusted lockfile-backed verification path in sloppy-joe. Resolution-sensitive checks continue with reduced confidence. Gradle dependency locking via gradle.lockfile is recommended when practical.",
                    spec.manifest_path.display()
                ))
                .fix(
                    "Keep Maven and review resolution-sensitive findings manually, or move the build to Gradle with dependency locking if you need strict lockfile enforcement.",
                ),
            ),
        }

        if spec.kind == ProjectInputKind::PyProjectPoetry {
            warnings.extend(poetry_preference_warnings(spec)?);
        }

        let npm_manifest = npm_manifests.get(&spec.manifest_path);
        if spec.kind == ProjectInputKind::Npm {
            let manifest = npm_manifest.expect("npm manifests should be parsed during preflight");
            validate_npm_package_manager_policy(&canonical_root, spec, manifest)?;
            validate_npm_manifest_security_policy(spec, manifest)?;
        }
        validate_lockfile_syntax(spec, npm_manifest, config)?;

        if spec.kind == ProjectInputKind::Npm {
            let manifest = npm_manifest.expect("npm manifests should be parsed during preflight");
            validate_local_npm_dependencies(&canonical_root, spec, manifest, &npm_index)?;
        }
    }

    Ok(warnings)
}

fn python_legacy_warning(spec: &ProjectInputSpec) -> Issue {
    Issue::new(
        spec.manifest_path.display().to_string(),
        checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST,
        Severity::Warning,
    )
    .message(format!(
        "Python manifest '{}' uses the legacy {} workflow. sloppy-joe will scan it, but Poetry with pyproject.toml + poetry.lock is the trusted Python path and provides stronger lockfile-backed assurance.",
        spec.manifest_path.display(),
        spec.kind.manifest_label()
    ))
    .fix("Migrate this project to Poetry and commit poetry.lock. Legacy Python manifests remain allowed, but every run will warn until the project moves to the trusted Poetry workflow.")
}

fn poetry_preference_warnings(spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
    let mut warnings = Vec::new();
    for candidate in legacy_python_manifest_paths(spec.project_dir())? {
        warnings.push(
            Issue::new(
                candidate.display().to_string(),
                checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST,
                Severity::Warning,
            )
            .message(format!(
                "Ignoring legacy Python manifest '{}' because '{}' is a Poetry project. sloppy-joe prefers Poetry as the trusted source of truth for this directory.",
                candidate.display(),
                spec.manifest_path.display()
            ))
            .fix(
                "Remove or stop relying on the legacy Python manifest, and keep pyproject.toml + poetry.lock as the single trusted dependency source for this project.",
            ),
        );
    }
    Ok(warnings)
}

fn read_npm_manifest_value(path: &std::path::Path) -> Result<serde_json::Value> {
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken manifest '{}': failed to parse JSON: {}",
            path.display(),
            err
        )
    })
}

fn load_npm_manifests(
    specs: &[ProjectInputSpec],
) -> Result<std::collections::HashMap<std::path::PathBuf, serde_json::Value>> {
    let mut manifests = std::collections::HashMap::new();
    for spec in specs {
        if spec.kind == ProjectInputKind::Npm {
            manifests.insert(
                spec.manifest_path.clone(),
                read_npm_manifest_value(&spec.manifest_path)?,
            );
        }
    }
    Ok(manifests)
}

#[derive(Default)]
struct NpmProjectIndex {
    dirs: std::collections::HashSet<std::path::PathBuf>,
    by_name: std::collections::HashMap<String, std::collections::HashSet<std::path::PathBuf>>,
}

fn index_npm_projects(
    manifests: &std::collections::HashMap<std::path::PathBuf, serde_json::Value>,
) -> Result<NpmProjectIndex> {
    let mut index = NpmProjectIndex::default();
    for (manifest_path, manifest) in manifests {
        let project_dir = std::fs::canonicalize(
            manifest_path
                .parent()
                .expect("manifest paths should always have a parent directory"),
        )
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", manifest_path.display(), err))?;
        index.dirs.insert(project_dir.clone());
        if let Some(name) = manifest.get("name").and_then(|value| value.as_str()) {
            index
                .by_name
                .entry(name.to_string())
                .or_default()
                .insert(project_dir);
        }
    }
    Ok(index)
}

fn validate_local_npm_dependencies(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    npm_index: &NpmProjectIndex,
) -> Result<()> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;

    for (name, local_spec) in npm_dependency_entries(manifest)
        .into_iter()
        .filter(|(_, spec)| {
            spec.starts_with("workspace:") || spec.starts_with("file:") || spec.starts_with("link:")
        })
    {
        if local_spec.starts_with("workspace:") {
            validate_workspace_npm_dependency(
                scan_root,
                spec,
                &name,
                &canonical_project_dir,
                npm_index,
            )?;
            continue;
        }

        let canonical_target =
            resolve_local_npm_target(scan_root, spec, &name, &local_spec, &canonical_project_dir)?;
        if !npm_index.dirs.contains(&canonical_target) {
            anyhow::bail!(
                "Local npm dependency '{}' in '{}' resolves to '{}' inside the scan root, but no scanned npm project was found there.",
                name,
                spec.manifest_path.display(),
                local_spec
            );
        }
    }

    Ok(())
}

fn resolve_local_npm_target(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    local_spec: &str,
    canonical_project_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let raw_target = local_spec
        .strip_prefix("file:")
        .or_else(|| local_spec.strip_prefix("link:"))
        .unwrap_or("")
        .trim();
    if raw_target.is_empty() {
        anyhow::bail!(
            "Local npm dependency '{}' in '{}' has an empty target.",
            dep_name,
            spec.manifest_path.display()
        );
    }

    let candidate = if std::path::Path::new(raw_target).is_absolute() {
        std::path::PathBuf::from(raw_target)
    } else {
        canonical_project_dir.join(raw_target)
    };
    let normalized = normalize_filesystem_path(&candidate);
    let canonical_root = std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))?;

    let canonical_target = match std::fs::canonicalize(&normalized) {
        Ok(path) => path,
        Err(err) => {
            if !normalized.starts_with(&canonical_root) {
                anyhow::bail!(
                    "Local npm dependency '{}' in '{}' resolves outside the scan root via '{}'.",
                    dep_name,
                    spec.manifest_path.display(),
                    local_spec
                );
            }
            anyhow::bail!(
                "Local npm dependency '{}' in '{}' points to '{}' but that target is missing or unreadable: {}.",
                dep_name,
                spec.manifest_path.display(),
                raw_target,
                err
            );
        }
    };

    if !canonical_target.starts_with(&canonical_root) {
        anyhow::bail!(
            "Local npm dependency '{}' in '{}' resolves outside the scan root via '{}'.",
            dep_name,
            spec.manifest_path.display(),
            local_spec
        );
    }
    if !canonical_target.is_dir() {
        anyhow::bail!(
            "Local npm dependency '{}' in '{}' points to '{}' which is not a project directory.",
            dep_name,
            spec.manifest_path.display(),
            raw_target
        );
    }

    Ok(canonical_target)
}

fn normalize_filesystem_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut normalized = std::path::PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                normalized.push(component.as_os_str())
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

fn ancestor_dirs_inclusive(
    start: &std::path::Path,
    root: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>> {
    if !start.starts_with(root) {
        anyhow::bail!(
            "Path '{}' is outside scan root '{}'.",
            start.display(),
            root.display()
        );
    }

    let mut dirs = Vec::new();
    let mut current = start.to_path_buf();
    loop {
        dirs.push(current.clone());
        if current == root {
            break;
        }
        current = current
            .parent()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to find ancestor path from '{}' back to scan root '{}'.",
                    start.display(),
                    root.display()
                )
            })?
            .to_path_buf();
    }

    Ok(dirs)
}

fn validate_lockfile_syntax(
    spec: &ProjectInputSpec,
    npm_manifest: Option<&serde_json::Value>,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let project_dir = spec.project_dir();

    match spec.kind {
        ProjectInputKind::Npm => {
            let path = selected_lockfile_path(spec)
                .expect("npm preflight should guarantee a lockfile exists");
            let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
            let lockfile = serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': failed to parse JSON: {}",
                    path.display(),
                    err
                )
            })?;
            validate_npm_lockfile_version(&lockfile, &path, config)?;
            let manifest = npm_manifest.expect("npm manifests should be parsed during preflight");
            validate_npm_lockfile_consistency(manifest, &lockfile, &path)?;
            validate_npm_lockfile_provenance(&lockfile, &path)?;
        }
        ProjectInputKind::Cargo => {
            let path = project_dir.join("Cargo.lock");
            let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
            toml::from_str::<toml::Value>(&content).map_err(|err| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': failed to parse TOML: {}",
                    path.display(),
                    err
                )
            })?;
        }
        ProjectInputKind::Php => {
            let path = project_dir.join("composer.lock");
            let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
            serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': failed to parse JSON: {}",
                    path.display(),
                    err
                )
            })?;
        }
        ProjectInputKind::Dotnet => {
            let path = spec.manifest_path.with_file_name("packages.lock.json");
            let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
            serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': failed to parse JSON: {}",
                    path.display(),
                    err
                )
            })?;
        }
        ProjectInputKind::PyProjectPoetry => {
            let path = project_dir.join("poetry.lock");
            let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
            toml::from_str::<toml::Value>(&content).map_err(|err| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': failed to parse TOML: {}",
                    path.display(),
                    err
                )
            })?;
        }
        ProjectInputKind::PyRequirements
        | ProjectInputKind::PyProjectLegacy
        | ProjectInputKind::PyPipfile
        | ProjectInputKind::PySetupPy
        | ProjectInputKind::PySetupCfg => {}
        ProjectInputKind::Go
        | ProjectInputKind::Ruby
        | ProjectInputKind::Gradle
        | ProjectInputKind::Maven => {}
    }

    Ok(())
}

fn validate_npm_package_manager_policy(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<()> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;

    for ancestor_dir in ancestor_dirs_inclusive(&canonical_project_dir, scan_root)? {
        let manifest_path = ancestor_dir.join("package.json");
        if ancestor_dir == canonical_project_dir {
            validate_npm_package_manager_field(&spec.manifest_path, manifest, &spec.manifest_path)?;
        } else if parsers::path_detected(&manifest_path)? {
            let ancestor_manifest = read_npm_manifest_value(&manifest_path)?;
            validate_npm_package_manager_field(
                &manifest_path,
                &ancestor_manifest,
                &spec.manifest_path,
            )?;
        }

        for foreign_lockfile in ["pnpm-lock.yaml", "yarn.lock"] {
            let path = ancestor_dir.join(foreign_lockfile);
            if parsers::path_detected(&path)? {
                anyhow::bail!(
                    "Found foreign lockfile '{}' above npm project '{}'. sloppy-joe refuses to trust package-lock.json or npm-shrinkwrap.json when pnpm/yarn lock state is present anywhere in the ancestor tree within the scan root.",
                    path.display(),
                    spec.manifest_path.display()
                );
            }
        }
    }

    Ok(())
}

fn validate_npm_package_manager_field(
    manifest_path: &std::path::Path,
    manifest: &serde_json::Value,
    npm_project_manifest: &std::path::Path,
) -> Result<()> {
    if let Some(package_manager) = manifest
        .get("packageManager")
        .and_then(|value| value.as_str())
    {
        let manager = package_manager
            .split_once('@')
            .map(|(name, _)| name)
            .unwrap_or(package_manager);
        if manager != "npm" {
            anyhow::bail!(
                "package.json '{}' declares packageManager '{}'. npm project '{}' sits inside a {}-managed tree, so sloppy-joe refuses to trust package-lock.json or npm-shrinkwrap.json there.",
                manifest_path.display(),
                package_manager,
                npm_project_manifest.display(),
                manager
            );
        }
    }

    Ok(())
}

fn validate_npm_manifest_security_policy(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<()> {
    if manifest.get("overrides").is_some() {
        anyhow::bail!(
            "package.json '{}' uses npm overrides. Overrides change the resolved dependency graph, and sloppy-joe does not yet have strict override verification. Remove overrides or review this project with another control until strict support exists.",
            spec.manifest_path.display()
        );
    }

    Ok(())
}

struct WorkspaceRoot {
    manifest_path: std::path::PathBuf,
    project_dir: std::path::PathBuf,
    patterns: Vec<String>,
}

fn validate_workspace_npm_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
    npm_index: &NpmProjectIndex,
) -> Result<()> {
    let Some(workspace_root) = find_npm_workspace_root(scan_root, canonical_project_dir)? else {
        anyhow::bail!(
            "Local npm dependency '{}' in '{}' uses workspace:, but no ancestor package.json with a matching npm workspaces declaration was found. Scan the workspace root, or replace the workspace reference with a dependency source sloppy-joe can verify exactly.",
            dep_name,
            spec.manifest_path.display()
        );
    };

    let matching_dirs = npm_index
        .by_name
        .get(dep_name)
        .into_iter()
        .flat_map(|dirs| dirs.iter())
        .filter(|dir| *dir != canonical_project_dir)
        .filter(|dir| {
            workspace_patterns_match(
                &workspace_root.project_dir,
                dir,
                workspace_root.patterns.iter().map(String::as_str),
            )
        })
        .cloned()
        .collect::<Vec<_>>();

    match matching_dirs.len() {
        1 => Ok(()),
        0 => anyhow::bail!(
            "Local npm dependency '{}' in '{}' does not resolve to any scanned package declared by the workspaces in '{}'. Keep workspace targets inside the declared npm workspaces set, or remove the workspace reference.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
        _ => anyhow::bail!(
            "Local npm dependency '{}' in '{}' resolves ambiguously to multiple scanned packages declared by the workspaces in '{}'. Each workspace package name must be unique within the workspace root.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
    }
}

fn find_npm_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    for ancestor_dir in ancestor_dirs_inclusive(canonical_project_dir, scan_root)? {
        let manifest_path = ancestor_dir.join("package.json");
        if !parsers::path_detected(&manifest_path)? {
            continue;
        }

        let manifest = read_npm_manifest_value(&manifest_path)?;
        let Some(patterns) = parse_npm_workspaces(&manifest_path, &manifest)? else {
            continue;
        };

        if ancestor_dir == canonical_project_dir
            || workspace_patterns_match(
                &ancestor_dir,
                canonical_project_dir,
                patterns.iter().map(String::as_str),
            )
        {
            return Ok(Some(WorkspaceRoot {
                manifest_path: manifest_path.clone(),
                project_dir: ancestor_dir,
                patterns,
            }));
        }
    }

    Ok(None)
}

fn parse_npm_workspaces(
    manifest_path: &std::path::Path,
    manifest: &serde_json::Value,
) -> Result<Option<Vec<String>>> {
    let Some(value) = manifest.get("workspaces") else {
        return Ok(None);
    };

    let patterns = if let Some(array) = value.as_array() {
        array
            .iter()
            .map(|entry| {
                entry.as_str().map(str::to_string).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': workspaces entries must be strings.",
                        manifest_path.display()
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else if let Some(array) = value
        .get("packages")
        .and_then(|packages| packages.as_array())
    {
        array
            .iter()
            .map(|entry| {
                entry.as_str().map(str::to_string).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': workspaces.packages entries must be strings.",
                        manifest_path.display()
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        anyhow::bail!(
            "Broken manifest '{}': workspaces must be an array of strings or an object with a packages array.",
            manifest_path.display()
        );
    };

    Ok(Some(patterns))
}

fn workspace_patterns_match<'a>(
    root_dir: &std::path::Path,
    candidate_dir: &std::path::Path,
    mut patterns: impl Iterator<Item = &'a str>,
) -> bool {
    let Ok(relative) = candidate_dir.strip_prefix(root_dir) else {
        return false;
    };
    let path_parts = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if path_parts.is_empty() {
        return false;
    }

    patterns.any(|pattern| workspace_pattern_matches_parts(pattern, &path_parts))
}

fn workspace_pattern_matches_parts(pattern: &str, path_parts: &[String]) -> bool {
    let pattern_parts = pattern
        .trim()
        .trim_start_matches("./")
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    workspace_pattern_parts_match(&pattern_parts, path_parts)
}

fn workspace_pattern_parts_match(pattern_parts: &[&str], path_parts: &[String]) -> bool {
    match pattern_parts.split_first() {
        None => path_parts.is_empty(),
        Some((&"**", remaining_patterns)) => (0..=path_parts.len())
            .any(|skip| workspace_pattern_parts_match(remaining_patterns, &path_parts[skip..])),
        Some((&segment_pattern, remaining_patterns)) => {
            let Some((path_part, remaining_path)) = path_parts.split_first() else {
                return false;
            };
            wildcard_segment_matches(segment_pattern, path_part)
                && workspace_pattern_parts_match(remaining_patterns, remaining_path)
        }
    }
}

fn wildcard_segment_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.split_once('*') {
        None => pattern == value,
        Some((prefix, suffix)) => {
            if !value.starts_with(prefix) || !value.ends_with(suffix) {
                return false;
            }
            value.len() >= prefix.len() + suffix.len()
        }
    }
}

fn validate_npm_lockfile_version(
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let version = lockfile
        .get("lockfileVersion")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);

    if version == 1 && !config.allow_legacy_npm_v1_lockfile {
        anyhow::bail!(
            "This repo is using a legacy npm v5/v6 lockfile ('{}', lockfileVersion: 1). Regenerate with a modern npm. If you must keep it temporarily, set allow_legacy_npm_v1_lockfile to true.",
            lockfile_path.display()
        );
    }

    Ok(())
}

fn first_existing_lockfile(
    project_dir: &std::path::Path,
    candidates: &[&str],
) -> Option<std::path::PathBuf> {
    candidates.iter().find_map(|candidate| {
        let path = project_dir.join(candidate);
        match parsers::path_detected(&path) {
            Ok(true) => Some(path),
            _ => None,
        }
    })
}

fn legacy_python_manifest_paths(project_dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut manifests = Vec::new();

    if let Some(path) = first_legacy_requirements_file(project_dir)? {
        manifests.push(path);
    }
    for manifest in ["Pipfile", "setup.cfg", "setup.py"] {
        let path = project_dir.join(manifest);
        if parsers::path_detected(&path)? {
            manifests.push(path);
        }
    }
    let pyproject = project_dir.join("pyproject.toml");
    if parsers::path_detected(&pyproject)?
        && matches!(
            parsers::pyproject_toml::classify_manifest(&pyproject)?,
            parsers::pyproject_toml::PyprojectKind::Legacy
        )
    {
        manifests.push(pyproject);
    }

    manifests.sort();
    Ok(manifests)
}

fn first_legacy_requirements_file(
    project_dir: &std::path::Path,
) -> Result<Option<std::path::PathBuf>> {
    let mut candidates = std::fs::read_dir(project_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", project_dir.display(), err))?
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
    Ok(candidates.into_iter().next())
}

fn ensure_lockfile_readable(path: &std::path::Path, help: &str) -> Result<()> {
    parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)
        .map(|_| ())
        .map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is missing or unreadable: {}. Fix: {}",
                path.display(),
                err,
                help
            )
        })
}

fn ensure_one_lockfile_readable(
    project_dir: &std::path::Path,
    candidates: &[&str],
    help: &str,
) -> Result<()> {
    let mut found_readable = false;

    for candidate in candidates {
        let path = project_dir.join(candidate);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
                    anyhow::anyhow!(
                        "Required lockfile '{}' is unreadable: {}. Fix: {}",
                        path.display(),
                        err,
                        help
                    )
                })?;
                found_readable = true;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Required lockfile '{}' could not be inspected: {}. Fix: {}",
                    path.display(),
                    err,
                    help
                ));
            }
        }
    }

    if found_readable {
        return Ok(());
    }

    anyhow::bail!(
        "Required lockfile '{}' is missing. Fix: {}",
        candidates.join("' or '"),
        help
    )
}

fn validate_npm_lockfile_consistency(
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    fn section_map(value: &serde_json::Value, section: &str) -> BTreeMap<String, String> {
        value
            .get(section)
            .and_then(|section| section.as_object())
            .map(|section| {
                section
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .as_str()
                            .map(|version| (name.clone(), version.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    let manifest_sections = [
        ("dependencies", section_map(manifest, "dependencies")),
        ("devDependencies", section_map(manifest, "devDependencies")),
        (
            "optionalDependencies",
            section_map(manifest, "optionalDependencies"),
        ),
        (
            "peerDependencies",
            section_map(manifest, "peerDependencies"),
        ),
    ];

    let root_package = lockfile
        .get("packages")
        .and_then(|packages| packages.get(""))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    if root_package.is_object() {
        for (section, manifest_entries) in &manifest_sections {
            let lock_entries = section_map(&root_package, section);
            if *manifest_entries != lock_entries {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: root '{}' entries do not match. Regenerate the lockfile so it matches the manifest exactly.",
                    lockfile_path.display(),
                    section
                );
            }
        }
    } else {
        let manifest_names: BTreeSet<String> = manifest_sections
            .iter()
            .flat_map(|(_, entries)| entries.keys().cloned())
            .collect();
        let locked_names: BTreeSet<String> = lockfile
            .get("dependencies")
            .and_then(|deps| deps.as_object())
            .map(|deps| deps.keys().cloned().collect())
            .unwrap_or_default();
        if manifest_names != locked_names {
            anyhow::bail!(
                "Required lockfile '{}' is out of sync with package.json: direct dependency entries do not match. Regenerate the lockfile so it matches the manifest exactly.",
                lockfile_path.display()
            );
        }
    }

    for (alias_name, raw_spec) in section_map(manifest, "dependencies")
        .into_iter()
        .chain(section_map(manifest, "devDependencies"))
        .chain(section_map(manifest, "optionalDependencies"))
        .chain(section_map(manifest, "peerDependencies"))
    {
        if let Some(alias_spec) = raw_spec.strip_prefix("npm:") {
            let (target_name, _) = alias_spec.rsplit_once('@').ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported npm alias '{}' in package.json: expected npm:<package>@<version>",
                    crate::report::sanitize_for_terminal(&raw_spec)
                )
            })?;
            let entry = lockfile
                .get("packages")
                .and_then(|packages| packages.get(format!("node_modules/{alias_name}")))
                .and_then(|entry| entry.as_object())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Required lockfile '{}' is out of sync with package.json: missing npm alias entry for '{}'.",
                        lockfile_path.display(),
                        alias_name
                    )
                })?;
            let locked_name = entry.get("name").and_then(|name| name.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "Required lockfile '{}' is out of sync with package.json: npm alias '{}' is missing its locked package name.",
                    lockfile_path.display(),
                    alias_name
                )
            })?;
            if locked_name != target_name {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: npm alias '{}' targets '{}' in the manifest but '{}' in the lockfile.",
                    lockfile_path.display(),
                    alias_name,
                    target_name,
                    locked_name
                );
            }
        }
    }

    Ok(())
}

fn validate_npm_lockfile_provenance(
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    if let Some(packages) = lockfile.get("packages").and_then(|value| value.as_object()) {
        for (key, entry) in packages {
            validate_npm_lockfile_package_entry(key, entry, lockfile_path)?;
        }
        return Ok(());
    }

    if let Some(dependencies) = lockfile
        .get("dependencies")
        .and_then(|value| value.as_object())
    {
        validate_npm_lockfile_dependency_entries(dependencies, lockfile_path)?;
    }

    Ok(())
}

fn validate_npm_lockfile_package_entry(
    key: &str,
    entry: &serde_json::Value,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    if key.is_empty() {
        return Ok(());
    }
    let Some(entry) = entry.as_object() else {
        anyhow::bail!(
            "Broken lockfile '{}': package entry '{}' was not an object.",
            lockfile_path.display(),
            key
        );
    };
    validate_npm_lockfile_entry_fields(
        entry
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or(
                key.rsplit_once("node_modules/")
                    .map(|(_, name)| name)
                    .unwrap_or(key),
            ),
        entry,
        lockfile_path,
    )
}

fn validate_npm_lockfile_dependency_entries(
    dependencies: &serde_json::Map<String, serde_json::Value>,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    for (name, entry) in dependencies {
        let Some(entry) = entry.as_object() else {
            anyhow::bail!(
                "Broken lockfile '{}': dependency entry '{}' was not an object.",
                lockfile_path.display(),
                name
            );
        };
        validate_npm_lockfile_entry_fields(
            entry
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or(name),
            entry,
            lockfile_path,
        )?;
        if let Some(nested) = entry
            .get("dependencies")
            .and_then(|value| value.as_object())
        {
            validate_npm_lockfile_dependency_entries(nested, lockfile_path)?;
        }
    }
    Ok(())
}

fn validate_npm_lockfile_entry_fields(
    package_name: &str,
    entry: &serde_json::Map<String, serde_json::Value>,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    if entry
        .get("link")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || entry
            .get("inBundle")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
        || entry
            .get("bundled")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    {
        return Ok(());
    }

    if entry
        .get("version")
        .and_then(|value| value.as_str())
        .is_none()
    {
        return Ok(());
    }

    let resolved = entry
        .get("resolved")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' entry '{}' is missing a resolved source URL. sloppy-joe only trusts npm lockfile entries with explicit tarball provenance.",
                lockfile_path.display(),
                package_name
            )
        })?;
    if !is_trusted_npm_resolved_source(resolved) {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has untrusted resolved source '{}'. sloppy-joe only trusts npm registry tarball URLs in package-lock.json and npm-shrinkwrap.json.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolved)
        );
    }

    let integrity = entry
        .get("integrity")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' entry '{}' is missing integrity metadata. sloppy-joe only trusts npm lockfile entries with explicit integrity hashes.",
                lockfile_path.display(),
                package_name
            )
        })?;
    if !integrity.contains('-') {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has malformed integrity metadata '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(integrity)
        );
    }

    Ok(())
}

fn is_trusted_npm_resolved_source(resolved: &str) -> bool {
    let resolved = resolved.trim();
    resolved == "registry.npmjs.org"
        || resolved.starts_with("registry.npmjs.org/")
        || resolved.starts_with("https://registry.npmjs.org/")
}

#[cfg(test)]
fn detected_project_inputs(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
) -> Result<Vec<ProjectInputSpec>> {
    detected_project_inputs_with_config(
        project_dir,
        project_type,
        &config::SloppyJoeConfig::default(),
    )
}

fn detected_project_inputs_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    _config: &config::SloppyJoeConfig,
) -> Result<Vec<ProjectInputSpec>> {
    let mut specs = discover_project_inputs(project_dir)?;
    specs.retain(|spec| match project_type {
        Some("npm") => spec.kind == ProjectInputKind::Npm,
        Some("pypi") => spec.kind.is_python(),
        Some("cargo") => spec.kind == ProjectInputKind::Cargo,
        Some("go") => spec.kind == ProjectInputKind::Go,
        Some("ruby") => spec.kind == ProjectInputKind::Ruby,
        Some("php") => spec.kind == ProjectInputKind::Php,
        Some("jvm") => matches!(
            spec.kind,
            ProjectInputKind::Gradle | ProjectInputKind::Maven
        ),
        Some("dotnet") => spec.kind == ProjectInputKind::Dotnet,
        Some(_) => false,
        None => true,
    });
    prune_included_requirement_specs(project_dir, &mut specs)?;
    prefer_poetry_project_inputs(&mut specs);

    if specs.is_empty() {
        match project_type {
            Some("npm") => {
                anyhow::bail!("Required manifest 'package.json' is missing for this project type.")
            }
            Some("pypi") => anyhow::bail!(
                "Required Python manifest is missing for this project type. Expected one of: pyproject.toml, requirements*.txt, Pipfile, setup.cfg, or setup.py."
            ),
            Some("cargo") => {
                anyhow::bail!("Required manifest 'Cargo.toml' is missing for this project type.")
            }
            Some("go") => {
                anyhow::bail!("Required manifest 'go.mod' is missing for this project type.")
            }
            Some("ruby") => {
                anyhow::bail!("Required manifest 'Gemfile' is missing for this project type.")
            }
            Some("php") => {
                anyhow::bail!("Required manifest 'composer.json' is missing for this project type.")
            }
            Some("jvm") => anyhow::bail!(
                "Required manifest 'build.gradle, build.gradle.kts, or pom.xml' is missing for this project type."
            ),
            Some("dotnet") => {
                anyhow::bail!("Required manifest '.csproj' is missing for this project type.")
            }
            Some(_) | None => {}
        }
    }

    Ok(specs)
}

fn discover_project_inputs(project_dir: &std::path::Path) -> Result<Vec<ProjectInputSpec>> {
    let root = std::fs::canonicalize(project_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            project_dir.display(),
            err
        )
    })?;
    let mut visited = std::collections::HashSet::new();
    let mut specs = Vec::new();
    walk_project_tree(project_dir, &root, &mut visited, &mut specs, false)?;
    specs.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    Ok(specs)
}

fn walk_project_tree(
    current_dir: &std::path::Path,
    root: &std::path::Path,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    specs: &mut Vec<ProjectInputSpec>,
    inside_installed_node_modules: bool,
) -> Result<()> {
    let canonical_current = std::fs::canonicalize(current_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            current_dir.display(),
            err
        )
    })?;

    if !canonical_current.starts_with(root) {
        anyhow::bail!(
            "Refusing to follow symlinked directory '{}' outside the scan root.",
            current_dir.display()
        );
    }

    if !visited.insert(canonical_current.clone()) {
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(current_dir)
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to inspect {} for project manifests: {}",
                current_dir.display(),
                err
            )
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to inspect {} for project manifests: {}",
                current_dir.display(),
                err
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name();
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", path.display(), err))?;

        if file_type.is_dir() {
            if name.to_str() == Some(".git") {
                continue;
            }
            let child_inside_installed_node_modules = if name.to_str() == Some("node_modules") {
                inside_installed_node_modules
                    || directory_has_detected_manifest(current_dir, "package.json")
            } else {
                inside_installed_node_modules
            };
            walk_project_tree(
                &path,
                root,
                visited,
                specs,
                child_inside_installed_node_modules,
            )?;
            continue;
        }

        if file_type.is_symlink() {
            let target = std::fs::canonicalize(&path).map_err(|err| {
                anyhow::anyhow!(
                    "Failed to resolve symlinked path '{}': {}",
                    path.display(),
                    err
                )
            })?;
            if target.is_dir() {
                if !target.starts_with(root) {
                    anyhow::bail!(
                        "Refusing to follow symlinked directory '{}' outside the scan root.",
                        path.display()
                    );
                }
                walk_project_tree(
                    &path,
                    root,
                    visited,
                    specs,
                    inside_installed_node_modules
                        || (path.file_name().and_then(|name| name.to_str())
                            == Some("node_modules")
                            && directory_has_detected_manifest(current_dir, "package.json")),
                )?;
                continue;
            }
        }

        if let Some(spec) = project_input_from_path(&path, inside_installed_node_modules)? {
            specs.push(spec);
        }
    }

    Ok(())
}

fn directory_has_detected_manifest(dir: &std::path::Path, manifest_name: &str) -> bool {
    parsers::path_detected(&dir.join(manifest_name)).unwrap_or(false)
}

fn project_input_from_path(
    path: &std::path::Path,
    inside_installed_node_modules: bool,
) -> Result<Option<ProjectInputSpec>> {
    let Some(kind) = project_input_kind_from_path(path)? else {
        return Ok(None);
    };

    if inside_installed_node_modules {
        match kind {
            ProjectInputKind::Npm
                if has_npm_lockfile(path.parent().expect("manifest paths have parent")) => {}
            kind if kind == ProjectInputKind::Npm || kind.is_python() => return Ok(None),
            _ => {}
        }
    }

    Ok(Some(ProjectInputSpec {
        kind,
        manifest_path: path.to_path_buf(),
    }))
}

fn project_input_kind_from_path(path: &std::path::Path) -> Result<Option<ProjectInputKind>> {
    Ok(match path.file_name().and_then(|name| name.to_str()) {
        Some("package.json") => Some(ProjectInputKind::Npm),
        Some("pyproject.toml") => Some(match parsers::pyproject_toml::classify_manifest(path)? {
            parsers::pyproject_toml::PyprojectKind::Poetry => ProjectInputKind::PyProjectPoetry,
            parsers::pyproject_toml::PyprojectKind::Legacy => ProjectInputKind::PyProjectLegacy,
        }),
        Some("Pipfile") => Some(ProjectInputKind::PyPipfile),
        Some("setup.py") => Some(ProjectInputKind::PySetupPy),
        Some("setup.cfg") => Some(ProjectInputKind::PySetupCfg),
        Some("requirements.txt") => Some(ProjectInputKind::PyRequirements),
        Some(name) if name.starts_with("requirements") && name.ends_with(".txt") => {
            Some(ProjectInputKind::PyRequirements)
        }
        Some("Cargo.toml") => Some(ProjectInputKind::Cargo),
        Some("go.mod") => Some(ProjectInputKind::Go),
        Some("Gemfile") => Some(ProjectInputKind::Ruby),
        Some("composer.json") => Some(ProjectInputKind::Php),
        Some("build.gradle") | Some("build.gradle.kts") => Some(ProjectInputKind::Gradle),
        Some("pom.xml") => Some(ProjectInputKind::Maven),
        _ if path.extension().is_some_and(|ext| ext == "csproj") => Some(ProjectInputKind::Dotnet),
        _ => None,
    })
}

fn prefer_poetry_project_inputs(specs: &mut Vec<ProjectInputSpec>) {
    let poetry_dirs: std::collections::HashSet<std::path::PathBuf> = specs
        .iter()
        .filter(|spec| spec.kind == ProjectInputKind::PyProjectPoetry)
        .map(|spec| spec.project_dir().to_path_buf())
        .collect();

    specs.retain(|spec| {
        spec.kind == ProjectInputKind::PyProjectPoetry
            || !spec.kind.is_legacy_python()
            || !poetry_dirs.contains(spec.project_dir())
    });
}

fn has_npm_lockfile(project_dir: &std::path::Path) -> bool {
    ["npm-shrinkwrap.json", "package-lock.json"]
        .iter()
        .any(|name| parsers::path_detected(&project_dir.join(name)).unwrap_or(false))
}

fn npm_dependency_entries(manifest: &serde_json::Value) -> Vec<(String, String)> {
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .into_iter()
    .flat_map(|section| {
        manifest
            .get(section)
            .and_then(|value| value.as_object())
            .into_iter()
            .flat_map(|section| section.iter())
            .filter_map(|(name, value)| value.as_str().map(|spec| (name.clone(), spec.to_string())))
    })
    .collect()
}

fn prune_included_requirement_specs(
    scan_root: &std::path::Path,
    specs: &mut Vec<ProjectInputSpec>,
) -> Result<()> {
    let mut included = std::collections::HashSet::new();

    for spec in specs
        .iter()
        .filter(|spec| spec.kind == ProjectInputKind::PyRequirements)
    {
        for include in parsers::requirements::included_paths(&spec.manifest_path, scan_root)? {
            included.insert(include);
        }
    }

    specs.retain(|spec| {
        if spec.kind != ProjectInputKind::PyRequirements {
            return true;
        }
        match std::fs::canonicalize(&spec.manifest_path) {
            Ok(canonical) => !included.contains(&canonical),
            Err(_) => true,
        }
    });

    Ok(())
}

fn parse_project_inputs(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
) -> Result<Vec<ParsedProject>> {
    let mut projects = Vec::new();
    for spec in specs {
        projects.push(ParsedProject {
            spec: spec.clone(),
            deps: parse_project_input(scan_root, spec)?,
        });
    }
    Ok(projects)
}

fn parse_project_input(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<Vec<Dependency>> {
    match spec.kind {
        ProjectInputKind::Npm => parsers::package_json::parse(spec.project_dir()),
        ProjectInputKind::PyProjectPoetry => {
            parsers::pyproject_toml::parse_poetry_file(&spec.manifest_path)
        }
        ProjectInputKind::PyRequirements => {
            parsers::requirements::parse_file(&spec.manifest_path, scan_root)
        }
        ProjectInputKind::PyProjectLegacy => {
            parsers::pyproject_toml::parse_legacy_file(&spec.manifest_path)
        }
        ProjectInputKind::PyPipfile => parsers::pipfile::parse_file(&spec.manifest_path),
        ProjectInputKind::PySetupPy => parsers::setup_py::parse_file(&spec.manifest_path),
        ProjectInputKind::PySetupCfg => parsers::setup_cfg::parse_file(&spec.manifest_path),
        ProjectInputKind::Cargo => parsers::cargo_toml::parse(spec.project_dir()),
        ProjectInputKind::Go => parsers::go_mod::parse(spec.project_dir()),
        ProjectInputKind::Ruby => parsers::gemfile::parse(spec.project_dir()),
        ProjectInputKind::Php => parsers::composer_json::parse(spec.project_dir()),
        ProjectInputKind::Gradle | ProjectInputKind::Maven => {
            parsers::jvm::parse_manifest(&spec.manifest_path)
        }
        ProjectInputKind::Dotnet => parsers::csproj::parse_file(&spec.manifest_path),
    }
}

fn selected_lockfile_path(spec: &ProjectInputSpec) -> Option<std::path::PathBuf> {
    let project_dir = spec.project_dir();
    match spec.kind {
        ProjectInputKind::Npm => {
            first_existing_lockfile(project_dir, &["npm-shrinkwrap.json", "package-lock.json"])
        }
        ProjectInputKind::Cargo => Some(project_dir.join("Cargo.lock")),
        ProjectInputKind::Go => Some(project_dir.join("go.sum")),
        ProjectInputKind::Ruby => Some(project_dir.join("Gemfile.lock")),
        ProjectInputKind::Php => Some(project_dir.join("composer.lock")),
        ProjectInputKind::Gradle => Some(project_dir.join("gradle.lockfile")),
        ProjectInputKind::Dotnet => Some(spec.manifest_path.with_file_name("packages.lock.json")),
        ProjectInputKind::PyProjectPoetry => Some(project_dir.join("poetry.lock")),
        ProjectInputKind::PyRequirements
        | ProjectInputKind::PyProjectLegacy
        | ProjectInputKind::PyPipfile
        | ProjectInputKind::PySetupPy
        | ProjectInputKind::PySetupCfg
        | ProjectInputKind::Maven => None,
    }
}

fn lockfile_paths_for_project(spec: &ProjectInputSpec) -> Vec<std::path::PathBuf> {
    selected_lockfile_path(spec).into_iter().collect()
}

fn scan_hash_for_projects(projects: &[ParsedProject]) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    type ProjectHashTuple<'a> = (String, &'a str, Option<&'a str>, &'a str, Option<&'a str>);

    let mut tuples: Vec<ProjectHashTuple<'_>> = projects
        .iter()
        .flat_map(|project| {
            project.deps.iter().map(|dep| {
                (
                    project.spec.manifest_path.display().to_string(),
                    dep.name.as_str(),
                    dep.version.as_deref(),
                    dep.ecosystem.as_str(),
                    dep.actual_name.as_deref(),
                )
            })
        })
        .collect();
    tuples.sort();
    tuples.hash(&mut hasher);

    let mut hashed_manifests = std::collections::HashSet::new();
    let mut manifests: Vec<_> = projects
        .iter()
        .map(|project| project.spec.manifest_path.clone())
        .filter(|path| hashed_manifests.insert(path.clone()))
        .collect();
    manifests.sort();

    for path in manifests {
        let content = parsers::read_bytes_limited(&path, parsers::MAX_MANIFEST_BYTES)
            .map_err(|err| format!("cannot safely hash {}: {}", path.display(), err))?;
        path.display().to_string().hash(&mut hasher);
        content.hash(&mut hasher);
    }

    let mut hashed_lockfiles = std::collections::HashSet::new();
    let mut lockfiles: Vec<_> = projects
        .iter()
        .flat_map(|project| lockfile_paths_for_project(&project.spec))
        .filter(|path| hashed_lockfiles.insert(path.clone()))
        .collect();
    lockfiles.sort();

    for path in lockfiles {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let content = parsers::read_bytes_limited(&path, parsers::MAX_MANIFEST_BYTES)
                    .map_err(|err| format!("cannot safely hash {}: {}", path.display(), err))?;
                path.display().to_string().hash(&mut hasher);
                content.hash(&mut hasher);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!("cannot safely hash {}: {}", path.display(), err));
            }
        }
    }

    Ok(hasher.finish())
}

fn scan_hash_matches_cache_for_projects(
    projects: &[ParsedProject],
    cache_base: &std::path::Path,
) -> std::result::Result<bool, String> {
    let hash = scan_hash_for_projects(projects)?;
    let hash_path = cache_base.join("scan-hash.json");
    Ok(matches!(
        cache::read_json_cache::<ScanHashCache>(&hash_path, 7 * 24 * 3600, |c| c.timestamp),
        Some(cached) if cached.hash == hash
    ))
}

/// Compute a hash of dependency tuples + lockfile content for change detection.
/// Includes lockfile so that resolved version changes (e.g., a compromised upstream
/// version satisfying the same range) invalidate the cache even when the manifest
/// is unchanged. If a known lockfile exists but cannot be safely hashed, hash-based
/// scan skipping is disabled for the run.
#[cfg(test)]
fn scan_hash(
    project_dir: &std::path::Path,
    deps: &[Dependency],
) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // Hash sorted dep tuples (manifest content)
    let mut tuples: Vec<(&str, Option<&str>, &str, Option<&str>)> = deps
        .iter()
        .map(|d| {
            (
                d.name.as_str(),
                d.version.as_deref(),
                d.ecosystem.as_str(),
                d.actual_name.as_deref(),
            )
        })
        .collect();
    tuples.sort();
    tuples.hash(&mut hasher);

    let lockfiles: Vec<std::path::PathBuf> = match deps.first().map(|dep| dep.ecosystem) {
        Some(Ecosystem::Npm) => {
            first_existing_lockfile(project_dir, &["npm-shrinkwrap.json", "package-lock.json"])
                .into_iter()
                .collect()
        }
        Some(Ecosystem::Cargo) => vec![project_dir.join("Cargo.lock")],
        Some(Ecosystem::Go) => vec![project_dir.join("go.sum")],
        Some(Ecosystem::Ruby) => vec![project_dir.join("Gemfile.lock")],
        Some(Ecosystem::PyPI) => vec![project_dir.join("poetry.lock")],
        Some(Ecosystem::Php) => vec![project_dir.join("composer.lock")],
        Some(Ecosystem::Jvm) => vec![project_dir.join("gradle.lockfile")],
        Some(Ecosystem::Dotnet) => vec![project_dir.join("packages.lock.json")],
        None => Vec::new(),
    };

    // Hash lockfile content (resolved versions) — catches upstream version changes
    for path in lockfiles {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let content = parsers::read_bytes_limited(&path, parsers::MAX_MANIFEST_BYTES)
                    .map_err(|err| format!("cannot safely hash {}: {}", path.display(), err))?;
                path.display().to_string().hash(&mut hasher);
                content.hash(&mut hasher);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!("cannot safely hash {}: {}", path.display(), err));
            }
        }
    }

    Ok(hasher.finish())
}

/// Cache entry for manifest hash skip.
#[derive(serde::Serialize, serde::Deserialize)]
struct ScanHashCache {
    timestamp: u64,
    hash: u64,
}

#[cfg(test)]
fn scan_hash_matches_cache(
    project_dir: &std::path::Path,
    deps: &[Dependency],
    cache_base: &std::path::Path,
) -> std::result::Result<bool, String> {
    let hash = scan_hash(project_dir, deps)?;
    let hash_path = cache_base.join("scan-hash.json");
    Ok(matches!(
        cache::read_json_cache::<ScanHashCache>(&hash_path, 7 * 24 * 3600, |c| c.timestamp),
        Some(cached) if cached.hash == hash
    ))
}

async fn scan_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    let specs = detected_project_inputs_with_config(project_dir, project_type, &config)?;
    let preflight_warnings = preflight_project_inputs(project_dir, &specs, &config)?;
    let projects = parse_project_inputs(project_dir, &specs)?;

    if projects.is_empty() {
        parsers::parse_dependencies(project_dir, project_type)?;
        return Ok(ScanReport::from_issues(0, preflight_warnings));
    }

    // Skip scan if deps haven't changed (manifest + lockfile hash check)
    if !opts.no_cache && !opts.skip_hash_check {
        let cache_base = opts
            .cache_dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
        match scan_hash_matches_cache_for_projects(&projects, &cache_base) {
            Ok(true) => {
                eprintln!("Dependencies unchanged, skipping scan.");
                return Ok(ScanReport::from_issues(0, preflight_warnings));
            }
            Ok(false) => {}
            Err(reason) => {
                eprintln!(
                    "Skipping dependency-hash shortcut: {}",
                    report::sanitize_for_terminal(&reason)
                );
            }
        }
    }

    // Scan each ecosystem separately, merge reports
    let client = registry::http_client();
    let osv_client = checks::malicious::RealOsvClient::with_client(client.clone());
    let mut total_packages = 0;
    let mut all_issues = preflight_warnings;
    let mut all_review_candidates = Vec::new();

    for project in &projects {
        if project.deps.is_empty() {
            continue;
        }
        let ecosystem = project.deps[0].ecosystem;
        let registry = registry::registry_for_with_client(ecosystem, client.clone())?;
        let report = scan_with_services_inner_for_kind(
            Some(project.spec.kind),
            project.spec.project_dir(),
            config.clone(),
            project.deps.clone(),
            &*registry,
            &osv_client,
            opts,
        )
        .await?;
        total_packages += report.packages_checked;
        all_issues.extend(report.issues);
        all_review_candidates.extend(report.review_candidates);
    }

    let report = ScanReport::from_issues_with_review_candidates(
        total_packages,
        all_issues,
        all_review_candidates,
    );

    // Save hash after successful scan
    if !opts.no_cache {
        let cache_base = opts
            .cache_dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
        match scan_hash_for_projects(&projects) {
            Ok(hash) => {
                let hash_path = cache_base.join("scan-hash.json");
                cache::atomic_write_json(
                    &hash_path,
                    &ScanHashCache {
                        timestamp: cache::now_epoch(),
                        hash,
                    },
                );
            }
            Err(reason) => {
                eprintln!(
                    "Not caching dependency hash for this run: {}",
                    report::sanitize_for_terminal(&reason)
                );
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
async fn scan_with_services_inner(
    project_dir: &std::path::Path,
    config: config::SloppyJoeConfig,
    deps: Vec<Dependency>,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    scan_with_services_inner_for_kind(None, project_dir, config, deps, registry, osv_client, opts)
        .await
}

async fn scan_with_services_inner_for_kind(
    project_kind: Option<ProjectInputKind>,
    project_dir: &std::path::Path,
    config: config::SloppyJoeConfig,
    deps: Vec<Dependency>,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    if deps.is_empty() {
        return Ok(ScanReport::empty());
    }

    let ecosystem = deps[0].ecosystem;

    // Classify deps into three tiers
    let (checkable, non_internal, internal) = classify_deps(&deps, &config, ecosystem);

    // Parse lockfile once
    let mut lockfile_data =
        lockfiles::LockfileData::parse_for_kind(project_dir, project_kind, &non_internal)?;

    // Build context + accumulator, run pipeline on direct deps
    let pipeline = checks::pipeline::default_pipeline();
    let ctx = checks::CheckContext {
        checkable_deps: &checkable,
        non_internal_deps: &non_internal,
        config: &config,
        registry,
        osv_client,
        resolution: &lockfile_data.resolution,
        ecosystem,
        opts,
    };
    let mut acc = checks::ScanAccumulator::new();
    acc.issues.extend(alias_identity_issues(&non_internal));
    for check in &pipeline {
        check.run(&ctx, &mut acc).await?;
    }
    mark_source(&mut acc.issues, "direct");

    // Run OSV on internal packages (they skip all other checks but still need vuln scanning)
    if !internal.is_empty() {
        let internal_resolution =
            lockfiles::LockfileData::parse_for_kind(project_dir, project_kind, &internal)
                .map(|ld| ld.resolution)
                .unwrap_or_default();
        let internal_ctx = checks::CheckContext {
            checkable_deps: &[],
            non_internal_deps: &internal,
            config: &config,
            registry,
            osv_client,
            resolution: &internal_resolution,
            ecosystem,
            opts,
        };
        let mut internal_acc = checks::ScanAccumulator::new();
        let osv_check: Box<dyn checks::Check> = Box::new(checks::pipeline::MaliciousCheck);
        osv_check.run(&internal_ctx, &mut internal_acc).await?;
        mark_source(&mut internal_acc.issues, "direct");
        acc.issues.extend(internal_acc.issues);
    }

    // Transitive dependency scanning
    let mut transitive_deps = std::mem::take(&mut lockfile_data.transitive_deps);
    transitive_deps.retain(|dep| {
        !config.is_internal(ecosystem.as_str(), dep.package_name())
            && !config.is_allowed(ecosystem.as_str(), dep.package_name())
    });

    if !transitive_deps.is_empty() {
        let trans_resolution = lockfile_data.resolve_transitive(&transitive_deps)?;

        // Build transitive pipeline (skip similarity unless --deep)
        let trans_pipeline: Vec<Box<dyn checks::Check>> =
            if opts.deep || ecosystem == Ecosystem::Npm {
                checks::pipeline::default_pipeline()
            } else {
                // All checks except similarity for transitive deps
                vec![
                    Box::new(checks::pipeline::CanonicalCheck),
                    Box::new(checks::pipeline::MetadataCheck),
                    Box::new(checks::pipeline::ExistenceCheck),
                    Box::new(checks::pipeline::MaliciousCheck),
                ]
            };

        let trans_ctx = checks::CheckContext {
            checkable_deps: &transitive_deps,
            non_internal_deps: &transitive_deps,
            config: &config,
            registry,
            osv_client,
            resolution: &trans_resolution,
            ecosystem,
            opts,
        };
        let mut trans_acc = checks::ScanAccumulator::new();
        // Carry forward similarity_flagged from direct deps
        trans_acc.similarity_flagged = acc.similarity_flagged.clone();
        for check in &trans_pipeline {
            check.run(&trans_ctx, &mut trans_acc).await?;
        }
        mark_source(&mut trans_acc.issues, "transitive");
        acc.issues.extend(trans_acc.issues);
    }

    Ok(ScanReport::from_issues_with_review_candidates(
        non_internal.len() + transitive_deps.len(),
        acc.issues,
        acc.review_candidates,
    ))
}

/// Classify deps into three tiers. Returns (checkable, non_internal, internal).
/// - checkable: full checks (similarity, existence, canonical, metadata, osv)
/// - non_internal: allowed + checkable (canonical, metadata, osv)
/// - internal: OSV only (skip similarity, existence, canonical, metadata)
fn classify_deps(
    deps: &[Dependency],
    config: &config::SloppyJoeConfig,
    ecosystem: Ecosystem,
) -> (Vec<Dependency>, Vec<Dependency>, Vec<Dependency>) {
    let eco_str = ecosystem.as_str();
    let (internal, rest): (Vec<&Dependency>, Vec<&Dependency>) = deps
        .iter()
        .partition(|dep| config.is_internal(eco_str, dep.package_name()));

    let (allowed, checkable): (Vec<&Dependency>, Vec<&Dependency>) = rest
        .iter()
        .copied()
        .partition(|dep| config.is_allowed(eco_str, dep.package_name()));

    if !internal.is_empty() {
        let names: Vec<_> = internal
            .iter()
            .map(|d| report::sanitize_for_terminal(d.package_name()))
            .collect();
        eprintln!(
            "Running OSV-only on {} internal package(s): {}",
            names.len(),
            names.join(", ")
        );
    }

    if !allowed.is_empty() {
        let names: Vec<_> = allowed
            .iter()
            .map(|d| report::sanitize_for_terminal(d.package_name()))
            .collect();
        eprintln!(
            "Skipping existence/similarity for {} allowed package(s): {}",
            names.len(),
            names.join(", ")
        );
    }

    let checkable_owned: Vec<Dependency> = checkable.into_iter().cloned().collect();
    let non_internal: Vec<Dependency> = rest.into_iter().cloned().collect();
    let internal_owned: Vec<Dependency> = internal.into_iter().cloned().collect();

    (checkable_owned, non_internal, internal_owned)
}

fn mark_source(issues: &mut [Issue], source: &str) {
    for issue in issues.iter_mut() {
        if issue.source.is_none() {
            issue.source = Some(source.to_string());
        }
    }
}

fn alias_identity_issues(deps: &[Dependency]) -> Vec<Issue> {
    deps.iter()
        .filter_map(|dep| {
            let actual = dep.actual_name.as_deref()?;
            Some(
                Issue::new(&dep.name, checks::names::RESOLUTION_NPM_ALIAS, Severity::Warning)
                    .message(format!(
                        "'{}' is declared as an npm alias for '{}'. sloppy-joe scanned the published package identity '{}', not the manifest alias.",
                        dep.name, actual, actual
                    ))
                    .fix(format!(
                        "Review whether the alias '{}' should point to '{}'. If the indirection is intentional, keep both names under code review because the manifest-visible package name differs from the installed registry identity.",
                        dep.name, actual
                    )),
            )
        })
        .collect()
}

/// Options that control scan behavior, set from CLI flags.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions<'a> {
    /// Enable similarity checks on transitive dependencies (--deep).
    pub deep: bool,
    /// Enable expensive mutation generators like bitflip (--paranoid).
    pub paranoid: bool,
    /// Disable reading from disk caches (--no-cache). Writes still happen.
    pub no_cache: bool,
    /// Override the default cache directory (--cache-dir).
    pub cache_dir: Option<&'a std::path::Path>,
    /// Disable OSV disk cache entirely (for testing).
    pub disable_osv_disk_cache: bool,
    /// Skip the manifest hash check (used by `cache` command to always run).
    pub skip_hash_check: bool,
    /// Emit structured exception review candidates for supported findings.
    pub review_exceptions: bool,
}

/// A dependency parsed from a project manifest file (package.json, Cargo.toml, etc.).
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Package key as it appears in the manifest (e.g., "react", "@types/node", or an npm alias).
    pub name: String,
    /// Version requirement from the manifest (e.g., "^18.0", "==2.31.0"). None if unspecified.
    pub version: Option<String>,
    /// Which ecosystem this dependency belongs to.
    pub ecosystem: Ecosystem,
    /// Underlying published package identity when the manifest key is an alias.
    pub actual_name: Option<String>,
}

impl Dependency {
    pub fn exact_version(&self) -> Option<String> {
        self.version
            .as_deref()
            .and_then(|version| version::exact_version(version, self.ecosystem))
    }

    pub fn has_unresolved_version(&self) -> bool {
        self.exact_version().is_none()
    }

    pub fn package_name(&self) -> &str {
        self.actual_name.as_deref().unwrap_or(&self.name)
    }
}

pub(crate) fn unresolved_version_policy_issues(
    deps: &[Dependency],
    resolution: &lockfiles::ResolutionResult,
    config: &config::SloppyJoeConfig,
) -> Vec<Issue> {
    let severity = if config.allow_unresolved_versions {
        Severity::Warning
    } else {
        Severity::Error
    };

    deps.iter()
        .filter(|dep| resolution.is_unresolved(dep))
        .map(|dep| {
            let message = if let Some(requirement) = dep.version.as_deref() {
                format!(
                    "'{}' uses the unresolved version requirement '{}'. Without a resolved version, the following checks are skipped: version-age, install-script-risk, dependency-explosion, maintainer-change, and known-vulnerability (OSV).",
                    dep.package_name(),
                    requirement
                )
            } else {
                format!(
                    "'{}' does not declare an exact version and no trusted lockfile resolution was available. The following checks are skipped: version-age, install-script-risk, dependency-explosion, maintainer-change, and known-vulnerability (OSV).",
                    dep.package_name()
                )
            };

            Issue::new(
                dep.package_name(),
                checks::names::RESOLUTION_NO_EXACT_VERSION,
                severity,
            )
                .message(message)
                .fix("Pin an exact version or provide a trusted lockfile entry. To continue with reduced accuracy, set allow_unresolved_versions to true in the config.")
        })
        .collect()
}

/// Shared test helpers for creating test dependencies.
#[cfg(test)]
pub(crate) mod test_helpers {
    use super::{Dependency, Ecosystem};

    /// Create a test dependency with the given name and Npm ecosystem.
    pub fn npm_dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        }
    }

    /// Create a test dependency with name, optional version, and ecosystem.
    pub fn dep_with(name: &str, version: Option<&str>, ecosystem: Ecosystem) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            ecosystem,
            actual_name: None,
        }
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
