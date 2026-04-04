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
use checks::Check;
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
        scan_mode: ScanMode::Full,
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
        scan_mode: ScanMode::Full,
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
    PyProjectUv,
    PyRequirements,
    PyRequirementsTrusted,
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
    lockfile_path_override: Option<std::path::PathBuf>,
    js_binding: Option<JsProjectBinding>,
}

#[derive(Clone, Debug)]
struct ParsedProject {
    spec: ProjectInputSpec,
    deps: Vec<Dependency>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum JsPackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl JsPackageManager {
    fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
        }
    }
}

#[derive(Clone, Debug)]
struct JsProjectBinding {
    manager: JsPackageManager,
    root_manifest_path: std::path::PathBuf,
    lockfile_path: Option<std::path::PathBuf>,
    package_entry_key: String,
}

impl ProjectInputSpec {
    fn project_dir(&self) -> &std::path::Path {
        self.manifest_path
            .parent()
            .expect("manifest paths should always have a parent directory")
    }

    fn npm_lockfile_package_key(&self) -> &str {
        self.js_binding
            .as_ref()
            .map(|binding| binding.package_entry_key.as_str())
            .unwrap_or("")
    }
}

impl ProjectInputKind {
    fn is_python(self) -> bool {
        matches!(
            self,
            Self::PyProjectPoetry
                | Self::PyProjectUv
                | Self::PyRequirements
                | Self::PyRequirementsTrusted
                | Self::PyProjectLegacy
                | Self::PyPipfile
                | Self::PySetupPy
                | Self::PySetupCfg
        )
    }

    fn manifest_label(self) -> &'static str {
        match self {
            Self::Npm => "package.json",
            Self::PyProjectPoetry | Self::PyProjectUv | Self::PyProjectLegacy => "pyproject.toml",
            Self::PyRequirements | Self::PyRequirementsTrusted => "requirements*.txt",
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
            Self::PyProjectUv => Some("Run `uv lock` and commit uv.lock alongside pyproject.toml."),
            Self::PyRequirements
            | Self::PyRequirementsTrusted
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
    let npm_alias_targets = npm_alias_targets_by_lockfile(specs, &npm_manifests)?;
    let mut warnings = Vec::new();

    for spec in specs {
        let npm_manifest = npm_manifests.get(&spec.manifest_path);
        match spec.kind {
            ProjectInputKind::Npm => {
                let manifest =
                    npm_manifest.expect("npm manifests should be parsed during preflight");
                parsers::package_json::parse_manifest_value(&spec.manifest_path, manifest)
            }
            _ => parse_project_input_with_config(scan_root, spec, config),
        }
        .map_err(|err| {
            anyhow::anyhow!(
                "Broken manifest '{}': {}",
                spec.manifest_path.display(),
                err
            )
        })?;

        match spec.kind {
            ProjectInputKind::Npm => ensure_authoritative_js_lockfile_readable(spec)?,
            ProjectInputKind::PyProjectPoetry => ensure_lockfile_readable(
                &spec.project_dir().join("poetry.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::PyProjectUv => {
                if config.python_enforcement == config::PythonEnforcement::PoetryOnly {
                    anyhow::bail!(
                        "Python manifest '{}' uses the uv workflow, which is not allowed in poetry_only mode. Use Poetry with pyproject.toml + poetry.lock, or relax python_enforcement to prefer_poetry.",
                        spec.manifest_path.display()
                    );
                }
                ensure_lockfile_readable(
                    &spec.project_dir().join("uv.lock"),
                    spec.kind.missing_lockfile_help().unwrap(),
                )?
            }
            ProjectInputKind::PyRequirementsTrusted => {
                if config.python_enforcement == config::PythonEnforcement::PoetryOnly {
                    anyhow::bail!(
                        "Python manifest '{}' uses trusted pip-tools requirements, which are not allowed in poetry_only mode. Use Poetry with pyproject.toml + poetry.lock, or relax python_enforcement to prefer_poetry.",
                        spec.manifest_path.display()
                    );
                }
            }
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
                &authoritative_cargo_lockfile_path(scan_root, &spec.manifest_path, config)?,
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Go => {
                let manifest_content = parsers::read_file_limited(
                    &spec.manifest_path,
                    parsers::MAX_MANIFEST_BYTES,
                )
                .map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
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

        if spec.kind == ProjectInputKind::Cargo {
            warnings.extend(validate_cargo_source_policy(scan_root, spec, config)?);
        }

        if matches!(
            spec.kind,
            ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
        ) {
            warnings.extend(trusted_python_preference_warnings(spec)?);
        }

        if spec.kind == ProjectInputKind::Npm {
            let manifest = npm_manifest.expect("npm manifests should be parsed during preflight");
            validate_supported_js_manager(spec)?;
            match spec
                .js_binding
                .as_ref()
                .map(|binding| binding.manager)
                .unwrap_or(JsPackageManager::Npm)
            {
                JsPackageManager::Npm => {
                    validate_npm_manifest_security_policy(spec, manifest)?;
                    let allowed_alias_targets = selected_lockfile_path(spec)
                        .and_then(|path| npm_alias_targets.get(&path))
                        .cloned()
                        .unwrap_or_default();
                    let (lockfile, npm_warnings) = read_validated_npm_lockfile(
                        spec,
                        manifest,
                        config,
                        &allowed_alias_targets,
                    )?;
                    warnings.extend(npm_warnings);
                    let npm_scope_root = npm_trusted_scope_root(&canonical_root, spec)?;
                    validate_local_npm_dependencies(
                        &npm_scope_root,
                        spec,
                        manifest,
                        &lockfile,
                        &npm_index,
                    )?;
                }
                JsPackageManager::Pnpm => {
                    let lockfile = read_validated_pnpm_lockfile(spec, manifest)?;
                    let pnpm_scope_root = npm_trusted_scope_root(&canonical_root, spec)?;
                    validate_local_pnpm_dependencies(
                        &pnpm_scope_root,
                        spec,
                        manifest,
                        &lockfile,
                        &npm_index,
                    )?;
                }
                JsPackageManager::Bun => {
                    let lockfile = read_validated_bun_lockfile(spec, manifest)?;
                    let bun_scope_root = npm_trusted_scope_root(&canonical_root, spec)?;
                    validate_local_bun_dependencies(
                        &bun_scope_root,
                        spec,
                        manifest,
                        &lockfile,
                        &npm_index,
                    )?;
                }
                JsPackageManager::Yarn => {
                    let lockfile = read_validated_yarn_lockfile(spec, manifest)?;
                    let yarn_scope_root = npm_trusted_scope_root(&canonical_root, spec)?;
                    validate_local_yarn_dependencies(&yarn_scope_root, spec, manifest, &lockfile)?;
                }
            }
        } else {
            validate_lockfile_syntax(scan_root, spec, npm_manifest, config)?;
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
        "Python manifest '{}' uses the legacy {} workflow. sloppy-joe will scan it, but trusted Python modes such as Poetry with poetry.lock, uv with uv.lock, and fully hash-locked pip-tools requirements provide stronger lockfile-backed assurance.",
        spec.manifest_path.display(),
        spec.kind.manifest_label()
    ))
    .fix("Migrate this project to a trusted Python mode and commit its authoritative lock data. Legacy Python manifests remain allowed, but every run will warn until the project moves to Poetry, uv, or fully hash-locked pip-tools.")
}

fn trusted_python_preference_warnings(spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
    let mut warnings = Vec::new();
    let (tool_name, fix) = match spec.kind {
        ProjectInputKind::PyProjectPoetry => (
            "Poetry",
            "Remove or stop relying on the legacy Python manifest, and keep pyproject.toml + poetry.lock as the single trusted dependency source for this project.",
        ),
        ProjectInputKind::PyProjectUv => (
            "uv",
            "Remove or stop relying on the legacy Python manifest, and keep pyproject.toml + uv.lock as the single trusted dependency source for this project.",
        ),
        _ => return Ok(warnings),
    };
    for candidate in legacy_python_manifest_paths(spec.project_dir())? {
        warnings.push(
            Issue::new(
                candidate.display().to_string(),
                checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST,
                Severity::Warning,
            )
            .message(format!(
                "Ignoring legacy Python manifest '{}' because '{}' is a {} project. sloppy-joe prefers the trusted {} workflow as the source of truth for this directory.",
                candidate.display(),
                spec.manifest_path.display(),
                tool_name,
                tool_name
            ))
            .fix(fix),
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

fn read_validated_npm_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    config: &config::SloppyJoeConfig,
    allowed_alias_targets: &std::collections::HashMap<String, String>,
) -> Result<(serde_json::Value, Vec<Issue>)> {
    let path =
        selected_lockfile_path(spec).expect("npm preflight should guarantee a lockfile exists");
    let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
    let lockfile = serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken lockfile '{}': failed to parse JSON: {}",
            path.display(),
            err
        )
    })?;
    validate_npm_lockfile_version(&lockfile, &path, config)?;
    validate_npm_lockfile_consistency(manifest, &lockfile, &path, spec.npm_lockfile_package_key())?;
    validate_npm_lockfile_provenance(&lockfile, &path, allowed_alias_targets)?;

    let warnings = if npm_lockfile_version(&lockfile) == 1 && config.allow_legacy_npm_v1_lockfile {
        legacy_npm_v1_warnings(&path)
    } else {
        Vec::new()
    };

    Ok((lockfile, warnings))
}

fn read_validated_pnpm_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<serde_yaml::Value> {
    let path =
        selected_lockfile_path(spec).expect("pnpm preflight should guarantee a lockfile exists");
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let lockfile: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    validate_pnpm_lockfile_consistency(spec, manifest, &lockfile, &path)?;
    crate::lockfiles::pnpm::validate_provenance(&lockfile, &path)?;
    Ok(lockfile)
}

fn read_validated_bun_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<serde_json::Value> {
    let path =
        selected_lockfile_path(spec).expect("bun preflight should guarantee a lockfile exists");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bun.lock");
    if file_name == "bun.lockb" {
        anyhow::bail!(
            "Legacy Bun binary lockfile '{}' is not supported yet. Regenerate and commit the text bun.lock.",
            path.display()
        );
    }
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let lockfile: serde_json::Value = json5::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    validate_bun_lockfile_consistency(spec, manifest, &lockfile, &path)?;
    crate::lockfiles::bun::validate_provenance(&lockfile, &path)?;
    Ok(lockfile)
}

fn read_validated_yarn_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<crate::lockfiles::yarn::ParsedYarnLock> {
    let path =
        selected_lockfile_path(spec).expect("Yarn preflight should guarantee a lockfile exists");
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let project_name = manifest
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Broken manifest '{}': Yarn projects must declare a package name.",
                spec.manifest_path.display()
            )
        })?;
    let lockfile =
        crate::lockfiles::yarn::parse_lockfile(&content, path.clone(), spec.project_dir())
            .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    crate::lockfiles::yarn::validate_manifest_consistency(
        &lockfile,
        manifest,
        spec.npm_lockfile_package_key(),
        project_name,
    )?;
    crate::lockfiles::yarn::validate_provenance(&lockfile)?;
    Ok(lockfile)
}

fn read_validated_uv_lockfile(spec: &ProjectInputSpec, deps: &[Dependency]) -> Result<toml::Value> {
    let path = selected_lockfile_path(spec).unwrap_or_else(|| spec.project_dir().join("uv.lock"));
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let lockfile: toml::Value = toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    crate::lockfiles::uv::validate_schema(&lockfile, &path)?;
    crate::lockfiles::uv::validate_manifest_consistency(&lockfile, deps, &path)?;
    crate::lockfiles::uv::validate_provenance(&lockfile, &path)?;
    Ok(lockfile)
}

fn validate_supported_js_manager(spec: &ProjectInputSpec) -> Result<()> {
    let Some(binding) = &spec.js_binding else {
        return Ok(());
    };
    if matches!(
        binding.manager,
        JsPackageManager::Npm
            | JsPackageManager::Pnpm
            | JsPackageManager::Bun
            | JsPackageManager::Yarn
    ) {
        return Ok(());
    }
    anyhow::bail!(
        "JS project '{}' is managed by '{}', rooted at '{}'. sloppy-joe detected the manager correctly, but support for {} projects is not implemented yet.",
        spec.manifest_path.display(),
        binding.manager.as_str(),
        binding.root_manifest_path.display(),
        binding.manager.as_str()
    );
}

fn npm_trusted_scope_root(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<std::path::PathBuf> {
    if let Some(binding) = &spec.js_binding {
        let root_dir = binding
            .root_manifest_path
            .parent()
            .expect("package.json should always have a parent directory");
        return std::fs::canonicalize(root_dir)
            .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", root_dir.display(), err));
    }
    std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))
}

fn legacy_npm_v1_warnings(lockfile_path: &std::path::Path) -> Vec<Issue> {
    vec![
        Issue::new(
            "<lockfile>",
            checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE,
            Severity::Warning,
        )
        .message(format!(
            "Legacy npm v5/v6 lockfile '{}' is allowed by config, but sloppy-joe treats it as reduced-confidence input. package-lock v1 cannot prove modern npm artifact and graph invariants as strongly as current lockfiles.",
            lockfile_path.display()
        ))
        .fix(
            "Regenerate the lockfile with a modern npm and commit the upgraded package-lock.json or npm-shrinkwrap.json.",
        ),
        Issue::new(
            "<lockfile>",
            checks::names::RESOLUTION_NO_TRUSTED_TRANSITIVE_COVERAGE,
            Severity::Warning,
        )
        .message(format!(
            "Legacy npm v5/v6 lockfile '{}' is scanned without trusted transitive coverage. sloppy-joe skips transitive dependency extraction for package-lock v1 because the older format is too weak for strict graph trust.",
            lockfile_path.display()
        ))
        .fix(
            "Upgrade the lockfile with a modern npm if you need trusted transitive npm coverage.",
        ),
    ]
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
    names_by_dir: std::collections::HashMap<std::path::PathBuf, String>,
    by_name: std::collections::HashMap<String, std::collections::HashSet<std::path::PathBuf>>,
}

fn bind_js_project_inputs(
    scan_root: &std::path::Path,
    specs: &mut [ProjectInputSpec],
) -> Result<()> {
    for spec in specs.iter_mut() {
        if spec.kind != ProjectInputKind::Npm {
            continue;
        }
        spec.js_binding = Some(resolve_js_project_binding(scan_root, spec)?);
        if let Some(binding) = &spec.js_binding {
            spec.lockfile_path_override = binding.lockfile_path.clone();
        }
    }
    Ok(())
}

fn resolve_js_project_binding(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<JsProjectBinding> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;
    let ancestry_root = js_ancestry_root(scan_root, spec.project_dir())?;
    let workspace_root = find_js_workspace_root(&ancestry_root, &canonical_project_dir)?;
    let (root_manifest_path, root_dir, manager) = if let Some(root) = workspace_root.as_ref() {
        (
            root.manifest_path.clone(),
            root.project_dir.clone(),
            root.manager,
        )
    } else {
        let root_manifest_path = spec.manifest_path.clone();
        let root_manifest = read_npm_manifest_value(&root_manifest_path)?;
        let root_dir = root_manifest_path
            .parent()
            .expect("package.json should always have a parent directory")
            .to_path_buf();
        let manager = detect_js_manager(&root_dir, &root_manifest_path, &root_manifest)?;
        (root_manifest_path, root_dir, manager)
    };
    let canonical_root_dir = std::fs::canonicalize(&root_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", root_dir.display(), err))?;
    let lockfile_path = match manager {
        JsPackageManager::Npm => {
            first_existing_lockfile(&root_dir, &["npm-shrinkwrap.json", "package-lock.json"])
        }
        JsPackageManager::Pnpm => {
            let path = root_dir.join("pnpm-lock.yaml");
            parsers::path_detected(&path)?.then_some(path)
        }
        JsPackageManager::Yarn => {
            let path = root_dir.join("yarn.lock");
            parsers::path_detected(&path)?.then_some(path)
        }
        JsPackageManager::Bun => {
            let text = root_dir.join("bun.lock");
            if parsers::path_detected(&text)? {
                Some(text)
            } else {
                let binary = root_dir.join("bun.lockb");
                parsers::path_detected(&binary)?.then_some(binary)
            }
        }
    };
    let package_entry_key = if canonical_project_dir == canonical_root_dir {
        match manager {
            JsPackageManager::Pnpm => ".".to_string(),
            _ => String::new(),
        }
    } else {
        relative_package_entry_key(&canonical_root_dir, &canonical_project_dir)?
    };

    Ok(JsProjectBinding {
        manager,
        root_manifest_path,
        lockfile_path,
        package_entry_key,
    })
}

fn js_ancestry_root(
    scan_root: &std::path::Path,
    project_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    if let Some(git_root) =
        crate::config::registry::find_git_root(project_dir).map_err(anyhow::Error::msg)?
    {
        return Ok(git_root);
    }
    std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))
}

fn relative_package_entry_key(
    root_dir: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<String> {
    let relative = canonical_project_dir.strip_prefix(root_dir).map_err(|_| {
        anyhow::anyhow!(
            "Path '{}' is outside npm root '{}'.",
            canonical_project_dir.display(),
            root_dir.display()
        )
    })?;
    let key = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if key.is_empty() {
        anyhow::bail!(
            "Could not derive npm workspace entry key for '{}' relative to '{}'.",
            canonical_project_dir.display(),
            root_dir.display()
        );
    }
    Ok(key)
}

fn detect_js_manager(
    root_dir: &std::path::Path,
    manifest_path: &std::path::Path,
    manifest: &serde_json::Value,
) -> Result<JsPackageManager> {
    let mut signals = Vec::new();
    if let Some(package_manager) = manifest
        .get("packageManager")
        .and_then(|value| value.as_str())
    {
        let manager = package_manager
            .split_once('@')
            .map(|(name, _)| name)
            .unwrap_or(package_manager);
        let manager = match manager {
            "npm" => JsPackageManager::Npm,
            "pnpm" => JsPackageManager::Pnpm,
            "yarn" => JsPackageManager::Yarn,
            "bun" => JsPackageManager::Bun,
            other => {
                anyhow::bail!(
                    "package.json '{}' declares unsupported packageManager '{}'. sloppy-joe only understands npm, pnpm, yarn, and bun at the JS manager layer.",
                    manifest_path.display(),
                    other
                );
            }
        };
        signals.push((
            manager,
            format!("packageManager in '{}'", manifest_path.display()),
        ));
    }
    for (marker, manager) in [
        ("pnpm-lock.yaml", JsPackageManager::Pnpm),
        ("pnpm-workspace.yaml", JsPackageManager::Pnpm),
        ("yarn.lock", JsPackageManager::Yarn),
        (".pnp.cjs", JsPackageManager::Yarn),
        ("bun.lock", JsPackageManager::Bun),
        ("bun.lockb", JsPackageManager::Bun),
        ("npm-shrinkwrap.json", JsPackageManager::Npm),
        ("package-lock.json", JsPackageManager::Npm),
    ] {
        let path = root_dir.join(marker);
        if parsers::path_detected(&path)? {
            signals.push((manager, path.display().to_string()));
        }
    }

    let distinct = signals
        .iter()
        .map(|(manager, _)| *manager)
        .collect::<std::collections::HashSet<_>>();
    if distinct.len() > 1 {
        let details = signals
            .into_iter()
            .map(|(manager, source)| format!("{} via {}", manager.as_str(), source))
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "JS project rooted at '{}' has conflicting package-manager signals: {}. sloppy-joe requires one authoritative JS manager per root.",
            manifest_path.display(),
            details
        );
    }

    Ok(signals
        .into_iter()
        .next()
        .map(|(manager, _)| manager)
        .unwrap_or(JsPackageManager::Npm))
}

fn npm_alias_targets_by_lockfile(
    specs: &[ProjectInputSpec],
    manifests: &std::collections::HashMap<std::path::PathBuf, serde_json::Value>,
) -> Result<std::collections::HashMap<std::path::PathBuf, std::collections::HashMap<String, String>>>
{
    let mut by_lockfile = std::collections::HashMap::new();
    for spec in specs {
        if spec.kind != ProjectInputKind::Npm {
            continue;
        }
        let Some(lockfile_path) = selected_lockfile_path(spec) else {
            continue;
        };
        let Some(manifest) = manifests.get(&spec.manifest_path) else {
            continue;
        };
        let aliases = by_lockfile
            .entry(lockfile_path)
            .or_insert_with(std::collections::HashMap::new);
        for (alias_name, raw_spec) in npm_dependency_entries(manifest) {
            let Some(alias_spec) = raw_spec.strip_prefix("npm:") else {
                continue;
            };
            let (target_name, _) = alias_spec.rsplit_once('@').ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported npm alias '{}' in {}: expected npm:<package>@<version>",
                    crate::report::sanitize_for_terminal(&raw_spec),
                    spec.manifest_path.display()
                )
            })?;
            if let Some(existing) = aliases.get(&alias_name)
                && existing != target_name
            {
                anyhow::bail!(
                    "Npm alias '{}' resolves to both '{}' and '{}' under authoritative lockfile '{}'. sloppy-joe requires alias bindings to be unique per lockfile.",
                    alias_name,
                    existing,
                    target_name,
                    selected_lockfile_path(spec)
                        .expect("lockfile path checked above")
                        .display()
                );
            }
            aliases.insert(alias_name, target_name.to_string());
        }
    }
    Ok(by_lockfile)
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
                .names_by_dir
                .insert(project_dir.clone(), name.to_string());
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
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
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
        let expected_target = if local_spec.starts_with("workspace:") {
            validate_workspace_npm_dependency(
                trusted_root,
                spec,
                &name,
                &canonical_project_dir,
                npm_index,
            )?
        } else {
            let canonical_target = resolve_local_npm_target(
                trusted_root,
                spec,
                &name,
                &local_spec,
                &canonical_project_dir,
            )?;
            if !npm_index.dirs.contains(&canonical_target) {
                anyhow::bail!(
                    "Local npm dependency '{}' in '{}' resolves to '{}' inside the scan root, but no scanned npm project was found there.",
                    name,
                    spec.manifest_path.display(),
                    local_spec
                );
            }
            if npm_index
                .names_by_dir
                .get(&canonical_target)
                .is_none_or(|target_name| target_name != &name)
            {
                let actual = npm_index
                    .names_by_dir
                    .get(&canonical_target)
                    .cloned()
                    .unwrap_or_else(|| "<missing package name>".to_string());
                anyhow::bail!(
                    "Local npm dependency '{}' in '{}' resolves to '{}', but that project declares package name '{}'. Local file:/link: targets must match the dependency package identity exactly.",
                    name,
                    spec.manifest_path.display(),
                    canonical_target.display(),
                    crate::report::sanitize_for_terminal(&actual)
                );
            }
            canonical_target
        };

        validate_local_npm_lockfile_target(spec, lockfile, &name, &local_spec, &expected_target)?;
    }

    Ok(())
}

fn validate_local_pnpm_dependencies(
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_yaml::Value,
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
        let expected_target = if local_spec.starts_with("workspace:") {
            validate_workspace_pnpm_dependency(trusted_root, spec, &name, &canonical_project_dir)?
        } else {
            let canonical_target = resolve_local_npm_target(
                trusted_root,
                spec,
                &name,
                &local_spec,
                &canonical_project_dir,
            )?;
            if !npm_index.dirs.contains(&canonical_target) {
                anyhow::bail!(
                    "Local pnpm dependency '{}' in '{}' resolves to '{}' inside the scan root, but no scanned package.json was found there.",
                    name,
                    spec.manifest_path.display(),
                    local_spec
                );
            }
            if npm_index
                .names_by_dir
                .get(&canonical_target)
                .is_none_or(|target_name| target_name != &name)
            {
                let actual = npm_index
                    .names_by_dir
                    .get(&canonical_target)
                    .cloned()
                    .unwrap_or_else(|| "<missing package name>".to_string());
                anyhow::bail!(
                    "Local pnpm dependency '{}' in '{}' resolves to '{}', but that project declares package name '{}'. Local file:/link: targets must match the dependency package identity exactly.",
                    name,
                    spec.manifest_path.display(),
                    canonical_target.display(),
                    crate::report::sanitize_for_terminal(&actual)
                );
            }
            canonical_target
        };

        validate_local_pnpm_lockfile_target(spec, lockfile, &name, &local_spec, &expected_target)?;
    }

    Ok(())
}

fn validate_local_bun_dependencies(
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
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
        let expected_target = if local_spec.starts_with("workspace:") {
            validate_workspace_bun_dependency(trusted_root, spec, &name, &canonical_project_dir)?
        } else {
            let canonical_target = resolve_local_npm_target(
                trusted_root,
                spec,
                &name,
                &local_spec,
                &canonical_project_dir,
            )?;
            if !npm_index.dirs.contains(&canonical_target) {
                anyhow::bail!(
                    "Local Bun dependency '{}' in '{}' resolves to '{}' inside the scan root, but no scanned package.json was found there.",
                    name,
                    spec.manifest_path.display(),
                    local_spec
                );
            }
            if npm_index
                .names_by_dir
                .get(&canonical_target)
                .is_none_or(|target_name| target_name != &name)
            {
                let actual = npm_index
                    .names_by_dir
                    .get(&canonical_target)
                    .cloned()
                    .unwrap_or_else(|| "<missing package name>".to_string());
                anyhow::bail!(
                    "Local Bun dependency '{}' in '{}' resolves to '{}', but that project declares package name '{}'. Local file:/link: targets must match the dependency package identity exactly.",
                    name,
                    spec.manifest_path.display(),
                    canonical_target.display(),
                    crate::report::sanitize_for_terminal(&actual)
                );
            }
            canonical_target
        };

        validate_local_bun_lockfile_target(spec, lockfile, &name, &local_spec, &expected_target)?;
    }

    Ok(())
}

fn validate_local_yarn_dependencies(
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &crate::lockfiles::yarn::ParsedYarnLock,
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
        if !local_spec.starts_with("workspace:") {
            anyhow::bail!(
                "Local Yarn dependency '{}' in '{}' uses unsupported spec '{}'. sloppy-joe currently supports Yarn workspace: dependencies, but file:/link: targets remain blocked until their lockfile provenance is modeled exactly.",
                name,
                spec.manifest_path.display(),
                crate::report::sanitize_for_terminal(&local_spec)
            );
        }

        let expected_target =
            validate_workspace_yarn_dependency(trusted_root, spec, &name, &canonical_project_dir)?;
        let relative_target = if expected_target == *trusted_root {
            ".".to_string()
        } else {
            expected_target
                .strip_prefix(trusted_root)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Local Yarn dependency '{}' in '{}' resolved outside the trusted Yarn root '{}'.",
                        name,
                        spec.manifest_path.display(),
                        trusted_root.display()
                    )
                })?
                .components()
                .filter_map(|component| match component {
                    std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/")
        };

        crate::lockfiles::yarn::validate_workspace_target(lockfile, &name, &relative_target)?;
    }

    Ok(())
}

fn validate_local_npm_lockfile_target(
    spec: &ProjectInputSpec,
    lockfile: &serde_json::Value,
    dep_name: &str,
    local_spec: &str,
    expected_target: &std::path::Path,
) -> Result<()> {
    let lockfile_path = selected_lockfile_path(spec)
        .expect("npm projects must have a selected lockfile during preflight");
    let entry = lockfile
        .get("packages")
        .and_then(|packages| packages.get(format!("node_modules/{dep_name}")))
        .and_then(|value| value.as_object())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is out of sync with package.json: local npm dependency '{}' is missing its lockfile entry.",
                lockfile_path.display(),
                dep_name
            )
        })?;

    if !entry
        .get("link")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' must be a local link for '{}', but link=true was not present.",
            lockfile_path.display(),
            dep_name,
            local_spec
        );
    }

    let resolved = entry
        .get("resolved")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' entry '{}' is missing its resolved local target for '{}'.",
                lockfile_path.display(),
                dep_name,
                local_spec
            )
        })?;
    let lockfile_dir = lockfile_path
        .parent()
        .expect("lockfile paths should always have a parent directory");
    let candidate = if std::path::Path::new(resolved).is_absolute() {
        std::path::PathBuf::from(resolved)
    } else {
        lockfile_dir.join(resolved)
    };
    let normalized = normalize_filesystem_path(&candidate);
    let canonical_lockfile_target = std::fs::canonicalize(&normalized).map_err(|err| {
        anyhow::anyhow!(
            "Required lockfile '{}' entry '{}' points to '{}' but that target is missing or unreadable: {}.",
            lockfile_path.display(),
            dep_name,
            resolved,
            err
        )
    })?;

    if canonical_lockfile_target != expected_target {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' points to '{}' for '{}', but the manifest-verified local target is '{}'. Regenerate the lockfile so the local dependency binding matches exactly.",
            lockfile_path.display(),
            dep_name,
            resolved,
            local_spec,
            expected_target.display()
        );
    }

    Ok(())
}

fn validate_local_pnpm_lockfile_target(
    spec: &ProjectInputSpec,
    lockfile: &serde_yaml::Value,
    dep_name: &str,
    local_spec: &str,
    expected_target: &std::path::Path,
) -> Result<()> {
    let lockfile_path = selected_lockfile_path(spec)
        .expect("pnpm projects must have a selected lockfile during preflight");
    let importer_key = spec
        .js_binding
        .as_ref()
        .map(|binding| binding.package_entry_key.as_str())
        .unwrap_or(".");
    let importer = lockfile
        .get("importers")
        .and_then(|value| value.get(importer_key))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is out of sync: importer '{}' is missing.",
                lockfile_path.display(),
                importer_key
            )
        })?;
    let version = pnpm_importer_entry(importer, dep_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Required lockfile '{}' is out of sync: local pnpm dependency '{}' is missing from importer '{}'.",
            lockfile_path.display(),
            dep_name,
            importer_key
        )
    })?;
    let resolved = version
        .strip_prefix("link:")
        .or_else(|| version.strip_prefix("file:"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' importer '{}' records '{}' as '{}', but local pnpm dependencies must resolve through link:/file: entries.",
                lockfile_path.display(),
                importer_key,
                dep_name,
                crate::report::sanitize_for_terminal(version)
            )
        })?;
    let lockfile_dir = lockfile_path
        .parent()
        .expect("lockfile paths should always have a parent directory");
    let importer_dir = if importer_key == "." {
        lockfile_dir.to_path_buf()
    } else {
        lockfile_dir.join(importer_key)
    };
    let candidate = if std::path::Path::new(resolved).is_absolute() {
        std::path::PathBuf::from(resolved)
    } else {
        importer_dir.join(resolved)
    };
    let normalized = normalize_filesystem_path(&candidate);
    let canonical_lockfile_target = std::fs::canonicalize(&normalized).map_err(|err| {
        anyhow::anyhow!(
            "Required lockfile '{}' importer '{}' points '{}' at '{}' but that target is missing or unreadable: {}.",
            lockfile_path.display(),
            importer_key,
            dep_name,
            resolved,
            err
        )
    })?;
    if canonical_lockfile_target != expected_target {
        anyhow::bail!(
            "Required lockfile '{}' importer '{}' points '{}' to '{}' for '{}', but the manifest-verified local target is '{}'. Regenerate pnpm-lock.yaml so the local dependency binding matches exactly.",
            lockfile_path.display(),
            importer_key,
            dep_name,
            resolved,
            local_spec,
            expected_target.display()
        );
    }
    Ok(())
}

fn validate_local_bun_lockfile_target(
    spec: &ProjectInputSpec,
    lockfile: &serde_json::Value,
    dep_name: &str,
    local_spec: &str,
    expected_target: &std::path::Path,
) -> Result<()> {
    let lockfile_path = selected_lockfile_path(spec)
        .expect("Bun projects must have a selected lockfile during preflight");
    let descriptor = lockfile
        .get("packages")
        .and_then(|packages| packages.get(dep_name))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is out of sync with package.json: local Bun dependency '{}' is missing its lockfile package entry.",
                lockfile_path.display(),
                dep_name
            )
        })?;

    let (prefix, label) = if local_spec.starts_with("workspace:") {
        ("@workspace:", "workspace:")
    } else if local_spec.starts_with("file:") {
        ("@file:", "file:")
    } else if local_spec.starts_with("link:") {
        ("@link:", "link:")
    } else {
        anyhow::bail!(
            "Local Bun dependency '{}' in '{}' uses unsupported spec '{}'.",
            dep_name,
            spec.manifest_path.display(),
            crate::report::sanitize_for_terminal(local_spec)
        );
    };

    let expected_prefix = format!("{dep_name}{prefix}");
    let Some(relative_target) = descriptor.strip_prefix(&expected_prefix) else {
        anyhow::bail!(
            "Required lockfile '{}' is out of sync with package.json: local Bun dependency '{}' should resolve via {}, but the lockfile recorded '{}'.",
            lockfile_path.display(),
            dep_name,
            label,
            crate::report::sanitize_for_terminal(descriptor)
        );
    };

    let lockfile_root = lockfile_path
        .parent()
        .expect("lockfile paths should always have a parent directory");
    let canonical_lock_target = std::fs::canonicalize(lockfile_root.join(relative_target))
        .map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' points local Bun dependency '{}' at '{}', but that target is unreadable: {}",
                lockfile_path.display(),
                dep_name,
                crate::report::sanitize_for_terminal(relative_target),
                err
            )
        })?;
    if canonical_lock_target != expected_target {
        anyhow::bail!(
            "Required lockfile '{}' is out of sync with package.json: local Bun dependency '{}' points to '{}', but package.json resolves to '{}'. Regenerate bun.lock from the Bun workspace root.",
            lockfile_path.display(),
            dep_name,
            canonical_lock_target.display(),
            expected_target.display()
        );
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

fn cargo_trusted_scope_root(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<std::path::PathBuf> {
    let canonical_root = std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))?;
    let manifest_dir = manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let canonical_manifest_dir = std::fs::canonicalize(manifest_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", manifest_dir.display(), err))?;

    if canonical_manifest_dir.starts_with(&canonical_root) {
        return Ok(canonical_root);
    }

    if cargo_allowlisted_local_target(scan_root, &canonical_manifest_dir, config)? {
        return Ok(canonical_manifest_dir);
    }

    anyhow::bail!(
        "Path '{}' is outside scan root '{}' and not exactly allowlisted for Cargo local provenance.",
        canonical_manifest_dir.display(),
        canonical_root.display()
    );
}

fn find_in_scope_cargo_workspace_root(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<Option<parsers::cargo_toml::CargoManifest>> {
    let manifest_dir = manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let canonical_manifest_dir = std::fs::canonicalize(manifest_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", manifest_dir.display(), err))?;
    let trusted_root = cargo_trusted_scope_root(scan_root, manifest_path, config)?;

    for ancestor in ancestor_dirs_inclusive(&canonical_manifest_dir, &trusted_root)? {
        let candidate = ancestor.join("Cargo.toml");
        if !parsers::path_detected(&candidate)? {
            continue;
        }
        let manifest = parsers::cargo_toml::parse_manifest_file(&candidate)?;
        if manifest.has_workspace
            && cargo_workspace_contains_manifest(&manifest, &canonical_manifest_dir)?
        {
            return Ok(Some(manifest));
        }
    }

    Ok(None)
}

fn cargo_workspace_contains_manifest(
    workspace: &parsers::cargo_toml::CargoManifest,
    canonical_manifest_dir: &std::path::Path,
) -> Result<bool> {
    let workspace_dir = workspace
        .manifest_path
        .parent()
        .expect("workspace manifest should always have a parent directory");
    let canonical_workspace_dir = std::fs::canonicalize(workspace_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", workspace_dir.display(), err))?;

    if canonical_manifest_dir == canonical_workspace_dir {
        return Ok(true);
    }
    if !canonical_manifest_dir.starts_with(&canonical_workspace_dir) {
        return Ok(false);
    }
    if workspace.workspace_members.is_empty() {
        return Ok(false);
    }

    let excluded = workspace_patterns_match(
        &canonical_workspace_dir,
        canonical_manifest_dir,
        workspace.workspace_exclude.iter().map(String::as_str),
    );
    if excluded {
        return Ok(false);
    }

    Ok(workspace_patterns_match(
        &canonical_workspace_dir,
        canonical_manifest_dir,
        workspace.workspace_members.iter().map(String::as_str),
    ))
}

fn authoritative_cargo_lockfile_path(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<std::path::PathBuf> {
    if let Some(workspace_root) =
        find_in_scope_cargo_workspace_root(scan_root, manifest_path, config)?
    {
        let workspace_dir = workspace_root
            .manifest_path
            .parent()
            .expect("workspace manifest should always have a parent directory");
        return Ok(workspace_dir.join("Cargo.lock"));
    }

    Ok(manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory")
        .join("Cargo.lock"))
}

fn cargo_lockfile_value(lockfile_path: &std::path::Path) -> Result<toml::Value> {
    let content = parsers::read_file_limited(lockfile_path, parsers::MAX_MANIFEST_BYTES)?;
    toml::from_str::<toml::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken lockfile '{}': failed to parse TOML: {}",
            lockfile_path.display(),
            err
        )
    })
}

fn cargo_lockfile_entries(lockfile: &toml::Value) -> Vec<&toml::value::Table> {
    lockfile
        .get("package")
        .and_then(|value| value.as_array())
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter_map(|package| package.as_table())
        .collect()
}

fn cargo_issue_message_prefix(check: &str) -> &'static str {
    match check {
        checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE => "Cargo local dependency source",
        checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE => "Cargo registry source",
        checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE => "Cargo git source",
        checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE => "Cargo provenance rewrite",
        _ => "Cargo dependency source",
    }
}

fn cargo_fail(check: &str, message: impl Into<String>) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", cargo_issue_message_prefix(check), message.into())
}

fn cargo_dependency_exact_version(
    spec: &parsers::cargo_toml::CargoDependencySpec,
) -> Option<String> {
    version::exact_version(spec.version.as_deref()?, Ecosystem::Cargo)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveCargoDependency {
    spec: parsers::cargo_toml::CargoDependencySpec,
    base_dir: std::path::PathBuf,
    expected_exact_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveCargoRewrite {
    package_name: String,
    patch_scope: Option<parsers::cargo_toml::CargoPatchScope>,
    replace_source: Option<String>,
    replace_version: Option<String>,
    spec: parsers::cargo_toml::CargoDependencySpec,
    base_dir: std::path::PathBuf,
}

#[derive(Debug, Default)]
struct CargoConfigRewrites {
    local_paths: std::collections::HashMap<String, std::path::PathBuf>,
    source_replace_with: std::collections::HashMap<String, String>,
    source_definitions: std::collections::HashMap<String, CargoConfigSourceDefinition>,
    rewrite_targets: Vec<EffectiveCargoRewrite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CargoConfigSourceDefinition {
    Registry(String),
    Unsupported { kind: String, detail: String },
}

fn cargo_package_name_from_manifest(manifest_path: &std::path::Path) -> Result<Option<String>> {
    let content = parsers::read_file_limited(manifest_path, parsers::MAX_MANIFEST_BYTES)?;
    let value = toml::from_str::<toml::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken manifest '{}': failed to parse TOML: {}",
            manifest_path.display(),
            err
        )
    })?;
    Ok(value
        .get("package")
        .and_then(|value| value.as_table())
        .and_then(|package| package.get("name"))
        .and_then(|value| value.as_str())
        .map(str::to_string))
}

fn merge_cargo_config_rewrites(into: &mut CargoConfigRewrites, from: CargoConfigRewrites) {
    into.local_paths.extend(from.local_paths);
    into.source_replace_with.extend(from.source_replace_with);
    into.source_definitions.extend(from.source_definitions);
    into.rewrite_targets.extend(from.rewrite_targets);
}

fn ensure_additive_cargo_config_rewrites(
    base: &CargoConfigRewrites,
    overlay: &CargoConfigRewrites,
    origin: &std::path::Path,
) -> Result<()> {
    for (package, path) in &overlay.local_paths {
        if let Some(existing) = base.local_paths.get(package)
            && existing != path
        {
            return Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Host-local Cargo config '{}' conflicts with repo-visible local path trust for crate '{}'. sloppy-joe only allows additive host-local Cargo relaxations.",
                    origin.display(),
                    package
                ),
            ));
        }
    }

    for (source_name, alias) in &overlay.source_replace_with {
        if let Some(existing) = base.source_replace_with.get(source_name)
            && existing != alias
        {
            return Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Host-local Cargo config '{}' conflicts with repo-visible source replacement for '{}'. sloppy-joe only allows additive host-local Cargo relaxations.",
                    origin.display(),
                    source_name
                ),
            ));
        }
    }

    for (source_name, definition) in &overlay.source_definitions {
        if let Some(existing) = base.source_definitions.get(source_name)
            && existing != definition
        {
            return Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Host-local Cargo config '{}' conflicts with repo-visible source definition for '{}'. sloppy-joe only allows additive host-local Cargo relaxations.",
                    origin.display(),
                    source_name
                ),
            ));
        }
    }

    Ok(())
}

fn cargo_registry_source_for_alias<'a>(
    alias: &str,
    config: &'a config::SloppyJoeConfig,
) -> Option<&'a str> {
    config
        .trusted_registries("cargo")
        .iter()
        .find(|entry| entry.name == alias)
        .map(|entry| entry.source.as_str())
}

fn cargo_normalize_registry_source(source: &str) -> String {
    let trimmed = source.trim();
    if trimmed.starts_with("registry+") || trimmed.starts_with("sparse+") {
        trimmed.to_string()
    } else {
        format!("registry+{trimmed}")
    }
}

fn cargo_git_source_id(
    url: &str,
    rev: Option<&str>,
    branch: Option<&str>,
    tag: Option<&str>,
) -> String {
    if let Some(rev) = rev {
        return format!("git+{url}?rev={rev}#{rev}");
    }
    if let Some(branch) = branch {
        return format!("git+{url}?branch={branch}");
    }
    if let Some(tag) = tag {
        return format!("git+{url}?tag={tag}");
    }
    format!("git+{url}")
}

fn cargo_dependency_source_id(
    dep: &parsers::cargo_toml::CargoDependencySpec,
    config: &config::SloppyJoeConfig,
) -> Option<String> {
    match &dep.source {
        parsers::cargo_toml::CargoSourceSpec::CratesIo => {
            Some("registry+https://github.com/rust-lang/crates.io-index".to_string())
        }
        parsers::cargo_toml::CargoSourceSpec::RegistryAlias(alias) => {
            cargo_registry_source_for_alias(alias, config).map(str::to_string)
        }
        parsers::cargo_toml::CargoSourceSpec::RegistryIndex(source) => Some(source.clone()),
        parsers::cargo_toml::CargoSourceSpec::Git {
            url,
            rev,
            branch,
            tag,
        } => Some(cargo_git_source_id(
            url,
            rev.as_deref(),
            branch.as_deref(),
            tag.as_deref(),
        )),
        parsers::cargo_toml::CargoSourceSpec::Path(_)
        | parsers::cargo_toml::CargoSourceSpec::Workspace => None,
    }
}

fn cargo_config_source_name(source: &parsers::cargo_toml::CargoSourceSpec) -> Option<&str> {
    match source {
        parsers::cargo_toml::CargoSourceSpec::CratesIo => Some("crates-io"),
        parsers::cargo_toml::CargoSourceSpec::RegistryAlias(alias) => Some(alias.as_str()),
        _ => None,
    }
}

fn resolve_cargo_config_source_target(
    source_name: &str,
    rewrites: &CargoConfigRewrites,
    config: &config::SloppyJoeConfig,
    seen: &mut std::collections::HashSet<String>,
) -> Result<Option<parsers::cargo_toml::CargoSourceSpec>> {
    if !seen.insert(source_name.to_string()) {
        return Err(cargo_fail(
            checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
            format!(
                "Cargo source replacement cycle detected at source '{}'.",
                source_name
            ),
        ));
    }

    if let Some(definition) = rewrites.source_definitions.get(source_name) {
        return match definition {
            CargoConfigSourceDefinition::Registry(url) => {
                let expected_source = format!("registry+{url}");
                if config
                    .trusted_registries("cargo")
                    .iter()
                    .any(|entry| entry.name == source_name && entry.source == expected_source)
                {
                    Ok(Some(parsers::cargo_toml::CargoSourceSpec::RegistryAlias(
                        source_name.to_string(),
                    )))
                } else {
                    Err(cargo_fail(
                        checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
                        format!(
                            "Cargo source '{}' resolves to registry '{}' but that alias/source pair is not trusted by config.",
                            source_name, expected_source
                        ),
                    ))
                }
            }
            CargoConfigSourceDefinition::Unsupported { kind, detail } => Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Cargo source '{}' uses unsupported {} source '{}'.",
                    source_name, kind, detail
                ),
            )),
        };
    }

    if let Some(target_name) = rewrites.source_replace_with.get(source_name) {
        if rewrites.source_definitions.contains_key(target_name)
            || rewrites.source_replace_with.contains_key(target_name)
        {
            return resolve_cargo_config_source_target(target_name, rewrites, config, seen);
        }
        if config
            .trusted_registries("cargo")
            .iter()
            .any(|entry| entry.name == *target_name)
        {
            return Ok(Some(parsers::cargo_toml::CargoSourceSpec::RegistryAlias(
                target_name.clone(),
            )));
        }
    }

    Ok(None)
}

fn apply_cargo_config_source_rewrite(
    dep: &parsers::cargo_toml::CargoDependencySpec,
    rewrites: &CargoConfigRewrites,
    config: &config::SloppyJoeConfig,
) -> Result<Option<parsers::cargo_toml::CargoSourceSpec>> {
    let Some(source_name) = cargo_config_source_name(&dep.source) else {
        return Ok(None);
    };
    resolve_cargo_config_source_target(
        source_name,
        rewrites,
        config,
        &mut std::collections::HashSet::new(),
    )
}

fn cargo_patch_scope_matches(
    scope: &parsers::cargo_toml::CargoPatchScope,
    source: &parsers::cargo_toml::CargoSourceSpec,
    config: &config::SloppyJoeConfig,
) -> bool {
    match (scope, source) {
        (
            parsers::cargo_toml::CargoPatchScope::CratesIo,
            parsers::cargo_toml::CargoSourceSpec::CratesIo,
        ) => true,
        (
            parsers::cargo_toml::CargoPatchScope::RegistryName(expected),
            parsers::cargo_toml::CargoSourceSpec::RegistryAlias(actual),
        ) => expected == actual,
        (
            parsers::cargo_toml::CargoPatchScope::SourceUrl(expected),
            parsers::cargo_toml::CargoSourceSpec::RegistryIndex(actual),
        ) => cargo_normalize_registry_source(expected) == *actual,
        (
            parsers::cargo_toml::CargoPatchScope::SourceUrl(expected),
            parsers::cargo_toml::CargoSourceSpec::RegistryAlias(alias),
        ) => cargo_registry_source_for_alias(alias, config) == Some(expected.as_str()),
        (
            parsers::cargo_toml::CargoPatchScope::SourceUrl(expected),
            parsers::cargo_toml::CargoSourceSpec::Git { url, .. },
        ) => expected == url,
        (
            parsers::cargo_toml::CargoPatchScope::RegistryName(_),
            parsers::cargo_toml::CargoSourceSpec::CratesIo,
        )
        | (
            parsers::cargo_toml::CargoPatchScope::SourceUrl(_),
            parsers::cargo_toml::CargoSourceSpec::CratesIo,
        )
        | (
            parsers::cargo_toml::CargoPatchScope::CratesIo,
            parsers::cargo_toml::CargoSourceSpec::RegistryAlias(_),
        )
        | (
            parsers::cargo_toml::CargoPatchScope::CratesIo,
            parsers::cargo_toml::CargoSourceSpec::RegistryIndex(_),
        )
        | (
            parsers::cargo_toml::CargoPatchScope::CratesIo,
            parsers::cargo_toml::CargoSourceSpec::Git { .. },
        )
        | (
            parsers::cargo_toml::CargoPatchScope::RegistryName(_),
            parsers::cargo_toml::CargoSourceSpec::RegistryIndex(_),
        )
        | (
            parsers::cargo_toml::CargoPatchScope::RegistryName(_),
            parsers::cargo_toml::CargoSourceSpec::Git { .. },
        )
        | (_, parsers::cargo_toml::CargoSourceSpec::Path(_))
        | (_, parsers::cargo_toml::CargoSourceSpec::Workspace) => false,
    }
}

fn cargo_patch_scope_matches_lockfile_source(
    scope: &parsers::cargo_toml::CargoPatchScope,
    lockfile_source: &str,
    config: &config::SloppyJoeConfig,
) -> bool {
    match scope {
        parsers::cargo_toml::CargoPatchScope::CratesIo => {
            lockfile_source == "registry+https://github.com/rust-lang/crates.io-index"
        }
        parsers::cargo_toml::CargoPatchScope::RegistryName(alias) => {
            cargo_registry_source_for_alias(alias, config)
                .map(|source| lockfile_source == source)
                .unwrap_or(false)
        }
        parsers::cargo_toml::CargoPatchScope::SourceUrl(url) => {
            lockfile_source == format!("registry+{url}")
                || lockfile_source.starts_with(&format!("git+{url}"))
        }
    }
}

fn cargo_rewrite_matches_lockfile_scope(
    rewrite: &EffectiveCargoRewrite,
    lockfile: &toml::Value,
    config: &config::SloppyJoeConfig,
) -> bool {
    let entries = cargo_lockfile_entries(lockfile);
    let has_direct_match = entries.iter().copied().any(|package| {
        let same_name = package.get("name").and_then(|value| value.as_str())
            == Some(rewrite.package_name.as_str());
        if !same_name {
            return false;
        }
        let version_matches = rewrite.replace_version.as_ref().is_none_or(|expected| {
            package.get("version").and_then(|value| value.as_str()) == Some(expected.as_str())
        });
        if !version_matches {
            return false;
        }
        let source_matches = rewrite.replace_source.as_ref().is_none_or(|expected| {
            package
                .get("source")
                .and_then(|value| value.as_str())
                .map(|source| source == expected)
                .unwrap_or(false)
        });
        if !source_matches {
            return false;
        }

        rewrite
            .patch_scope
            .as_ref()
            .and_then(|scope| {
                package
                    .get("source")
                    .and_then(|value| value.as_str())
                    .map(|source| cargo_patch_scope_matches_lockfile_source(scope, source, config))
            })
            .unwrap_or(true)
    });
    if has_direct_match {
        return true;
    }

    if !matches!(
        rewrite.spec.source,
        parsers::cargo_toml::CargoSourceSpec::Path(_)
    ) || (rewrite.replace_source.is_none() && rewrite.patch_scope.is_none())
    {
        return false;
    }

    let has_localized_target = entries.iter().copied().any(|package| {
        let same_name = package.get("name").and_then(|value| value.as_str())
            == Some(rewrite.package_name.as_str());
        if !same_name {
            return false;
        }
        let version_matches = rewrite.replace_version.as_ref().is_none_or(|expected| {
            package.get("version").and_then(|value| value.as_str()) == Some(expected.as_str())
        });
        version_matches
            && package
                .get("source")
                .and_then(|value| value.as_str())
                .is_none()
    });
    if !has_localized_target {
        return false;
    }

    !entries.iter().copied().any(|package| {
        let same_name = package.get("name").and_then(|value| value.as_str())
            == Some(rewrite.package_name.as_str());
        if !same_name {
            return false;
        }
        let version_matches = rewrite.replace_version.as_ref().is_none_or(|expected| {
            package.get("version").and_then(|value| value.as_str()) == Some(expected.as_str())
        });
        version_matches
            && package
                .get("source")
                .and_then(|value| value.as_str())
                .is_some()
    })
}

fn parse_cargo_config_rewrites(config_path: &std::path::Path) -> Result<CargoConfigRewrites> {
    let content = parsers::read_file_limited(config_path, parsers::MAX_MANIFEST_BYTES)?;
    let value = toml::from_str::<toml::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken Cargo config '{}': failed to parse TOML: {}",
            config_path.display(),
            err
        )
    })?;

    let mut rewrites = CargoConfigRewrites::default();
    let config_dir = config_path
        .parent()
        .expect("Cargo config file should always have a parent directory");

    if let Some(paths) = value.get("paths").and_then(|value| value.as_array()) {
        for path in paths {
            let Some(path) = path.as_str() else {
                anyhow::bail!(
                    "Broken Cargo config '{}': paths entries must be strings.",
                    config_path.display()
                );
            };
            let candidate = normalize_filesystem_path(&config_dir.join(path));
            let manifest_path = candidate.join("Cargo.toml");
            if !parsers::path_detected(&manifest_path)? {
                continue;
            }
            if let Some(package_name) = cargo_package_name_from_manifest(&manifest_path)?
                && let Some(existing) = rewrites
                    .local_paths
                    .insert(package_name.clone(), candidate.clone())
                && existing != candidate
            {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                    format!(
                        "Cargo config '{}' declares multiple local path rewrites for crate '{}': '{}' and '{}'. sloppy-joe refuses ambiguous local provenance.",
                        config_path.display(),
                        package_name,
                        existing.display(),
                        candidate.display()
                    ),
                ));
            }
        }
    }

    if let Some(source_table) = value.get("source").and_then(|value| value.as_table()) {
        for (name, entry) in source_table
            .iter()
            .filter_map(|(name, value)| value.as_table().map(|table| (name.as_str(), table)))
        {
            if let Some(alias) = entry.get("replace-with").and_then(|value| value.as_str()) {
                rewrites
                    .source_replace_with
                    .insert(name.to_string(), alias.to_string());
            }
            if let Some(url) = entry.get("registry").and_then(|value| value.as_str()) {
                rewrites.source_definitions.insert(
                    name.to_string(),
                    CargoConfigSourceDefinition::Registry(url.to_string()),
                );
            } else if let Some(path) = entry.get("directory").and_then(|value| value.as_str()) {
                rewrites.source_definitions.insert(
                    name.to_string(),
                    CargoConfigSourceDefinition::Unsupported {
                        kind: "directory".to_string(),
                        detail: path.to_string(),
                    },
                );
            } else if let Some(path) = entry.get("local-registry").and_then(|value| value.as_str())
            {
                rewrites.source_definitions.insert(
                    name.to_string(),
                    CargoConfigSourceDefinition::Unsupported {
                        kind: "local-registry".to_string(),
                        detail: path.to_string(),
                    },
                );
            } else if let Some(url) = entry.get("git").and_then(|value| value.as_str()) {
                rewrites.source_definitions.insert(
                    name.to_string(),
                    CargoConfigSourceDefinition::Unsupported {
                        kind: "git".to_string(),
                        detail: url.to_string(),
                    },
                );
            }
        }
    }

    for rewrite in parsers::cargo_toml::collect_rewrites(config_path, &value, "patch")?
        .into_iter()
        .chain(parsers::cargo_toml::collect_rewrites(
            config_path,
            &value,
            "replace",
        )?)
    {
        rewrites.rewrite_targets.push(EffectiveCargoRewrite {
            package_name: rewrite.package_name,
            patch_scope: rewrite.patch_scope,
            replace_source: rewrite.replace_source,
            replace_version: rewrite.replace_version,
            spec: rewrite.dependency,
            base_dir: config_dir.to_path_buf(),
        });
    }

    Ok(rewrites)
}

fn load_repo_visible_cargo_config_rewrites(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<CargoConfigRewrites> {
    let manifest_dir = manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let canonical_manifest_dir = std::fs::canonicalize(manifest_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", manifest_dir.display(), err))?;
    let trusted_root = cargo_trusted_scope_root(scan_root, manifest_path, config)?;
    let mut rewrites = CargoConfigRewrites::default();

    let mut ancestors = ancestor_dirs_inclusive(&canonical_manifest_dir, &trusted_root)?;
    ancestors.reverse();
    for ancestor in ancestors {
        for config_name in ["config.toml", "config"] {
            let config_path = ancestor.join(".cargo").join(config_name);
            if parsers::path_detected(&config_path)? {
                merge_cargo_config_rewrites(
                    &mut rewrites,
                    parse_cargo_config_rewrites(&config_path)?,
                );
            }
        }
    }

    Ok(rewrites)
}

fn host_local_cargo_home() -> Option<std::path::PathBuf> {
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
        return Some(std::path::PathBuf::from(cargo_home));
    }
    std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
}

fn load_host_local_cargo_config_rewrites_from_home(
    cargo_home: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    let mut rewrites = CargoConfigRewrites::default();
    let mut warnings = Vec::new();
    let mut found = Vec::new();

    for config_name in ["config.toml", "config"] {
        let path = cargo_home.join(config_name);
        if parsers::path_detected(&path)? {
            found.push(path.clone());
            merge_cargo_config_rewrites(&mut rewrites, parse_cargo_config_rewrites(&path)?);
        }
    }

    if found.is_empty() {
        return Ok((rewrites, warnings));
    }

    if !config.allow_host_local_cargo_config {
        return Err(cargo_fail(
            checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
            format!(
                "Found host-local Cargo config outside the repo at {}. sloppy-joe blocks hidden machine-local Cargo provenance by default.",
                found[0].display()
            ),
        ));
    }

    warnings.push(
        Issue::new(
            "<cargo-config>",
            checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
            Severity::Warning,
        )
        .message(format!(
            "Host-local Cargo config '{}' was trusted via a local-only overlay. This run depends on machine-local Cargo provenance and may differ from CI.",
            found[0].display()
        ))
        .fix(
            "Prefer repo-visible Cargo config for reviewed provenance. Keep local-only host Cargo config relaxations out of CI.",
        ),
    );

    Ok((rewrites, warnings))
}

fn load_effective_cargo_config_rewrites_inner(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
    cargo_home_override: Option<&std::path::Path>,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    let mut rewrites = load_repo_visible_cargo_config_rewrites(scan_root, manifest_path, config)?;
    let mut warnings = Vec::new();
    if let Some(cargo_home) = cargo_home_override
        .map(std::path::Path::to_path_buf)
        .or_else(host_local_cargo_home)
    {
        let (host_rewrites, host_warnings) =
            load_host_local_cargo_config_rewrites_from_home(&cargo_home, config)?;
        ensure_additive_cargo_config_rewrites(
            &rewrites,
            &host_rewrites,
            &cargo_home.join("config.toml"),
        )?;
        merge_cargo_config_rewrites(&mut rewrites, host_rewrites);
        warnings.extend(host_warnings);
    }
    Ok((rewrites, warnings))
}

fn load_effective_cargo_config_rewrites(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    load_effective_cargo_config_rewrites_inner(scan_root, manifest_path, config, None)
}

#[cfg(test)]
fn load_effective_cargo_config_rewrites_for_test(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
    cargo_home_override: Option<std::path::PathBuf>,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    load_effective_cargo_config_rewrites_inner(
        scan_root,
        manifest_path,
        config,
        cargo_home_override.as_deref(),
    )
}

#[cfg(test)]
fn cargo_host_local_config_rewrites_for_test(
    home_dir: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    load_host_local_cargo_config_rewrites_from_home(&home_dir.join(".cargo"), config)
}

fn cargo_rewrite_matches(
    rewrite: &EffectiveCargoRewrite,
    dep: &parsers::cargo_toml::CargoDependencySpec,
    config: &config::SloppyJoeConfig,
) -> bool {
    rewrite.package_name == dep.package_name
        && rewrite.replace_source.as_ref().is_none_or(|source| {
            cargo_dependency_source_id(dep, config).as_deref() == Some(source.as_str())
        })
        && rewrite.replace_version.as_ref().is_none_or(|version| {
            cargo_dependency_exact_version(dep).as_deref() == Some(version.as_str())
        })
        && rewrite
            .patch_scope
            .as_ref()
            .is_none_or(|scope| cargo_patch_scope_matches(scope, &dep.source, config))
}

fn cargo_manifest_rewrites(
    manifest: &parsers::cargo_toml::CargoManifest,
    base_dir: &std::path::Path,
) -> Vec<EffectiveCargoRewrite> {
    manifest
        .patches
        .iter()
        .chain(manifest.replaces.iter())
        .map(|rewrite| EffectiveCargoRewrite {
            package_name: rewrite.package_name.clone(),
            patch_scope: rewrite.patch_scope.clone(),
            replace_source: rewrite.replace_source.clone(),
            replace_version: rewrite.replace_version.clone(),
            spec: rewrite.dependency.clone(),
            base_dir: base_dir.to_path_buf(),
        })
        .collect()
}

fn push_effective_cargo_rewrite(
    rewrites: &mut Vec<EffectiveCargoRewrite>,
    candidate: EffectiveCargoRewrite,
) -> Result<()> {
    if let Some(existing) = rewrites.iter().find(|rewrite| {
        rewrite.package_name == candidate.package_name
            && rewrite.patch_scope == candidate.patch_scope
            && rewrite.replace_source == candidate.replace_source
            && rewrite.replace_version == candidate.replace_version
    }) {
        if existing != &candidate {
            return Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Conflicting Cargo rewrite for package '{}' and scope '{:?}'. sloppy-joe refuses to guess rewrite precedence across multiple provenance sources.",
                    candidate.package_name, candidate.patch_scope
                ),
            ));
        }
        return Ok(());
    }

    rewrites.push(candidate);
    Ok(())
}

fn collect_effective_cargo_rewrites(
    scan_root: &std::path::Path,
    manifest: &parsers::cargo_toml::CargoManifest,
    config: &config::SloppyJoeConfig,
    cargo_config_rewrites: &CargoConfigRewrites,
) -> Result<Vec<EffectiveCargoRewrite>> {
    let mut rewrites = Vec::new();
    let manifest_dir = manifest
        .manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    if let Some(workspace_root) =
        find_in_scope_cargo_workspace_root(scan_root, &manifest.manifest_path, config)?
    {
        if workspace_root.manifest_path == manifest.manifest_path {
            for rewrite in cargo_manifest_rewrites(manifest, manifest_dir) {
                push_effective_cargo_rewrite(&mut rewrites, rewrite)?;
            }
        } else {
            let workspace_dir = workspace_root
                .manifest_path
                .parent()
                .expect("workspace root should have a parent directory");
            for rewrite in cargo_manifest_rewrites(&workspace_root, workspace_dir) {
                push_effective_cargo_rewrite(&mut rewrites, rewrite)?;
            }
        }
    } else {
        for rewrite in cargo_manifest_rewrites(manifest, manifest_dir) {
            push_effective_cargo_rewrite(&mut rewrites, rewrite)?;
        }
    }

    for rewrite in cargo_config_rewrites.rewrite_targets.iter().cloned() {
        push_effective_cargo_rewrite(&mut rewrites, rewrite)?;
    }
    Ok(rewrites)
}

fn resolve_cargo_effective_dependencies(
    scan_root: &std::path::Path,
    manifest: &parsers::cargo_toml::CargoManifest,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<EffectiveCargoDependency>> {
    let manifest_dir = manifest
        .manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let cargo_config_rewrites =
        load_effective_cargo_config_rewrites(scan_root, &manifest.manifest_path, config)?.0;
    let rewrites =
        collect_effective_cargo_rewrites(scan_root, manifest, config, &cargo_config_rewrites)?;

    let mut effective = Vec::new();
    for dep in &manifest.dependencies {
        let mut current = dep.clone();
        let mut current_base_dir = manifest_dir.to_path_buf();
        let mut expected_exact_version = cargo_dependency_exact_version(dep);
        let mut workspace_hops = 0usize;

        loop {
            let rewritten = rewrites
                .iter()
                .rfind(|rewrite| cargo_rewrite_matches(rewrite, &current, config));
            if let Some(rewrite) = rewritten {
                let next_expected_exact_version = rewrite
                    .replace_version
                    .clone()
                    .or(expected_exact_version.clone());
                if rewrite.spec != current
                    || rewrite.base_dir != current_base_dir
                    || next_expected_exact_version != expected_exact_version
                {
                    expected_exact_version = next_expected_exact_version;
                    current = rewrite.spec.clone();
                    current_base_dir = rewrite.base_dir.clone();
                }
            }

            if matches!(
                current.source,
                parsers::cargo_toml::CargoSourceSpec::CratesIo
            ) && let Some(path) = cargo_config_rewrites.local_paths.get(&current.package_name)
            {
                current.source =
                    parsers::cargo_toml::CargoSourceSpec::Path(path.display().to_string());
            }
            if let Some(rewritten_source) =
                apply_cargo_config_source_rewrite(&current, &cargo_config_rewrites, config)?
            {
                current.source = rewritten_source;
            }

            if !matches!(
                current.source,
                parsers::cargo_toml::CargoSourceSpec::Workspace
            ) {
                let expected_exact_version =
                    expected_exact_version.or_else(|| cargo_dependency_exact_version(&current));
                effective.push(EffectiveCargoDependency {
                    spec: current,
                    base_dir: current_base_dir,
                    expected_exact_version,
                });
                break;
            }

            if !current.workspace_member_invalid_keys.is_empty() {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
                    format!(
                        "'{}' uses workspace = true with unsupported member-local keys: {}.",
                        current.package_name,
                        current.workspace_member_invalid_keys.join(", ")
                    ),
                ));
            }
            let Some(workspace_root) =
                find_in_scope_cargo_workspace_root(scan_root, &manifest.manifest_path, config)?
            else {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
                    format!(
                        "'{}' uses workspace = true but no in-scope workspace root was found.",
                        current.package_name
                    ),
                ));
            };
            let Some(inherited) = workspace_root
                .workspace_dependencies
                .get(&current.package_name)
                .cloned()
            else {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
                    format!(
                        "'{}' uses workspace = true but the nearest in-scope [workspace.dependencies] entry is missing.",
                        current.package_name
                    ),
                ));
            };
            let workspace_dir = workspace_root
                .manifest_path
                .parent()
                .expect("workspace root should have a parent directory");
            expected_exact_version =
                expected_exact_version.or_else(|| cargo_dependency_exact_version(&inherited));
            current = inherited;
            current_base_dir = workspace_dir.to_path_buf();
            workspace_hops += 1;
            if workspace_hops > 8 {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
                    format!(
                        "'{}' exceeded Cargo workspace inheritance resolution depth.",
                        dep.package_name
                    ),
                ));
            }
        }
    }

    Ok(effective)
}

fn cargo_allowlisted_local_target(
    scan_root: &std::path::Path,
    target: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<bool> {
    let canonical_target = std::fs::canonicalize(target)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", target.display(), err))?;
    let canonical_root = std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))?;
    if canonical_target.starts_with(&canonical_root) {
        return Ok(true);
    }

    for allowlisted in config.trusted_local_paths("cargo") {
        let candidate = normalize_filesystem_path(std::path::Path::new(allowlisted));
        let Ok(canonical_allowlisted) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if canonical_allowlisted == canonical_target {
            return Ok(true);
        }
    }

    Ok(false)
}

fn cargo_local_target_manifest(
    scan_root: &std::path::Path,
    manifest_dir: &std::path::Path,
    path: &str,
    expected_package_name: &str,
    config: &config::SloppyJoeConfig,
) -> Result<Option<std::path::PathBuf>> {
    let candidate = normalize_filesystem_path(&manifest_dir.join(path));
    let allowlisted = match cargo_allowlisted_local_target(scan_root, &candidate, config) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if !allowlisted {
        return Ok(None);
    }

    let Ok(canonical_target) = std::fs::canonicalize(&candidate) else {
        return Ok(None);
    };
    let manifest_path = canonical_target.join("Cargo.toml");
    if !parsers::path_detected(&manifest_path)? {
        return Ok(None);
    }
    if cargo_package_name_from_manifest(&manifest_path)?.as_deref() != Some(expected_package_name) {
        return Ok(None);
    }

    Ok(Some(manifest_path))
}

fn validate_cargo_local_target(
    scan_root: &std::path::Path,
    manifest_dir: &std::path::Path,
    dep: &parsers::cargo_toml::CargoDependencySpec,
    path: &str,
    expected_exact_version: Option<&str>,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let candidate = normalize_filesystem_path(&manifest_dir.join(path));
    let allowlisted = cargo_allowlisted_local_target(scan_root, &candidate, config)?;
    if !allowlisted {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' resolves to '{}' which is outside the scan root and not exactly allowlisted.",
                dep.package_name,
                candidate.display()
            ),
        ));
    }

    let canonical_target = std::fs::canonicalize(&candidate).map_err(|err| {
        cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' but that target is missing or unreadable: {}.",
                dep.package_name,
                candidate.display(),
                err
            ),
        )
    })?;

    let manifest_path = canonical_target.join("Cargo.toml");
    if !parsers::path_detected(&manifest_path)? {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' which is not a valid Cargo crate directory.",
                dep.package_name,
                canonical_target.display()
            ),
        ));
    }

    let manifest_value = toml::from_str::<toml::Value>(&parsers::read_file_limited(
        &manifest_path,
        parsers::MAX_MANIFEST_BYTES,
    )?)
    .map_err(|err| {
        cargo_fail(
            checks::names::RESOLUTION_PARSE_FAILED,
            format!(
                "Failed to parse local Cargo target '{}': {}.",
                manifest_path.display(),
                err
            ),
        )
    })?;

    if manifest_value
        .get("package")
        .and_then(|value| value.as_table())
        .is_none()
    {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' but that target does not declare a [package] crate.",
                dep.package_name,
                canonical_target.display()
            ),
        ));
    }

    let actual_name = manifest_value
        .get("package")
        .and_then(|value| value.as_table())
        .and_then(|package| package.get("name"))
        .and_then(|value| value.as_str());
    if actual_name != Some(dep.package_name.as_str()) {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' but that target declares package '{}' instead of '{}'.",
                dep.package_name,
                canonical_target.display(),
                actual_name.unwrap_or("<missing>"),
                dep.package_name
            ),
        ));
    }

    let actual_version = manifest_value
        .get("package")
        .and_then(|value| value.as_table())
        .and_then(|package| package.get("version"))
        .and_then(|value| value.as_str());
    if let Some(expected_version) = expected_exact_version
        && actual_version != Some(expected_version)
    {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' but that target declares version '{}' instead of '{}'.",
                dep.package_name,
                canonical_target.display(),
                actual_version.unwrap_or("<missing>"),
                expected_version
            ),
        ));
    }

    Ok(())
}

fn validate_cargo_registry_source(
    dep: &parsers::cargo_toml::CargoDependencySpec,
    expected_exact_version: Option<&str>,
    alias: Option<&str>,
    source: &str,
    lockfile: &toml::Value,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let trusted = if let Some(alias) = alias {
        config
            .trusted_registries("cargo")
            .iter()
            .any(|entry| entry.name == alias && entry.source == source)
    } else {
        source == "registry+https://github.com/rust-lang/crates.io-index"
            || config
                .trusted_registries("cargo")
                .iter()
                .any(|entry| entry.source == source)
    };

    if !trusted {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
            format!(
                "'{}' uses registry source '{}' which is not trusted by config.",
                dep.package_name, source
            ),
        ));
    }

    let exact_version = expected_exact_version
        .map(str::to_string)
        .or_else(|| cargo_dependency_exact_version(dep));
    let matched = cargo_lockfile_entries(lockfile).into_iter().any(|package| {
        let same_name =
            package.get("name").and_then(|value| value.as_str()) == Some(dep.package_name.as_str());
        let same_source = package.get("source").and_then(|value| value.as_str()) == Some(source);
        let version_ok = exact_version.as_ref().is_none_or(|expected| {
            package
                .get("version")
                .and_then(|value| value.as_str())
                .is_some_and(|actual| cargo_registry_versions_match(expected, actual))
        });
        same_name && same_source && version_ok
    });

    if !matched {
        return Err(cargo_fail(
            checks::names::RESOLUTION_MISSING_LOCKFILE_ENTRY,
            format!(
                "Cargo.lock did not prove a trusted registry entry for '{}' with source '{}'.",
                dep.package_name, source
            ),
        ));
    }

    Ok(())
}

fn cargo_registry_versions_match(expected: &str, actual: &str) -> bool {
    expected == actual || strip_cargo_build_metadata(expected) == strip_cargo_build_metadata(actual)
}

fn strip_cargo_build_metadata(version: &str) -> &str {
    version.split_once('+').map_or(version, |(base, _)| base)
}

fn validate_cargo_git_source(
    dep: &parsers::cargo_toml::CargoDependencySpec,
    expected_exact_version: Option<&str>,
    source: &parsers::cargo_toml::CargoSourceSpec,
    lockfile: &toml::Value,
    config: &config::SloppyJoeConfig,
) -> Result<Issue> {
    let parsers::cargo_toml::CargoSourceSpec::Git {
        url,
        rev,
        branch,
        tag,
    } = source
    else {
        unreachable!("validate_cargo_git_source must only be called for git specs");
    };
    if config.cargo_git_policy != config::CargoGitPolicy::WarnPinned {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "'{}' uses git source '{}' but cargo_git_policy blocks git dependencies by default.",
                dep.package_name, url
            ),
        ));
    }
    if branch.is_some() || tag.is_some() || rev.is_none() {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "'{}' must pin git dependencies to an exact rev; branch, tag, or unspecified refs are not allowed.",
                dep.package_name
            ),
        ));
    }
    let rev = rev.as_deref().expect("checked above");
    let is_exact_rev = rev.len() == 40
        && rev
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !is_exact_rev {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "'{}' uses git rev '{}' which is not a full lowercase 40-character commit SHA.",
                dep.package_name, rev
            ),
        ));
    }
    if !config
        .trusted_git_sources("cargo")
        .iter()
        .any(|trusted| trusted.trim() == url.trim())
    {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "'{}' uses git source '{}' which is not allowlisted.",
                dep.package_name, url
            ),
        ));
    }

    let expected_source = format!("git+{url}?rev={rev}#{rev}");
    let matched = cargo_lockfile_entries(lockfile).into_iter().any(|package| {
        package.get("name").and_then(|value| value.as_str()) == Some(dep.package_name.as_str())
            && package.get("source").and_then(|value| value.as_str())
                == Some(expected_source.as_str())
            && expected_exact_version.is_none_or(|expected| {
                package.get("version").and_then(|value| value.as_str()) == Some(expected)
            })
    });
    if !matched {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "Cargo.lock did not prove the exact git repo and commit for '{}' as '{}'.",
                dep.package_name, expected_source
            ),
        ));
    }

    Ok(
        Issue::new(
            &dep.package_name,
            checks::names::RESOLUTION_REDUCED_CONFIDENCE_GIT,
            Severity::Warning,
        )
        .message(format!(
            "'{}' uses an allowlisted git dependency pinned to exact rev {} from '{}'. sloppy-joe continues in reduced-confidence mode because git provenance is outside normal registry trust.",
            dep.package_name, rev, url
        ))
        .fix(
            "Prefer a reviewed registry release when available. If git is required, keep the repo URL and exact revision under explicit review.",
        ),
    )
}

fn validate_cargo_dependency_spec(
    scan_root: &std::path::Path,
    manifest_dir: &std::path::Path,
    dep: &parsers::cargo_toml::CargoDependencySpec,
    expected_exact_version: Option<&str>,
    config: &config::SloppyJoeConfig,
    lockfile: &toml::Value,
) -> Result<Vec<Issue>> {
    match &dep.source {
        parsers::cargo_toml::CargoSourceSpec::CratesIo => validate_cargo_registry_source(
            dep,
            expected_exact_version,
            None,
            "registry+https://github.com/rust-lang/crates.io-index",
            lockfile,
            config,
        )
        .map(|_| Vec::new()),
        parsers::cargo_toml::CargoSourceSpec::Path(path) => {
            validate_cargo_local_target(
                scan_root,
                manifest_dir,
                dep,
                path,
                expected_exact_version,
                config,
            )?;
            Ok(Vec::new())
        }
        parsers::cargo_toml::CargoSourceSpec::RegistryAlias(alias) => {
            let Some(source) = config
                .trusted_registries("cargo")
                .iter()
                .find(|entry| entry.name == *alias)
                .map(|entry| entry.source.as_str())
            else {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
                    format!(
                        "'{}' uses registry alias '{}' which is not trusted by config.",
                        dep.package_name, alias
                    ),
                ));
            };
            validate_cargo_registry_source(
                dep,
                expected_exact_version,
                Some(alias),
                source,
                lockfile,
                config,
            )?;
            Ok(Vec::new())
        }
        parsers::cargo_toml::CargoSourceSpec::RegistryIndex(source) => {
            validate_cargo_registry_source(
                dep,
                expected_exact_version,
                None,
                source,
                lockfile,
                config,
            )?;
            Ok(Vec::new())
        }
        parsers::cargo_toml::CargoSourceSpec::Git { .. } => {
            validate_cargo_git_source(dep, expected_exact_version, &dep.source, lockfile, config)
                .map(|issue| vec![issue])
        }
        parsers::cargo_toml::CargoSourceSpec::Workspace => Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' uses workspace = true but no in-scope workspace dependency was resolved.",
                dep.package_name
            ),
        )),
    }
}

fn validate_cargo_effective_rewrite(
    scan_root: &std::path::Path,
    rewrite: &EffectiveCargoRewrite,
    config: &config::SloppyJoeConfig,
    lockfile: &toml::Value,
) -> Result<Vec<Issue>> {
    let exact_version = cargo_dependency_exact_version(&rewrite.spec);
    let expected_version = rewrite
        .replace_version
        .as_deref()
        .or(exact_version.as_deref());
    match &rewrite.spec.source {
        parsers::cargo_toml::CargoSourceSpec::Path(path) => {
            validate_cargo_local_target(
                scan_root,
                &rewrite.base_dir,
                &rewrite.spec,
                path,
                expected_version,
                config,
            )?;
            Ok(Vec::new())
        }
        _ => validate_cargo_dependency_spec(
            scan_root,
            &rewrite.base_dir,
            &rewrite.spec,
            expected_version,
            config,
            lockfile,
        ),
    }
}

fn validate_cargo_source_policy(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Issue>> {
    let manifest = parsers::cargo_toml::parse_manifest_file(&spec.manifest_path)?;
    let authoritative_lockfile =
        authoritative_cargo_lockfile_path(scan_root, &spec.manifest_path, config)?;
    ensure_lockfile_readable(
        &authoritative_lockfile,
        spec.kind.missing_lockfile_help().unwrap(),
    )?;
    let lockfile = cargo_lockfile_value(&authoritative_lockfile)?;
    let (cargo_config_rewrites, config_warnings) =
        load_effective_cargo_config_rewrites(scan_root, &spec.manifest_path, config)?;
    let rewrites =
        collect_effective_cargo_rewrites(scan_root, &manifest, config, &cargo_config_rewrites)?;
    let mut warnings = config_warnings;

    for dep in resolve_cargo_effective_dependencies(scan_root, &manifest, config)? {
        let dep_warnings = validate_cargo_dependency_spec(
            scan_root,
            &dep.base_dir,
            &dep.spec,
            dep.expected_exact_version.as_deref(),
            config,
            &lockfile,
        )?;
        warnings.extend(dep_warnings);
    }

    for rewrite in rewrites
        .into_iter()
        .filter(|rewrite| cargo_rewrite_matches_lockfile_scope(rewrite, &lockfile, config))
    {
        warnings.extend(validate_cargo_effective_rewrite(
            scan_root, &rewrite, config, &lockfile,
        )?);
    }

    Ok(warnings)
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
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    npm_manifest: Option<&serde_json::Value>,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let project_dir = spec.project_dir();

    match spec.kind {
        ProjectInputKind::Npm => {
            let manifest = npm_manifest.expect("npm manifests should be parsed during preflight");
            match spec
                .js_binding
                .as_ref()
                .map(|binding| binding.manager)
                .unwrap_or(JsPackageManager::Npm)
            {
                JsPackageManager::Npm => {
                    let path = selected_lockfile_path(spec)
                        .expect("npm preflight should guarantee a lockfile exists");
                    let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
                    let lockfile =
                        serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
                            anyhow::anyhow!(
                                "Broken lockfile '{}': failed to parse JSON: {}",
                                path.display(),
                                err
                            )
                        })?;
                    validate_npm_lockfile_version(&lockfile, &path, config)?;
                    validate_npm_lockfile_consistency(
                        manifest,
                        &lockfile,
                        &path,
                        spec.npm_lockfile_package_key(),
                    )?;
                    validate_npm_lockfile_provenance(
                        &lockfile,
                        &path,
                        &std::collections::HashMap::new(),
                    )?;
                }
                JsPackageManager::Pnpm => {
                    let _ = read_validated_pnpm_lockfile(spec, manifest)?;
                }
                JsPackageManager::Bun => {
                    let _ = read_validated_bun_lockfile(spec, manifest)?;
                }
                JsPackageManager::Yarn => {
                    let _ = read_validated_yarn_lockfile(spec, manifest)?;
                }
            }
        }
        ProjectInputKind::Cargo => {
            let path = authoritative_cargo_lockfile_path(scan_root, &spec.manifest_path, config)?;
            cargo_lockfile_value(&path)?;
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
        ProjectInputKind::PyProjectUv => {
            let deps = parsers::pyproject_toml::parse_legacy_file(&spec.manifest_path)?;
            let _ = read_validated_uv_lockfile(spec, &deps)?;
        }
        ProjectInputKind::PyRequirementsTrusted => {}
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
    manager: JsPackageManager,
}

fn validate_workspace_npm_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
    npm_index: &NpmProjectIndex,
) -> Result<std::path::PathBuf> {
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
        1 => Ok(matching_dirs[0].clone()),
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

fn validate_workspace_pnpm_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let Some(workspace_root) = find_pnpm_workspace_root(scan_root, canonical_project_dir)? else {
        anyhow::bail!(
            "Local pnpm dependency '{}' in '{}' uses workspace:, but no ancestor pnpm-workspace.yaml with a matching packages declaration was found. Scan the workspace root, or replace the workspace reference with a dependency source sloppy-joe can verify exactly.",
            dep_name,
            spec.manifest_path.display()
        );
    };

    let matching_dirs = workspace_manifest_paths(&workspace_root)?
        .into_iter()
        .filter_map(|manifest_path| {
            let project_dir = manifest_path.parent()?.to_path_buf();
            let canonical_dir = std::fs::canonicalize(&project_dir).ok()?;
            if canonical_dir == canonical_project_dir {
                return None;
            }
            let manifest = read_npm_manifest_value(&manifest_path).ok()?;
            let name = manifest.get("name").and_then(|value| value.as_str())?;
            (name == dep_name).then_some(canonical_dir)
        })
        .collect::<Vec<_>>();

    match matching_dirs.len() {
        1 => Ok(matching_dirs[0].clone()),
        0 => anyhow::bail!(
            "Local pnpm dependency '{}' in '{}' does not resolve to any workspace package declared by '{}'. Keep workspace targets inside pnpm-workspace.yaml, or remove the workspace reference.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root
                .project_dir
                .join("pnpm-workspace.yaml")
                .display()
        ),
        _ => anyhow::bail!(
            "Local pnpm dependency '{}' in '{}' resolves ambiguously to multiple workspace packages declared by '{}'. Each pnpm workspace package name must be unique.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root
                .project_dir
                .join("pnpm-workspace.yaml")
                .display()
        ),
    }
}

fn validate_workspace_bun_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let Some(workspace_root) = find_bun_workspace_root(scan_root, canonical_project_dir)? else {
        anyhow::bail!(
            "Local Bun dependency '{}' in '{}' uses workspace:, but no ancestor Bun workspace root with a matching workspaces declaration was found. Scan the workspace root, or replace the workspace reference with a dependency source sloppy-joe can verify exactly.",
            dep_name,
            spec.manifest_path.display()
        );
    };

    let matching_dirs = workspace_manifest_paths(&workspace_root)?
        .into_iter()
        .filter_map(|manifest_path| {
            let project_dir = manifest_path.parent()?.to_path_buf();
            let canonical_dir = std::fs::canonicalize(&project_dir).ok()?;
            if canonical_dir == canonical_project_dir {
                return None;
            }
            let manifest = read_npm_manifest_value(&manifest_path).ok()?;
            let name = manifest.get("name").and_then(|value| value.as_str())?;
            (name == dep_name).then_some(canonical_dir)
        })
        .collect::<Vec<_>>();

    match matching_dirs.len() {
        1 => Ok(matching_dirs[0].clone()),
        0 => anyhow::bail!(
            "Local Bun dependency '{}' in '{}' does not resolve to any workspace package declared by '{}'. Keep workspace targets inside the Bun workspaces set, or remove the workspace reference.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
        _ => anyhow::bail!(
            "Local Bun dependency '{}' in '{}' resolves ambiguously to multiple workspace packages declared by '{}'. Each Bun workspace package name must be unique within the workspace root.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
    }
}

fn validate_workspace_yarn_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let Some(workspace_root) = find_yarn_workspace_root(scan_root, canonical_project_dir)? else {
        anyhow::bail!(
            "Local Yarn dependency '{}' in '{}' uses workspace:, but no ancestor Yarn workspace root with a matching workspaces declaration was found. Scan the workspace root, or replace the workspace reference with a dependency source sloppy-joe can verify exactly.",
            dep_name,
            spec.manifest_path.display()
        );
    };

    let matching_dirs = workspace_manifest_paths(&workspace_root)?
        .into_iter()
        .filter_map(|manifest_path| {
            let project_dir = manifest_path.parent()?.to_path_buf();
            let canonical_dir = std::fs::canonicalize(&project_dir).ok()?;
            if canonical_dir == canonical_project_dir {
                return None;
            }
            let manifest = read_npm_manifest_value(&manifest_path).ok()?;
            let name = manifest.get("name").and_then(|value| value.as_str())?;
            (name == dep_name).then_some(canonical_dir)
        })
        .collect::<Vec<_>>();

    match matching_dirs.len() {
        1 => Ok(matching_dirs[0].clone()),
        0 => anyhow::bail!(
            "Local Yarn dependency '{}' in '{}' does not resolve to any workspace package declared by '{}'. Keep workspace targets inside the Yarn workspaces set, or remove the workspace reference.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
        _ => anyhow::bail!(
            "Local Yarn dependency '{}' in '{}' resolves ambiguously to multiple workspace packages declared by '{}'. Each Yarn workspace package name must be unique within the workspace root.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
    }
}

fn find_pnpm_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    Ok(find_js_workspace_root(scan_root, canonical_project_dir)?
        .filter(|root| root.manager == JsPackageManager::Pnpm))
}

fn find_yarn_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    Ok(find_js_workspace_root(scan_root, canonical_project_dir)?
        .filter(|root| root.manager == JsPackageManager::Yarn))
}

fn find_bun_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    Ok(find_js_workspace_root(scan_root, canonical_project_dir)?
        .filter(|root| root.manager == JsPackageManager::Bun))
}

fn find_npm_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    Ok(find_js_workspace_root(scan_root, canonical_project_dir)?
        .filter(|root| root.manager == JsPackageManager::Npm))
}

fn find_js_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    for ancestor_dir in ancestor_dirs_inclusive(canonical_project_dir, scan_root)? {
        let manifest_path = ancestor_dir.join("package.json");
        if parsers::path_detected(&manifest_path)? {
            let manifest = read_npm_manifest_value(&manifest_path)?;
            let manager = detect_js_manager(&ancestor_dir, &manifest_path, &manifest)?;
            let Some(patterns) =
                parse_js_workspace_patterns(&ancestor_dir, &manifest_path, &manifest, manager)?
            else {
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
                    project_dir: ancestor_dir.clone(),
                    patterns,
                    manager,
                }));
            }
        }

        let pnpm_workspace_path = ancestor_dir.join("pnpm-workspace.yaml");
        if !parsers::path_detected(&pnpm_workspace_path)? {
            continue;
        }
        let Some(patterns) = parse_pnpm_workspaces(&ancestor_dir)? else {
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
                manifest_path: pnpm_workspace_path,
                project_dir: ancestor_dir,
                patterns,
                manager: JsPackageManager::Pnpm,
            }));
        }
    }

    Ok(None)
}

fn parse_js_workspace_patterns(
    workspace_dir: &std::path::Path,
    manifest_path: &std::path::Path,
    manifest: &serde_json::Value,
    manager: JsPackageManager,
) -> Result<Option<Vec<String>>> {
    match manager {
        JsPackageManager::Npm => parse_npm_workspaces(manifest_path, manifest),
        JsPackageManager::Pnpm => parse_pnpm_workspaces(workspace_dir),
        JsPackageManager::Yarn | JsPackageManager::Bun => {
            parse_npm_workspaces(manifest_path, manifest)
        }
    }
}

fn parse_pnpm_workspaces(workspace_dir: &std::path::Path) -> Result<Option<Vec<String>>> {
    let path = workspace_dir.join("pnpm-workspace.yaml");
    if !parsers::path_detected(&path)? {
        return Ok(None);
    }
    let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
    let value: serde_yaml::Value = serde_yaml::from_str(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken manifest '{}': failed to parse YAML: {}",
            path.display(),
            err
        )
    })?;
    let packages = value
        .get("packages")
        .and_then(|value| value.as_sequence())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Broken manifest '{}': packages must be an array of strings.",
                path.display()
            )
        })?;
    let mut patterns = Vec::with_capacity(packages.len());
    for entry in packages {
        let Some(pattern) = entry.as_str() else {
            anyhow::bail!(
                "Broken manifest '{}': packages entries must be strings.",
                path.display()
            );
        };
        patterns.push(pattern.to_string());
    }
    Ok(Some(patterns))
}

fn workspace_manifest_paths(workspace_root: &WorkspaceRoot) -> Result<Vec<std::path::PathBuf>> {
    let root = std::fs::canonicalize(&workspace_root.project_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            workspace_root.project_dir.display(),
            err
        )
    })?;
    let mut visited = std::collections::HashSet::new();
    let mut specs = Vec::new();
    walk_project_tree(
        &workspace_root.project_dir,
        &root,
        &mut visited,
        &mut specs,
        false,
    )?;
    Ok(specs
        .into_iter()
        .filter(|spec| {
            spec.kind == ProjectInputKind::Npm
                && workspace_patterns_match(
                    &workspace_root.project_dir,
                    spec.project_dir(),
                    workspace_root.patterns.iter().map(String::as_str),
                )
        })
        .map(|spec| spec.manifest_path)
        .collect())
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

fn npm_lockfile_version(lockfile: &serde_json::Value) -> u64 {
    lockfile
        .get("lockfileVersion")
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
}

fn npm_registry_tarball_path(resolved: &str) -> Option<&str> {
    let resolved = resolved.trim();
    let resolved = resolved.strip_prefix("https://").unwrap_or(resolved);
    resolved.strip_prefix("registry.npmjs.org/")
}

fn expected_npm_registry_tarball_paths(package_name: &str, version: &str) -> Vec<String> {
    if let Some((scope, leaf)) = package_name.split_once('/')
        && let Some(scope_name) = scope.strip_prefix('@')
    {
        let filename = format!("{leaf}-{version}.tgz");
        return vec![
            format!("{package_name}/-/{filename}"),
            format!("%40{scope_name}%2F{leaf}/-/{filename}"),
            format!("%40{scope_name}%2f{leaf}/-/{filename}"),
        ];
    }

    vec![format!("{package_name}/-/{}-{version}.tgz", package_name)]
}

fn validate_npm_resolved_identity(
    package_name: &str,
    version: &str,
    resolved: &str,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    let Some(path) = npm_registry_tarball_path(resolved) else {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has untrusted resolved source '{}'. sloppy-joe only trusts npm registry tarball URLs in package-lock.json and npm-shrinkwrap.json.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolved)
        );
    };

    if !expected_npm_registry_tarball_paths(package_name, version)
        .iter()
        .any(|expected| expected == path)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' resolves to '{}', which does not match the locked package identity '{}' at version '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolved),
            package_name,
            version
        );
    }

    Ok(())
}

fn validate_npm_lockfile_version(
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let version = npm_lockfile_version(lockfile);

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

fn ensure_authoritative_js_lockfile_readable(spec: &ProjectInputSpec) -> Result<()> {
    let help = js_lockfile_help(spec);
    let Some(binding) = &spec.js_binding else {
        return ensure_one_lockfile_readable(
            spec.project_dir(),
            &["npm-shrinkwrap.json", "package-lock.json"],
            &help,
        );
    };
    let root_dir = binding
        .root_manifest_path
        .parent()
        .expect("package.json should always have a parent directory");
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;
    let canonical_root_dir = std::fs::canonicalize(root_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", root_dir.display(), err))?;
    let shadow_lockfile = if canonical_project_dir != canonical_root_dir {
        first_existing_lockfile(
            spec.project_dir(),
            &[
                "npm-shrinkwrap.json",
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "bun.lock",
                "bun.lockb",
            ],
        )
    } else {
        None
    };
    if let Some(shadow) = shadow_lockfile {
        anyhow::bail!(
            "Found shadow JS lockfile '{}' under workspace project '{}'. The authoritative {} lockfile lives at '{}'. Remove the child lockfile and keep the workspace root lockfile as the single source of truth.",
            shadow.display(),
            spec.manifest_path.display(),
            binding.manager.as_str(),
            binding
                .lockfile_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<missing>".to_string())
        );
    }
    let Some(path) = &binding.lockfile_path else {
        let expected = match binding.manager {
            JsPackageManager::Npm => "'npm-shrinkwrap.json' or 'package-lock.json'",
            JsPackageManager::Pnpm => "'pnpm-lock.yaml'",
            JsPackageManager::Yarn => "'yarn.lock'",
            JsPackageManager::Bun => "'bun.lock' or 'bun.lockb'",
        };
        anyhow::bail!(
            "Required lockfile {} is missing for {} project '{}'. Fix: {}",
            expected,
            binding.manager.as_str(),
            spec.manifest_path.display(),
            help
        );
    };
    ensure_lockfile_readable(path, &help)
}

fn validate_npm_lockfile_consistency(
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
    package_entry_key: &str,
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

    let package_entry = lockfile
        .get("packages")
        .and_then(|packages| packages.get(package_entry_key))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    if package_entry.is_object() {
        for (section, manifest_entries) in &manifest_sections {
            let lock_entries = section_map(&package_entry, section);
            if *manifest_entries != lock_entries {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: package entry '{}' does not match its '{}' declarations. Regenerate the lockfile so it matches the manifest exactly.",
                    lockfile_path.display(),
                    if package_entry_key.is_empty() {
                        "<root>"
                    } else {
                        package_entry_key
                    },
                    section,
                );
            }
        }
    } else {
        if !package_entry_key.is_empty() {
            anyhow::bail!(
                "Required lockfile '{}' is missing workspace package entry '{}'. Regenerate the lockfile from the npm workspace root so it records this project explicitly.",
                lockfile_path.display(),
                package_entry_key
            );
        }
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

fn validate_pnpm_lockfile_consistency(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_yaml::Value,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    use std::collections::BTreeMap;

    fn manifest_section_map(value: &serde_json::Value, section: &str) -> BTreeMap<String, String> {
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

    fn importer_section_map(
        importer: &serde_yaml::Value,
        section: &str,
    ) -> Result<BTreeMap<String, String>> {
        let Some(entries) = importer.get(section) else {
            return Ok(BTreeMap::new());
        };
        let Some(entries) = entries.as_mapping() else {
            anyhow::bail!(
                "Broken lockfile importer section '{}': expected a mapping of dependencies.",
                section
            );
        };
        let mut out = BTreeMap::new();
        for (name, value) in entries {
            let Some(name) = name.as_str() else {
                anyhow::bail!(
                    "Broken lockfile importer section '{}': dependency names must be strings.",
                    section
                );
            };
            let specifier = value
                .get("specifier")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken lockfile importer section '{}': dependency '{}' is missing its specifier.",
                        section,
                        name
                    )
                })?;
            out.insert(name.to_string(), specifier.to_string());
        }
        Ok(out)
    }

    let importer_key = spec
        .js_binding
        .as_ref()
        .map(|binding| binding.package_entry_key.as_str())
        .unwrap_or(".");
    let importer = lockfile
        .get("importers")
        .and_then(|value| value.get(importer_key))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is missing importer '{}'. Regenerate pnpm-lock.yaml from the workspace root so it records this project explicitly.",
                lockfile_path.display(),
                importer_key
            )
        })?;

    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let manifest_entries = manifest_section_map(manifest, section);
        let lock_entries = importer_section_map(importer, section)?;
        if manifest_entries != lock_entries {
            anyhow::bail!(
                "Required lockfile '{}' is out of sync with package.json: importer '{}' does not match its '{}' declarations. Regenerate pnpm-lock.yaml so it matches the manifest exactly.",
                lockfile_path.display(),
                importer_key,
                section
            );
        }
    }

    Ok(())
}

fn validate_bun_lockfile_consistency(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    use std::collections::BTreeMap;

    fn manifest_section_map(value: &serde_json::Value, section: &str) -> BTreeMap<String, String> {
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

    fn workspace_section_map(
        workspace: &serde_json::Value,
        section: &str,
    ) -> Result<BTreeMap<String, String>> {
        let Some(entries) = workspace.get(section) else {
            return Ok(BTreeMap::new());
        };
        let Some(entries) = entries.as_object() else {
            anyhow::bail!(
                "Broken lockfile workspace section '{}': expected a mapping of dependencies.",
                section
            );
        };
        let mut out = BTreeMap::new();
        for (name, value) in entries {
            let Some(specifier) = value.as_str() else {
                anyhow::bail!(
                    "Broken lockfile workspace section '{}': dependency '{}' must have a string specifier.",
                    section,
                    name
                );
            };
            out.insert(name.to_string(), specifier.to_string());
        }
        Ok(out)
    }

    let workspace_key = spec
        .js_binding
        .as_ref()
        .map(|binding| binding.package_entry_key.as_str())
        .unwrap_or("");
    let workspace = lockfile
        .get("workspaces")
        .and_then(|value| value.get(workspace_key))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is missing workspace '{}'. Regenerate bun.lock from the workspace root so it records this project explicitly.",
                lockfile_path.display(),
                if workspace_key.is_empty() {
                    "<root>"
                } else {
                    workspace_key
                }
            )
        })?;

    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let manifest_entries = manifest_section_map(manifest, section);
        let lock_entries = workspace_section_map(workspace, section)?;
        if manifest_entries != lock_entries {
            anyhow::bail!(
                "Required lockfile '{}' is out of sync with package.json: workspace '{}' does not match its '{}' declarations. Regenerate bun.lock so it matches the manifest exactly.",
                lockfile_path.display(),
                if workspace_key.is_empty() {
                    "<root>"
                } else {
                    workspace_key
                },
                section
            );
        }
    }

    Ok(())
}

fn pnpm_importer_entry<'a>(importer: &'a serde_yaml::Value, dep_name: &str) -> Option<&'a str> {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let version = importer
            .get(section)
            .and_then(|value| value.get(dep_name))
            .and_then(|value| value.get("version"))
            .and_then(|value| value.as_str());
        if version.is_some() {
            return version;
        }
    }
    None
}

fn validate_npm_lockfile_provenance(
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
    allowed_alias_targets: &std::collections::HashMap<String, String>,
) -> Result<()> {
    if let Some(packages) = lockfile.get("packages").and_then(|value| value.as_object()) {
        for (key, entry) in packages {
            validate_npm_lockfile_package_entry(key, entry, lockfile_path, allowed_alias_targets)?;
        }
        return Ok(());
    }

    if let Some(dependencies) = lockfile
        .get("dependencies")
        .and_then(|value| value.as_object())
    {
        validate_npm_lockfile_dependency_entries(
            dependencies,
            lockfile_path,
            allowed_alias_targets,
        )?;
    }

    Ok(())
}

fn validate_npm_lockfile_package_entry(
    key: &str,
    entry: &serde_json::Value,
    lockfile_path: &std::path::Path,
    allowed_alias_targets: &std::collections::HashMap<String, String>,
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
    if !key.contains("node_modules/") {
        return Ok(());
    }
    let expected_name = key
        .rsplit_once("node_modules/")
        .map(|(_, name)| name)
        .unwrap_or(key);
    let locked_name = entry.get("name").and_then(|value| value.as_str());
    let allowed_alias_target = allowed_alias_targets.get(expected_name).map(String::as_str);
    if let Some(locked_name) = locked_name
        && locked_name != expected_name
        && Some(locked_name) != allowed_alias_target
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' claims to be '{}'. npm lockfile entries must match the package they install exactly.",
            lockfile_path.display(),
            expected_name,
            locked_name
        );
    }
    validate_npm_lockfile_entry_fields(locked_name.unwrap_or(expected_name), entry, lockfile_path)
}

fn validate_npm_lockfile_dependency_entries(
    dependencies: &serde_json::Map<String, serde_json::Value>,
    lockfile_path: &std::path::Path,
    allowed_alias_targets: &std::collections::HashMap<String, String>,
) -> Result<()> {
    for (name, entry) in dependencies {
        let Some(entry) = entry.as_object() else {
            anyhow::bail!(
                "Broken lockfile '{}': dependency entry '{}' was not an object.",
                lockfile_path.display(),
                name
            );
        };
        let locked_name = entry.get("name").and_then(|value| value.as_str());
        let allowed_alias_target = allowed_alias_targets.get(name).map(String::as_str);
        if let Some(locked_name) = locked_name
            && locked_name != name
            && Some(locked_name) != allowed_alias_target
        {
            anyhow::bail!(
                "Required lockfile '{}' entry '{}' claims to be '{}'. npm lockfile entries must match the package they install exactly.",
                lockfile_path.display(),
                name,
                locked_name
            );
        }
        validate_npm_lockfile_entry_fields(locked_name.unwrap_or(name), entry, lockfile_path)?;
        if let Some(nested) = entry
            .get("dependencies")
            .and_then(|value| value.as_object())
        {
            validate_npm_lockfile_dependency_entries(nested, lockfile_path, allowed_alias_targets)?;
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
    {
        return Ok(());
    }

    if entry
        .get("inBundle")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || entry
            .get("bundled")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' is marked as bundled. sloppy-joe does not trust bundled npm payloads yet because the bundled code cannot be verified independently from package-lock.json.",
            lockfile_path.display(),
            package_name
        );
    }

    let Some(version) = entry.get("version").and_then(|value| value.as_str()) else {
        return Ok(());
    };

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
    validate_npm_resolved_identity(package_name, version, resolved, lockfile_path)?;

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
    npm_registry_tarball_path(resolved).is_some()
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
    config: &config::SloppyJoeConfig,
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
    expand_cargo_project_inputs(project_dir, &mut specs, config)?;
    promote_trusted_pip_tools_specs(project_dir, &mut specs)?;
    prune_included_requirement_specs(project_dir, &mut specs)?;
    prefer_trusted_python_project_inputs(&mut specs);
    bind_js_project_inputs(project_dir, &mut specs)?;

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

fn expand_cargo_project_inputs(
    scan_root: &std::path::Path,
    specs: &mut Vec<ProjectInputSpec>,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let mut seen = specs
        .iter()
        .map(|spec| spec.manifest_path.clone())
        .collect::<std::collections::HashSet<_>>();

    let mut index = 0usize;
    while index < specs.len() {
        if specs[index].kind != ProjectInputKind::Cargo {
            index += 1;
            continue;
        }

        let manifest_path = specs[index].manifest_path.clone();
        specs[index].lockfile_path_override = Some(authoritative_cargo_lockfile_path(
            scan_root,
            &manifest_path,
            config,
        )?);

        let manifest = parsers::cargo_toml::parse_manifest_file(&manifest_path)?;
        let (cargo_config_rewrites, _) =
            load_effective_cargo_config_rewrites(scan_root, &manifest_path, config)?;
        let rewrites =
            collect_effective_cargo_rewrites(scan_root, &manifest, config, &cargo_config_rewrites)?;
        let effective = resolve_cargo_effective_dependencies(scan_root, &manifest, config)?;

        for dep in effective {
            if let parsers::cargo_toml::CargoSourceSpec::Path(path) = dep.spec.source
                && let Some(target_manifest) = cargo_local_target_manifest(
                    scan_root,
                    &dep.base_dir,
                    &path,
                    &dep.spec.package_name,
                    config,
                )?
                && seen.insert(target_manifest.clone())
            {
                specs.push(ProjectInputSpec {
                    kind: ProjectInputKind::Cargo,
                    manifest_path: target_manifest,
                    lockfile_path_override: None,
                    js_binding: None,
                });
            }
        }

        for rewrite in rewrites {
            if let parsers::cargo_toml::CargoSourceSpec::Path(path) = &rewrite.spec.source
                && let Some(target_manifest) = cargo_local_target_manifest(
                    scan_root,
                    &rewrite.base_dir,
                    path,
                    &rewrite.spec.package_name,
                    config,
                )?
                && seen.insert(target_manifest.clone())
            {
                specs.push(ProjectInputSpec {
                    kind: ProjectInputKind::Cargo,
                    manifest_path: target_manifest,
                    lockfile_path_override: None,
                    js_binding: None,
                });
            }
        }

        index += 1;
    }

    specs.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    Ok(())
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
        lockfile_path_override: None,
        js_binding: None,
    }))
}

fn project_input_kind_from_path(path: &std::path::Path) -> Result<Option<ProjectInputKind>> {
    Ok(match path.file_name().and_then(|name| name.to_str()) {
        Some("package.json") => Some(ProjectInputKind::Npm),
        Some("pyproject.toml") => Some(match parsers::pyproject_toml::classify_manifest(path)? {
            parsers::pyproject_toml::PyprojectKind::Poetry => ProjectInputKind::PyProjectPoetry,
            parsers::pyproject_toml::PyprojectKind::Uv => ProjectInputKind::PyProjectUv,
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

fn prefer_trusted_python_project_inputs(specs: &mut Vec<ProjectInputSpec>) {
    let trusted_pyproject_dirs: std::collections::HashSet<std::path::PathBuf> = specs
        .iter()
        .filter(|spec| {
            matches!(
                spec.kind,
                ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
            )
        })
        .map(|spec| spec.project_dir().to_path_buf())
        .collect();

    specs.retain(|spec| {
        if !spec.kind.is_python() {
            return true;
        }
        if !trusted_pyproject_dirs.contains(spec.project_dir()) {
            return true;
        }
        matches!(
            spec.kind,
            ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
        )
    });
}

fn has_npm_lockfile(project_dir: &std::path::Path) -> bool {
    ["npm-shrinkwrap.json", "package-lock.json"]
        .iter()
        .any(|name| parsers::path_detected(&project_dir.join(name)).unwrap_or(false))
}

fn promote_trusted_pip_tools_specs(
    scan_root: &std::path::Path,
    specs: &mut [ProjectInputSpec],
) -> Result<()> {
    for spec in specs.iter_mut() {
        if spec.kind != ProjectInputKind::PyRequirements {
            continue;
        }
        if parsers::requirements::is_hash_locked_requirements_file(&spec.manifest_path, scan_root)?
        {
            spec.kind = ProjectInputKind::PyRequirementsTrusted;
        }
    }
    Ok(())
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

    for spec in specs.iter().filter(|spec| {
        matches!(
            spec.kind,
            ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted
        )
    }) {
        for include in parsers::requirements::included_paths(&spec.manifest_path, scan_root)? {
            included.insert(include);
        }
    }

    specs.retain(|spec| {
        if !matches!(
            spec.kind,
            ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted
        ) {
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
    config: &config::SloppyJoeConfig,
) -> Result<Vec<ParsedProject>> {
    let mut projects = Vec::new();
    for spec in specs {
        projects.push(ParsedProject {
            spec: spec.clone(),
            deps: parse_project_input_with_config(scan_root, spec, config)?,
        });
    }
    Ok(projects)
}

fn parse_project_input_with_config(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Dependency>> {
    match spec.kind {
        ProjectInputKind::Cargo => parse_cargo_project_dependencies(scan_root, spec, config),
        _ => parse_project_input(scan_root, spec),
    }
}

fn parse_cargo_project_dependencies(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Dependency>> {
    let manifest = parsers::cargo_toml::parse_manifest_file(&spec.manifest_path)?;
    let mut deps = Vec::new();
    for dep in resolve_cargo_effective_dependencies(scan_root, &manifest, config)? {
        match dep.spec.source {
            parsers::cargo_toml::CargoSourceSpec::CratesIo
            | parsers::cargo_toml::CargoSourceSpec::RegistryAlias(_)
            | parsers::cargo_toml::CargoSourceSpec::RegistryIndex(_) => {
                let dependency = Dependency {
                    name: dep.spec.package_name,
                    version: dep.spec.version,
                    ecosystem: Ecosystem::Cargo,
                    actual_name: None,
                };
                parsers::validate_dependency(&dependency, &spec.manifest_path)?;
                deps.push(dependency);
            }
            parsers::cargo_toml::CargoSourceSpec::Path(_)
            | parsers::cargo_toml::CargoSourceSpec::Git { .. }
            | parsers::cargo_toml::CargoSourceSpec::Workspace => {}
        }
    }
    Ok(deps)
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
        ProjectInputKind::PyProjectUv => {
            parsers::pyproject_toml::parse_legacy_file(&spec.manifest_path)
        }
        ProjectInputKind::PyRequirements => {
            parsers::requirements::parse_file(&spec.manifest_path, scan_root)
        }
        ProjectInputKind::PyRequirementsTrusted => {
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
    if let Some(path) = &spec.lockfile_path_override {
        return Some(path.clone());
    }
    let project_dir = spec.project_dir();
    match spec.kind {
        ProjectInputKind::Npm => spec
            .js_binding
            .as_ref()
            .and_then(|binding| binding.lockfile_path.clone())
            .or_else(|| {
                first_existing_lockfile(project_dir, &["npm-shrinkwrap.json", "package-lock.json"])
            }),
        ProjectInputKind::Cargo => Some(project_dir.join("Cargo.lock")),
        ProjectInputKind::Go => Some(project_dir.join("go.sum")),
        ProjectInputKind::Ruby => Some(project_dir.join("Gemfile.lock")),
        ProjectInputKind::Php => Some(project_dir.join("composer.lock")),
        ProjectInputKind::Gradle => Some(project_dir.join("gradle.lockfile")),
        ProjectInputKind::Dotnet => Some(spec.manifest_path.with_file_name("packages.lock.json")),
        ProjectInputKind::PyProjectPoetry => Some(project_dir.join("poetry.lock")),
        ProjectInputKind::PyProjectUv => Some(project_dir.join("uv.lock")),
        ProjectInputKind::PyRequirementsTrusted => Some(spec.manifest_path.clone()),
        ProjectInputKind::PyRequirements
        | ProjectInputKind::PyProjectLegacy
        | ProjectInputKind::PyPipfile
        | ProjectInputKind::PySetupPy
        | ProjectInputKind::PySetupCfg
        | ProjectInputKind::Maven => None,
    }
}

fn js_lockfile_help(spec: &ProjectInputSpec) -> String {
    match spec.js_binding.as_ref().map(|binding| binding.manager) {
        Some(JsPackageManager::Pnpm) => {
            "Run `pnpm install --lockfile-only` and commit pnpm-lock.yaml.".to_string()
        }
        Some(JsPackageManager::Yarn) => {
            "Commit the authoritative yarn.lock for this project.".to_string()
        }
        Some(JsPackageManager::Bun) => {
            "Commit the authoritative bun.lock or bun.lockb for this project.".to_string()
        }
        _ => spec
            .kind
            .missing_lockfile_help()
            .unwrap_or("Commit the authoritative lockfile for this project.")
            .to_string(),
    }
}

fn lockfile_paths_for_project(spec: &ProjectInputSpec) -> Vec<std::path::PathBuf> {
    selected_lockfile_path(spec).into_iter().collect()
}

fn hash_json_value_canonical(
    value: &serde_json::Value,
    hasher: &mut std::collections::hash_map::DefaultHasher,
) {
    use std::hash::Hash;

    match value {
        serde_json::Value::Null => 0u8.hash(hasher),
        serde_json::Value::Bool(flag) => {
            1u8.hash(hasher);
            flag.hash(hasher);
        }
        serde_json::Value::Number(number) => {
            2u8.hash(hasher);
            number.to_string().hash(hasher);
        }
        serde_json::Value::String(string) => {
            3u8.hash(hasher);
            string.hash(hasher);
        }
        serde_json::Value::Array(items) => {
            4u8.hash(hasher);
            items.len().hash(hasher);
            for item in items {
                hash_json_value_canonical(item, hasher);
            }
        }
        serde_json::Value::Object(map) => {
            5u8.hash(hasher);
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            keys.len().hash(hasher);
            for key in keys {
                key.hash(hasher);
                hash_json_value_canonical(&map[key], hasher);
            }
        }
    }
}

fn policy_hash_value(
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<serde_json::Value, String> {
    serde_json::to_value(serde_json::json!({
        "config": config,
        "options": {
            "deep": opts.deep,
            "paranoid": opts.paranoid,
            "review_exceptions": opts.review_exceptions,
        },
        "hash_contract_version": 2u8,
    }))
    .map_err(|err| format!("cannot serialize scan policy for hashing: {err}"))
}

fn policy_hash_u64(
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<u64, String> {
    use std::hash::Hasher;
    let policy = policy_hash_value(config, opts)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hash_json_value_canonical(&policy, &mut hasher);
    Ok(hasher.finish())
}

fn project_state_hash_for_projects(projects: &[ParsedProject]) -> std::result::Result<u64, String> {
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

fn project_binding_hash_for_projects(projects: &[ParsedProject]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    let mut bindings: Vec<_> = projects
        .iter()
        .map(|project| {
            (
                project.spec.manifest_path.display().to_string(),
                project.spec.kind.manifest_label(),
                project.spec.js_binding.as_ref().map(|binding| {
                    (
                        binding.manager.as_str(),
                        binding.root_manifest_path.display().to_string(),
                        binding
                            .lockfile_path
                            .as_ref()
                            .map(|path| path.display().to_string()),
                        binding.package_entry_key.clone(),
                    )
                }),
            )
        })
        .collect::<Vec<_>>();
    bindings.sort();
    bindings.hash(&mut hasher);
    hasher.finish()
}

fn scan_hash_for_projects(
    projects: &[ParsedProject],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    project_state_hash_for_projects(projects)?.hash(&mut hasher);

    let policy = policy_hash_value(config, opts)?;
    hash_json_value_canonical(&policy, &mut hasher);

    Ok(hasher.finish())
}

#[cfg(test)]
fn scan_hash_for_projects_with_policy(
    projects: &[ParsedProject],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<u64, String> {
    scan_hash_for_projects(projects, config, opts)
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

const FULL_SCAN_TTL_SECS: u64 = 24 * 3600;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct FullScanFingerprintCache {
    timestamp: u64,
    project_state_hash: u64,
    policy_hash: u64,
    binding_hash: u64,
}

fn full_scan_fingerprint_cache_path(cache_base: &std::path::Path) -> std::path::PathBuf {
    cache_base.join("full-scan-fingerprint.json")
}

fn full_scan_fingerprint_components_for_projects(
    projects: &[ParsedProject],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
    timestamp: u64,
) -> std::result::Result<FullScanFingerprintCache, String> {
    Ok(FullScanFingerprintCache {
        timestamp,
        project_state_hash: project_state_hash_for_projects(projects)?,
        policy_hash: policy_hash_u64(config, opts)?,
        binding_hash: project_binding_hash_for_projects(projects),
    })
}

fn read_full_scan_fingerprint_cache(
    cache_base: &std::path::Path,
) -> std::result::Result<Option<FullScanFingerprintCache>, String> {
    let path = full_scan_fingerprint_cache_path(cache_base);
    if !path.exists() {
        return Ok(None);
    }
    cache::ensure_no_symlink(&path)
        .map_err(|err| format!("cannot safely read {}: {}", path.display(), err))?;
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {}: {}", path.display(), err))?;
    let parsed = serde_json::from_str::<FullScanFingerprintCache>(&content)
        .map_err(|err| format!("cannot parse {}: {}", path.display(), err))?;
    Ok(Some(parsed))
}

fn persist_successful_full_scan_fingerprint(
    projects: &[ParsedProject],
    cache_base: &std::path::Path,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<(), String> {
    let fingerprint =
        full_scan_fingerprint_components_for_projects(projects, config, opts, cache::now_epoch())?;
    let path = full_scan_fingerprint_cache_path(cache_base);
    cache::atomic_write_json(&path, &fingerprint);
    Ok(())
}

fn full_scan_recommendation_reasons_for_projects(
    projects: &[ParsedProject],
    cache_base: &std::path::Path,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
    now_epoch: u64,
) -> std::result::Result<Vec<report::FullScanRecommendationReason>, String> {
    let current = full_scan_fingerprint_components_for_projects(projects, config, opts, now_epoch)?;
    let Some(previous) = read_full_scan_fingerprint_cache(cache_base)? else {
        return Ok(vec![
            report::FullScanRecommendationReason::NoSuccessfulFullScan,
        ]);
    };

    let mut reasons = Vec::new();
    if now_epoch.saturating_sub(previous.timestamp) >= FULL_SCAN_TTL_SECS {
        reasons.push(report::FullScanRecommendationReason::LastFullScanStale);
    }
    if previous.project_state_hash != current.project_state_hash {
        reasons.push(report::FullScanRecommendationReason::DependencyStateChanged);
    }
    if previous.policy_hash != current.policy_hash {
        reasons.push(report::FullScanRecommendationReason::PolicyChanged);
    }
    if previous.binding_hash != current.binding_hash {
        reasons.push(report::FullScanRecommendationReason::ManagerBindingChanged);
    }
    Ok(reasons)
}

#[cfg(test)]
fn full_scan_fingerprint_for_projects(
    projects: &[ParsedProject],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let fingerprint =
        full_scan_fingerprint_components_for_projects(projects, config, opts, cache::now_epoch())?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    fingerprint.project_state_hash.hash(&mut hasher);
    fingerprint.policy_hash.hash(&mut hasher);
    fingerprint.binding_hash.hash(&mut hasher);
    Ok(hasher.finish())
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

fn local_overlay_relaxation_issues(config: &config::SloppyJoeConfig) -> Vec<Issue> {
    config
        .active_local_overlay_relaxations
        .iter()
        .map(|relaxation| {
            Issue::new(
                "<local-overlay>",
                checks::names::CONFIG_LOCAL_OVERLAY_RELAXATION,
                Severity::Warning,
            )
            .message(format!(
                "This scan used a local-only overlay relaxation: {}. Results may differ from CI.",
                relaxation
            ))
            .fix(
                "Keep local-only provenance relaxations out of CI. Prefer repo-visible, reviewed provenance whenever possible.",
            )
        })
        .collect()
}

async fn scan_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    let cache_base = opts
        .cache_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
    let specs = detected_project_inputs_with_config(project_dir, project_type, &config)?;
    let mut preflight_warnings = preflight_project_inputs(project_dir, &specs, &config)?;
    preflight_warnings.extend(local_overlay_relaxation_issues(&config));
    let projects = parse_project_inputs(project_dir, &specs, &config)?;

    if projects.is_empty() {
        parsers::parse_dependencies(project_dir, project_type)?;
        return Ok(ScanReport::from_issues(0, preflight_warnings));
    }
    let full_scan_reasons = if matches!(opts.scan_mode, ScanMode::Fast) {
        match full_scan_recommendation_reasons_for_projects(
            &projects,
            &cache_base,
            &config,
            opts,
            cache::now_epoch(),
        ) {
            Ok(reasons) => reasons,
            Err(reason) => {
                eprintln!(
                    "Skipping full-scan recommendation state: {}",
                    report::sanitize_for_terminal(&reason)
                );
                vec![report::FullScanRecommendationReason::NoSuccessfulFullScan]
            }
        }
    } else {
        Vec::new()
    };

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
        let report =
            scan_parsed_project(project, config.clone(), &*registry, &osv_client, opts).await?;
        total_packages += report.packages_checked;
        all_issues.extend(report.issues);
        all_review_candidates.extend(report.review_candidates);
    }

    let report = ScanReport::from_issues_with_review_candidates(
        total_packages,
        all_issues,
        all_review_candidates,
    );
    let mut report = report;
    report.full_scan_reasons = full_scan_reasons;

    // Save hash after successful scan
    if !opts.no_cache {
        match scan_hash_for_projects(&projects, &config, opts) {
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

    if opts.scan_mode.runs_full_checks()
        && let Err(reason) =
            persist_successful_full_scan_fingerprint(&projects, &cache_base, &config, opts)
    {
        eprintln!(
            "Not caching successful full-scan fingerprint for this run: {}",
            report::sanitize_for_terminal(&reason)
        );
    }

    Ok(report)
}

async fn scan_parsed_project(
    project: &ParsedProject,
    config: config::SloppyJoeConfig,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    if project.deps.is_empty() {
        return Ok(ScanReport::empty());
    }

    let ecosystem = project.deps[0].ecosystem;
    let (checkable, non_internal, internal) = classify_deps(&project.deps, &config, ecosystem);
    let mut lockfile_data = lockfiles::LockfileData::parse_for_kind_with_lockfile(
        project.spec.project_dir(),
        Some(project.spec.kind),
        &non_internal,
        project.spec.lockfile_path_override.as_deref(),
    )?;

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

    if !opts.scan_mode.runs_full_checks() {
        let canonical = checks::pipeline::CanonicalCheck;
        canonical.run(&ctx, &mut acc).await?;
        acc.issues.extend(lockfile_data.resolution.issues.clone());
        acc.issues.extend(unresolved_version_policy_issues(
            &non_internal,
            &lockfile_data.resolution,
            &config,
        ));
        mark_source(&mut acc.issues, "direct");
        return Ok(ScanReport::from_issues_with_review_candidates(
            non_internal.len(),
            acc.issues,
            acc.review_candidates,
        ));
    }

    let pipeline = checks::pipeline::default_pipeline();
    for check in &pipeline {
        check.run(&ctx, &mut acc).await?;
    }
    mark_source(&mut acc.issues, "direct");

    if !internal.is_empty() {
        let internal_resolution = lockfiles::LockfileData::parse_for_kind_with_lockfile(
            project.spec.project_dir(),
            Some(project.spec.kind),
            &internal,
            project.spec.lockfile_path_override.as_deref(),
        )
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

    let mut transitive_deps = std::mem::take(&mut lockfile_data.transitive_deps);
    transitive_deps.retain(|dep| {
        !config.is_internal(ecosystem.as_str(), dep.package_name())
            && !config.is_allowed(ecosystem.as_str(), dep.package_name())
    });

    if !transitive_deps.is_empty() {
        let trans_resolution = lockfile_data.resolve_transitive(&transitive_deps)?;
        let trans_pipeline: Vec<Box<dyn checks::Check>> =
            if opts.deep || ecosystem == Ecosystem::Npm {
                checks::pipeline::default_pipeline()
            } else {
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

#[cfg(test)]
#[allow(dead_code)]
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
    /// High-level scan behavior: fast local guardrail vs full online scan.
    pub scan_mode: ScanMode,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanMode {
    Fast,
    #[default]
    Full,
    Ci,
}

impl ScanMode {
    fn runs_full_checks(self) -> bool {
        !matches!(self, Self::Fast)
    }
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
        .filter(|dep| {
            resolution.is_unresolved(dep)
                && !resolution.has_issue_for(dep, checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC)
        })
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
