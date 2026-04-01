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
    let config = config::load_config_from_source(config_source, Some(project_dir))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let opts = ScanOptions {
        deep,
        paranoid,
        no_cache,
        cache_dir,
        disable_osv_disk_cache: false,
        skip_hash_check: false,
    };
    scan_with_config(project_dir, project_type, config, &opts).await
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
enum ProjectInputKind {
    Npm,
    PyPI,
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

impl ProjectInputKind {
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
            Self::PyPI | Self::Maven => None,
        }
    }
}

fn preflight_scan_inputs(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
) -> Result<Vec<Issue>> {
    let specs = detected_project_inputs(project_dir, project_type)?;
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
                project_dir,
                &["package-lock.json", "npm-shrinkwrap.json"],
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Cargo => ensure_lockfile_readable(
                &project_dir.join("Cargo.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Go => {
                if parsers::go_mod::requires_go_sum(&manifest_content) {
                    ensure_lockfile_readable(
                        &project_dir.join("go.sum"),
                        spec.kind.missing_lockfile_help().unwrap(),
                    )?;
                }
            }
            ProjectInputKind::Ruby => ensure_lockfile_readable(
                &project_dir.join("Gemfile.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Php => ensure_lockfile_readable(
                &project_dir.join("composer.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Gradle => ensure_lockfile_readable(
                &project_dir.join("gradle.lockfile"),
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
            ProjectInputKind::PyPI => {}
        }
    }

    Ok(warnings)
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

fn detected_project_inputs(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
) -> Result<Vec<ProjectInputSpec>> {
    match project_type {
        Some("npm") => require_named_manifest(project_dir, "package.json", ProjectInputKind::Npm),
        Some("pypi") => {
            require_named_manifest(project_dir, "requirements.txt", ProjectInputKind::PyPI)
        }
        Some("cargo") => require_named_manifest(project_dir, "Cargo.toml", ProjectInputKind::Cargo),
        Some("go") => require_named_manifest(project_dir, "go.mod", ProjectInputKind::Go),
        Some("ruby") => require_named_manifest(project_dir, "Gemfile", ProjectInputKind::Ruby),
        Some("php") => require_named_manifest(project_dir, "composer.json", ProjectInputKind::Php),
        Some("jvm") => detect_jvm_manifests(project_dir, true),
        Some("dotnet") => detect_dotnet_manifests(project_dir, true),
        Some(_) => Ok(Vec::new()),
        None => {
            let mut specs = Vec::new();
            specs.extend(detect_named_manifest(
                project_dir,
                "package.json",
                ProjectInputKind::Npm,
            )?);
            specs.extend(detect_named_manifest(
                project_dir,
                "requirements.txt",
                ProjectInputKind::PyPI,
            )?);
            specs.extend(detect_named_manifest(
                project_dir,
                "Cargo.toml",
                ProjectInputKind::Cargo,
            )?);
            specs.extend(detect_named_manifest(
                project_dir,
                "go.mod",
                ProjectInputKind::Go,
            )?);
            specs.extend(detect_named_manifest(
                project_dir,
                "Gemfile",
                ProjectInputKind::Ruby,
            )?);
            specs.extend(detect_named_manifest(
                project_dir,
                "composer.json",
                ProjectInputKind::Php,
            )?);
            specs.extend(detect_jvm_manifests(project_dir, false)?);
            specs.extend(detect_dotnet_manifests(project_dir, false)?);
            Ok(specs)
        }
    }
}

fn require_named_manifest(
    project_dir: &std::path::Path,
    manifest_name: &str,
    kind: ProjectInputKind,
) -> Result<Vec<ProjectInputSpec>> {
    let specs = detect_named_manifest(project_dir, manifest_name, kind)?;
    if specs.is_empty() {
        anyhow::bail!(
            "Required manifest '{}' is missing for this project type.",
            manifest_name
        );
    }
    Ok(specs)
}

fn detect_named_manifest(
    project_dir: &std::path::Path,
    manifest_name: &str,
    kind: ProjectInputKind,
) -> Result<Vec<ProjectInputSpec>> {
    let path = project_dir.join(manifest_name);
    if path_detected(&path)? {
        Ok(vec![ProjectInputSpec {
            kind,
            manifest_path: path,
        }])
    } else {
        Ok(Vec::new())
    }
}

fn detect_jvm_manifests(
    project_dir: &std::path::Path,
    required: bool,
) -> Result<Vec<ProjectInputSpec>> {
    let mut specs = Vec::new();

    for manifest_name in ["build.gradle", "build.gradle.kts"] {
        let path = project_dir.join(manifest_name);
        if path_detected(&path)? {
            specs.push(ProjectInputSpec {
                kind: ProjectInputKind::Gradle,
                manifest_path: path,
            });
        }
    }

    let pom = project_dir.join("pom.xml");
    if path_detected(&pom)? {
        specs.push(ProjectInputSpec {
            kind: ProjectInputKind::Maven,
            manifest_path: pom,
        });
    }

    if required && specs.is_empty() {
        anyhow::bail!(
            "Required manifest 'build.gradle, build.gradle.kts, or pom.xml' is missing for this project type."
        );
    }

    Ok(specs)
}

fn detect_dotnet_manifests(
    project_dir: &std::path::Path,
    required: bool,
) -> Result<Vec<ProjectInputSpec>> {
    let mut specs = Vec::new();
    for path in dotnet_manifest_paths(project_dir)? {
        specs.push(ProjectInputSpec {
            kind: ProjectInputKind::Dotnet,
            manifest_path: path,
        });
    }

    if required && specs.is_empty() {
        anyhow::bail!("Required manifest '.csproj' is missing for this project type.");
    }

    Ok(specs)
}

fn dotnet_manifest_paths(project_dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let entries = std::fs::read_dir(project_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for .csproj manifests: {}",
            project_dir.display(),
            err
        )
    })?;

    let mut manifests = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "csproj") {
            manifests.push(path);
        }
    }
    Ok(manifests)
}

fn path_detected(path: &std::path::Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(anyhow::anyhow!(
            "Failed to inspect {}: {}",
            path.display(),
            err
        )),
    }
}

/// Compute a hash of dependency tuples + lockfile content for change detection.
/// Includes lockfile so that resolved version changes (e.g., a compromised upstream
/// version satisfying the same range) invalidate the cache even when the manifest
/// is unchanged. If a known lockfile exists but cannot be safely hashed, hash-based
/// scan skipping is disabled for the run.
fn scan_hash(
    project_dir: &std::path::Path,
    deps: &[Dependency],
) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // Hash sorted dep tuples (manifest content)
    let mut tuples: Vec<(&str, Option<&str>, &str)> = deps
        .iter()
        .map(|d| (d.name.as_str(), d.version.as_deref(), d.ecosystem.as_str()))
        .collect();
    tuples.sort();
    tuples.hash(&mut hasher);

    // Hash lockfile content (resolved versions) — catches upstream version changes
    for lockfile in &[
        "package-lock.json",
        "npm-shrinkwrap.json",
        "Cargo.lock",
        "go.sum",
        "Gemfile.lock",
        "poetry.lock",
        "composer.lock",
        "gradle.lockfile",
        "packages.lock.json",
    ] {
        let path = project_dir.join(lockfile);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let content = parsers::read_bytes_limited(&path, parsers::MAX_MANIFEST_BYTES)
                    .map_err(|err| format!("cannot safely hash {}: {}", path.display(), err))?;
                lockfile.hash(&mut hasher);
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
    let preflight_warnings = preflight_scan_inputs(project_dir, project_type)?;

    // When project_type is specified, scan only that ecosystem (original behavior).
    // When auto-detecting, scan ALL ecosystems found in the project.
    let dep_sets: Vec<Vec<Dependency>> = if project_type.is_some() {
        vec![parsers::parse_dependencies(project_dir, project_type)?]
    } else {
        let all = parsers::parse_all_ecosystems(project_dir)?;
        if all.is_empty() {
            // Fall back to parse_dependencies for the error message
            vec![parsers::parse_dependencies(project_dir, None)?]
        } else {
            all
        }
    };

    // Flatten all deps for hash check
    let all_deps: Vec<Dependency> = dep_sets.iter().flatten().cloned().collect();

    // Skip scan if deps haven't changed (manifest + lockfile hash check)
    if !opts.no_cache && !opts.skip_hash_check && !all_deps.is_empty() {
        let cache_base = opts
            .cache_dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
        match scan_hash_matches_cache(project_dir, &all_deps, &cache_base) {
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

    for deps in &dep_sets {
        if deps.is_empty() {
            continue;
        }
        let ecosystem = deps[0].ecosystem;
        let registry = registry::registry_for_with_client(ecosystem, client.clone())?;
        let report = scan_with_services_inner(
            project_dir,
            config.clone(),
            deps.clone(),
            &*registry,
            &osv_client,
            opts,
        )
        .await?;
        total_packages += report.packages_checked;
        all_issues.extend(report.issues);
    }

    let report = ScanReport::from_issues(total_packages, all_issues);

    // Save hash after successful scan
    if !opts.no_cache && !all_deps.is_empty() {
        let cache_base = opts
            .cache_dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
        match scan_hash(project_dir, &all_deps) {
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

async fn scan_with_services_inner(
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
    let mut lockfile_data = lockfiles::LockfileData::parse(project_dir, &non_internal)?;

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
    for check in &pipeline {
        check.run(&ctx, &mut acc).await?;
    }
    mark_source(&mut acc.issues, "direct");

    // Run OSV on internal packages (they skip all other checks but still need vuln scanning)
    if !internal.is_empty() {
        let internal_resolution = lockfiles::LockfileData::parse(project_dir, &internal)
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
        !config.is_internal(ecosystem.as_str(), &dep.name)
            && !config.is_allowed(ecosystem.as_str(), &dep.name)
    });

    if !transitive_deps.is_empty() {
        let trans_resolution = lockfile_data.resolve_transitive(&transitive_deps)?;

        // Build transitive pipeline (skip similarity unless --deep)
        let trans_pipeline: Vec<Box<dyn checks::Check>> = if opts.deep {
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

    Ok(ScanReport::from_issues(
        non_internal.len() + transitive_deps.len(),
        acc.issues,
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
        .partition(|dep| config.is_internal(eco_str, &dep.name));

    let (allowed, checkable): (Vec<&Dependency>, Vec<&Dependency>) = rest
        .iter()
        .copied()
        .partition(|dep| config.is_allowed(eco_str, &dep.name));

    if !internal.is_empty() {
        let names: Vec<_> = internal
            .iter()
            .map(|d| report::sanitize_for_terminal(&d.name))
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
            .map(|d| report::sanitize_for_terminal(&d.name))
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
}

/// A dependency parsed from a project manifest file (package.json, Cargo.toml, etc.).
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Package name as it appears in the manifest (e.g., "react", "@types/node").
    pub name: String,
    /// Version requirement from the manifest (e.g., "^18.0", "==2.31.0"). None if unspecified.
    pub version: Option<String>,
    /// Which ecosystem this dependency belongs to.
    pub ecosystem: Ecosystem,
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
                    dep.name, requirement
                )
            } else {
                format!(
                    "'{}' does not declare an exact version and no trusted lockfile resolution was available. The following checks are skipped: version-age, install-script-risk, dependency-explosion, maintainer-change, and known-vulnerability (OSV).",
                    dep.name
                )
            };

            Issue::new(&dep.name, checks::names::RESOLUTION_NO_EXACT_VERSION, severity)
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
        }
    }

    /// Create a test dependency with name, optional version, and ecosystem.
    pub fn dep_with(name: &str, version: Option<&str>, ecosystem: Ecosystem) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            ecosystem,
        }
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
