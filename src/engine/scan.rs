use crate::*;

pub(crate) fn local_overlay_relaxation_issues(config: &config::SloppyJoeConfig) -> Vec<Issue> {
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

/// Per-project results gathered while scanning a repository.
struct ScanAccumulator {
    /// True when exactly one project is scanned: its failure fails the whole scan.
    single_project: bool,
    total_packages: usize,
    issues: Vec<Issue>,
    review_candidates: Vec<report::ReviewExceptionCandidate>,
    runs: Vec<report::ProjectScan>,
}

impl ScanAccumulator {
    /// Record a project that could not be scanned, or propagate its error for a lone project.
    fn record_failure(&mut self, spec: &ProjectInputSpec, error: anyhow::Error) -> Result<()> {
        if self.single_project {
            return Err(error);
        }
        self.issues.push(incomplete_project_issue(spec, &error));
        self.runs.push(project_scan_summary(
            spec,
            0,
            report::ProjectScanStatus::Unsupported,
        ));
        Ok(())
    }

    fn record_report(&mut self, spec: &ProjectInputSpec, mut report: ScanReport) {
        let manifest = spec.manifest_path.display().to_string();
        let blocked = report.has_errors()
            || self.issues.iter().any(|issue| {
                issue.project.as_deref() == Some(manifest.as_str())
                    && issue.severity == Severity::Error
            });
        let status = if blocked {
            report::ProjectScanStatus::Blocked
        } else {
            report::ProjectScanStatus::Passed
        };
        self.runs
            .push(project_scan_summary(spec, report.packages_checked, status));
        for issue in &mut report.issues {
            issue.project = Some(manifest.clone());
        }
        self.total_packages += report.packages_checked;
        self.issues.extend(report.issues);
        self.review_candidates.extend(report.review_candidates);
    }
}

/// Reasons a fast scan recommends a full scan; empty outside fast mode.
fn fast_mode_full_scan_reasons(
    projects: &[ParsedProject],
    cache_base: &std::path::Path,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Vec<report::FullScanRecommendationReason> {
    if !matches!(opts.scan_mode, ScanMode::Fast) {
        return Vec::new();
    }
    match full_scan_recommendation_reasons_for_projects(
        projects,
        cache_base,
        config,
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
}

/// Maven versions come from properties, management sections, BOMs and the parent chain, not only
/// from the declarations themselves. `None` means the project needs no resolution.
async fn with_resolved_maven_versions(
    project: &ParsedProject,
    client: &reqwest::Client,
) -> Result<Option<ParsedProject>> {
    if project.spec.kind != ProjectInputKind::Maven || project.unlocked_tooling {
        return Ok(None);
    }
    let deps = parsers::jvm::resolve_maven_versions(
        &project.spec.manifest_path,
        project.deps.clone(),
        client.clone(),
    )
    .await?;
    Ok(Some(ParsedProject {
        deps,
        ..project.clone()
    }))
}

/// Run all checks for one project, including the Gradle plugin implementation checks.
async fn scan_one_project(
    project: &ParsedProject,
    config: &config::SloppyJoeConfig,
    client: &reqwest::Client,
    osv_client: &checks::malicious::RealOsvClient,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    // A project with no declared dependencies is still scanned: its
    // lockfile may list installable packages.
    let registry = match gradle_plugin_scan::plugin_registry_for(project, client.clone())? {
        Some(registry) => registry,
        None => registry::registry_for_with_client(project.spec.kind.ecosystem(), client.clone())?,
    };
    let mut report =
        scan_parsed_project(project, config.clone(), &*registry, osv_client, opts).await?;
    let issues = gradle_plugin_scan::project_implementation_issues(
        project,
        client.clone(),
        osv_client,
        opts,
    )
    .await?;
    report.issues.extend(issues);
    Ok(report)
}

/// Remember the dependency hash and full-scan fingerprint so later runs can skip or escalate.
fn persist_scan_state(
    projects: &[ParsedProject],
    report: &ScanReport,
    cache_base: &std::path::Path,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) {
    if !opts.no_cache {
        match scan_hash_for_projects(projects, config, opts) {
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
        && !report.has_errors()
        && let Err(reason) =
            persist_successful_full_scan_fingerprint(projects, cache_base, config, opts)
    {
        eprintln!(
            "Not caching successful full-scan fingerprint for this run: {}",
            report::sanitize_for_terminal(&reason)
        );
    }
}

pub(crate) async fn scan_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    let cache_base = opts
        .cache_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
    cache::ensure_cache_dir_outside_project(&cache_base, project_dir)?;
    let mut specs = unbound_project_inputs_with_config(project_dir, project_type, &config)?;
    let mut binding_errors = ecosystems::bind(project_dir, &mut specs);
    let usable_specs: Vec<_> = specs
        .iter()
        .filter(|spec| !binding_errors.contains_key(&spec.manifest_path))
        .cloned()
        .collect();
    let mut acc = ScanAccumulator {
        single_project: specs.len() == 1,
        total_packages: 0,
        issues: local_overlay_relaxation_issues(&config),
        review_candidates: Vec::new(),
        runs: Vec::new(),
    };
    let mut projects = Vec::new();
    for spec in &specs {
        let prepared = (|| -> Result<Vec<ParsedProject>> {
            if let Some(error) = binding_errors.remove(&spec.manifest_path) {
                return Err(error);
            }
            let warnings = preflight_selected_project_inputs(
                project_dir,
                &usable_specs,
                std::slice::from_ref(spec),
                &config,
                opts,
            )?;
            let parsed = parse_project_inputs_with_options(
                project_dir,
                std::slice::from_ref(spec),
                &config,
                opts,
            )?;
            acc.issues.extend(warnings.into_iter().map(|mut issue| {
                issue.project = Some(spec.manifest_path.display().to_string());
                issue
            }));
            Ok(parsed)
        })();
        match prepared {
            Ok(parsed) => projects.extend(parsed),
            Err(error) => acc.record_failure(spec, error)?,
        }
    }
    if projects.is_empty() && acc.runs.is_empty() {
        parsers::parse_dependencies(project_dir, project_type)?;
        return Ok(ScanReport::from_issues(0, acc.issues));
    }
    let full_scan_reasons = fast_mode_full_scan_reasons(&projects, &cache_base, &config, opts);

    // Scan each ecosystem separately, merge reports
    let client = registry::http_client();
    let osv_client = checks::malicious::RealOsvClient::with_client(client.clone());

    for project in &projects {
        let resolved = match with_resolved_maven_versions(project, &client).await {
            Ok(resolved) => resolved,
            Err(error) => {
                acc.record_failure(&project.spec, error)?;
                continue;
            }
        };
        let project = resolved.as_ref().unwrap_or(project);
        match scan_one_project(project, &config, &client, &osv_client, opts).await {
            Ok(report) => acc.record_report(&project.spec, report),
            Err(error) => acc.record_failure(&project.spec, error)?,
        }
    }

    let mut report = ScanReport::from_issues_with_review_candidates(
        acc.total_packages,
        acc.issues,
        acc.review_candidates,
    );
    report.full_scan_reasons = full_scan_reasons;
    acc.runs
        .sort_by(|a, b| a.manifest_path.cmp(&b.manifest_path));
    report.projects = acc.runs;

    persist_scan_state(&projects, &report, &cache_base, &config, opts);
    Ok(report)
}

pub(crate) fn project_scan_summary(
    spec: &ProjectInputSpec,
    packages_checked: usize,
    status: report::ProjectScanStatus,
) -> report::ProjectScan {
    report::ProjectScan {
        manifest_path: spec.manifest_path.display().to_string(),
        lockfile_path: selected_lockfile_path(spec).map(|path| path.display().to_string()),
        manager: spec
            .js_binding
            .as_ref()
            .map(|binding| binding.manager.as_str().to_string())
            .or_else(|| spec.kind.descriptor().manager.map(str::to_string)),
        packages_checked,
        status,
    }
}

pub(crate) fn incomplete_project_issue(spec: &ProjectInputSpec, error: &anyhow::Error) -> Issue {
    let mut issue = Issue::new("<project>", checks::names::SCAN_INCOMPLETE_PROJECT, Severity::Error)
        .message(format!("Project scan incomplete: {error:#}"))
        .fix("Resolve the unsupported input or runtime error for this project; other independent project results are retained.");
    issue.project = Some(spec.manifest_path.display().to_string());
    issue
}
/// Classify deps into three tiers. Returns (checkable, non_internal, internal).
/// - checkable: full checks (similarity, existence, canonical, metadata, osv)
/// - non_internal: allowed + checkable (canonical, metadata, osv)
/// - internal: OSV only (skip similarity, existence, canonical, metadata)
pub(crate) fn classify_deps(
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

pub(crate) fn mark_source(issues: &mut [Issue], source: &str) {
    for issue in issues.iter_mut() {
        if issue.source.is_none() {
            issue.source = Some(source.to_string());
        }
    }
}

pub(crate) fn alias_identity_issues(deps: &[Dependency]) -> Vec<Issue> {
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
