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
    let mut binding_errors = std::collections::HashMap::new();
    for spec in &mut specs {
        if spec.kind != ProjectInputKind::Npm {
            continue;
        }
        match resolve_js_project_binding(project_dir, spec) {
            Ok(binding) => {
                spec.lockfile_path_override = binding.lockfile_path.clone();
                spec.js_binding = Some(binding);
            }
            Err(error) => {
                binding_errors.insert(spec.manifest_path.clone(), error);
            }
        }
    }
    let scanned_js_dirs: std::collections::HashSet<std::path::PathBuf> = specs
        .iter()
        .filter(|spec| spec.kind == ProjectInputKind::Npm)
        .filter_map(|spec| std::fs::canonicalize(spec.project_dir()).ok())
        .collect();
    for spec in &specs {
        if spec.kind != ProjectInputKind::Npm || binding_errors.contains_key(&spec.manifest_path) {
            continue;
        }
        if let Err(error) = ensure_js_workspace_members_scanned(project_dir, spec, &scanned_js_dirs)
        {
            binding_errors.insert(spec.manifest_path.clone(), error);
        }
    }
    let usable_specs: Vec<_> = specs
        .iter()
        .filter(|spec| !binding_errors.contains_key(&spec.manifest_path))
        .cloned()
        .collect();
    let mut preflight_warnings = local_overlay_relaxation_issues(&config);
    let mut projects = Vec::new();
    let mut project_runs = Vec::new();
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
            preflight_warnings.extend(warnings.into_iter().map(|mut issue| {
                issue.project = Some(spec.manifest_path.display().to_string());
                issue
            }));
            Ok(parsed)
        })();
        match prepared {
            Ok(parsed) => projects.extend(parsed),
            Err(error) => {
                if specs.len() == 1 {
                    return Err(error);
                }
                preflight_warnings.push(incomplete_project_issue(spec, &error));
                project_runs.push(project_scan_summary(
                    spec,
                    0,
                    report::ProjectScanStatus::Unsupported,
                ));
            }
        }
    }
    if projects.is_empty() && project_runs.is_empty() {
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
        // Maven versions come from properties, management sections, BOMs and
        // the parent chain, not only from the declarations themselves.
        let resolved_project;
        let project = if project.spec.kind == ProjectInputKind::Maven && !project.unlocked_tooling {
            match parsers::jvm::resolve_maven_versions(
                &project.spec.manifest_path,
                project.deps.clone(),
                client.clone(),
            )
            .await
            {
                Ok(deps) => {
                    resolved_project = ParsedProject {
                        deps,
                        ..project.clone()
                    };
                    &resolved_project
                }
                Err(error) => {
                    if specs.len() == 1 {
                        return Err(error);
                    }
                    all_issues.push(incomplete_project_issue(&project.spec, &error));
                    project_runs.push(project_scan_summary(
                        &project.spec,
                        0,
                        report::ProjectScanStatus::Unsupported,
                    ));
                    continue;
                }
            }
        } else {
            project
        };
        // A project with no declared dependencies is still scanned: its
        // lockfile may list installable packages.
        let registry = match gradle_plugin_scan::plugin_registry_for(project, client.clone())? {
            Some(registry) => registry,
            None => {
                registry::registry_for_with_client(project.spec.kind.ecosystem(), client.clone())?
            }
        };
        let result =
            scan_parsed_project(project, config.clone(), &*registry, &osv_client, opts).await;
        let result = match result {
            Ok(mut report) => gradle_plugin_scan::project_implementation_issues(
                project,
                client.clone(),
                &osv_client,
                opts,
            )
            .await
            .map(|issues| {
                report.issues.extend(issues);
                report
            }),
            Err(error) => Err(error),
        };
        match result {
            Ok(mut report) => {
                let status = if report.has_errors()
                    || all_issues.iter().any(|issue| {
                        issue.project.as_deref()
                            == Some(project.spec.manifest_path.to_string_lossy().as_ref())
                            && issue.severity == Severity::Error
                    }) {
                    report::ProjectScanStatus::Blocked
                } else {
                    report::ProjectScanStatus::Passed
                };
                project_runs.push(project_scan_summary(
                    &project.spec,
                    report.packages_checked,
                    status,
                ));
                for issue in &mut report.issues {
                    issue.project = Some(project.spec.manifest_path.display().to_string());
                }
                total_packages += report.packages_checked;
                all_issues.extend(report.issues);
                all_review_candidates.extend(report.review_candidates);
            }
            Err(error) => {
                if specs.len() == 1 {
                    return Err(error);
                }
                all_issues.push(incomplete_project_issue(&project.spec, &error));
                project_runs.push(project_scan_summary(
                    &project.spec,
                    0,
                    report::ProjectScanStatus::Unsupported,
                ));
            }
        }
    }

    let report = ScanReport::from_issues_with_review_candidates(
        total_packages,
        all_issues,
        all_review_candidates,
    );
    let mut report = report;
    report.full_scan_reasons = full_scan_reasons;
    project_runs.sort_by(|a, b| a.manifest_path.cmp(&b.manifest_path));
    report.projects = project_runs;

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
        && !report.has_errors()
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
            .or_else(|| {
                let manager = match spec.kind {
                    ProjectInputKind::Npm => return None,
                    ProjectInputKind::PyProjectPoetry => "poetry",
                    ProjectInputKind::PyProjectUv => "uv",
                    ProjectInputKind::PyPipfile => "pipenv",
                    ProjectInputKind::Cargo => "cargo",
                    ProjectInputKind::Go => "go",
                    ProjectInputKind::Ruby => "bundler",
                    ProjectInputKind::Php => "composer",
                    ProjectInputKind::Gradle => "gradle",
                    ProjectInputKind::Maven => "maven",
                    ProjectInputKind::Dotnet => "nuget",
                    _ => "pip",
                };
                Some(manager.to_string())
            }),
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

/// Packages routed by a repo `.npmrc` are private: their names are never sent
/// to the public registry or OSV. The route itself is repo-controlled, so in CI
/// it blocks unless the exact route + registry is allowlisted in out-of-repo
/// `trusted_registries.npm` (otherwise a PR could add `.npmrc` to opt a public
/// malicious package out of every check).
pub(crate) fn private_npm_issue(
    dep: &Dependency,
    source: &str,
    registries: &npm_config::NpmRegistries,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Issue {
    let (route, registry) = registries
        .private_route(dep.package_name())
        .expect("private npm issue requires a private route");
    let version = dep.version.as_deref().unwrap_or("locked version");
    let mut issue = if matches!(opts.scan_mode, ScanMode::Ci)
        && !config.is_trusted_npm_registry(route, registry)
    {
        Issue::new(&dep.name, checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE, Severity::Error)
            .message(format!("Package '{}' at {} is routed by the project's .npmrc ({} route) to a registry that is not allowlisted in the sloppy-joe config. A repository-controlled registry redirect cannot opt packages out of public existence, similarity, metadata, and advisory checks.", dep.package_name(), version, route))
            .fix(format!("If this registry is approved, add {{\"name\": \"{route}\", \"source\": \"<registry URL>\"}} to trusted_registries.npm in the out-of-repo sloppy-joe config. Otherwise remove the registry route from .npmrc."))
    } else {
        Issue::new(&dep.name, checks::names::RESOLUTION_PRIVATE_REGISTRY_UNVETTED, Severity::Warning)
            .message(format!("Private registry package '{}' at {} is unvetted: public existence, similarity, metadata, and advisory checks do not verify this registry's contents.", dep.package_name(), version))
            .fix("Review private registry access, upstream provenance, and package contents separately. Private hosting does not guarantee a safe release.")
    };
    issue.source = Some(source.to_string());
    issue
}

pub(crate) async fn scan_parsed_project(
    project: &ParsedProject,
    config: config::SloppyJoeConfig,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    if project.deps.is_empty() && project.unlocked_tooling {
        return Ok(ScanReport::empty());
    }
    let mut config = config;
    if project.unlocked_tooling {
        // No lockfile can pin build tooling, so version-sensitive checks are reported as
        // skipped (warnings) while name-level checks still run and block.
        config.allow_unresolved_versions = true;
    }

    let ecosystem = project.spec.kind.ecosystem();
    let registries = project
        .spec
        .js_binding
        .as_ref()
        .map(|b| b.npm_registries.clone())
        .unwrap_or_default();
    let mut lockfile_data = lockfile_data_for_scan(project, &project.deps, &config, opts)?;
    if project.deps.is_empty()
        && lockfile_data.transitive_deps.is_empty()
        && lockfile_data.resolution.issues.is_empty()
    {
        return Ok(ScanReport::empty());
    }
    let mut private_issues = Vec::new();
    let mut public_deps = Vec::new();
    let mut private_direct = std::collections::HashSet::new();
    for dep in &project.deps {
        if registries.private_registry(dep.package_name()).is_some() {
            private_direct.insert((
                dep.package_name().to_string(),
                lockfile_data
                    .resolution
                    .exact_version(dep)
                    .map(str::to_string),
            ));
            private_issues.push(private_npm_issue(dep, "direct", &registries, &config, opts));
        } else {
            public_deps.push(dep.clone());
        }
    }
    lockfile_data.transitive_deps.retain(|dep| {
        if registries.private_registry(dep.package_name()).is_none() {
            return true;
        }
        if !private_direct.contains(&(dep.package_name().to_string(), dep.version.clone())) {
            private_issues.push(private_npm_issue(
                dep,
                "transitive",
                &registries,
                &config,
                opts,
            ));
        }
        false
    });
    let private_count = private_issues.len();
    let (checkable, non_internal, internal) = classify_deps(&public_deps, &config, ecosystem);

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
        acc.issues.extend(private_issues);
        return Ok(ScanReport::from_issues_with_review_candidates(
            non_internal.len() + private_count,
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
        let internal_resolution = lockfile_data_for_scan(project, &internal, &config, opts)
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

    let transitive_count =
        scan_transitive_dependencies(&lockfile_data, &ctx, &project.deps, &mut acc).await?;

    // Routed (private) package names are never sent to the public registry or
    // OSV. Unallowlisted routes in CI block through `private_issues` instead.
    acc.issues.extend(private_issues);
    Ok(ScanReport::from_issues_with_review_candidates(
        non_internal.len() + transitive_count + private_count,
        acc.issues,
        acc.review_candidates,
    ))
}

#[cfg(test)]
pub(crate) async fn scan_with_services_inner(
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
pub(crate) async fn scan_with_services_inner_for_kind(
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
    if ecosystem == Ecosystem::PyPI
        && let Some(project_kind) = project_kind
    {
        let specs = detected_project_inputs_with_config(project_dir, Some("pypi"), &config)?;
        let preflight_warnings =
            preflight_project_inputs_with_options(project_dir, &specs, &config, opts)?;
        let projects = parse_project_inputs_with_options(project_dir, &specs, &config, opts)?;
        if let Some(project) = projects.into_iter().find(|project| {
            std::mem::discriminant(&project.spec.kind) == std::mem::discriminant(&project_kind)
        }) {
            let mut report =
                scan_parsed_project(&project, config, registry, osv_client, opts).await?;
            report.issues.splice(0..0, preflight_warnings);
            return Ok(report);
        }
    }
    let python_profile = (ecosystem == Ecosystem::PyPI)
        .then(|| active_python_lockfile_profile(opts, &PythonRootExtras::new()));

    // Classify deps into three tiers
    let (checkable, non_internal, internal) = classify_deps(&deps, &config, ecosystem);

    // Parse lockfile once
    let lockfile_data = lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
        project_dir,
        project_kind,
        &non_internal,
        None,
        python_profile.as_ref(),
    )?;

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
            lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
                project_dir,
                project_kind,
                &internal,
                None,
                python_profile.as_ref(),
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

    let transitive_count =
        scan_transitive_dependencies(&lockfile_data, &ctx, &deps, &mut acc).await?;

    Ok(ScanReport::from_issues_with_review_candidates(
        non_internal.len() + transitive_count,
        acc.issues,
        acc.review_candidates,
    ))
}

pub(crate) async fn scan_transitive_dependencies(
    lockfile_data: &lockfiles::LockfileData,
    ctx: &checks::CheckContext<'_>,
    direct_deps: &[Dependency],
    acc: &mut checks::ScanAccumulator,
) -> Result<usize> {
    let direct_resolution = lockfile_data.resolve_transitive(direct_deps)?;
    let direct_versions: std::collections::HashSet<_> = direct_deps
        .iter()
        .filter_map(|dep| {
            direct_resolution
                .exact_version(dep)
                .map(|version| (dep.package_name(), version))
        })
        .collect();
    let transitive_deps: Vec<_> = lockfile_data
        .transitive_deps
        .iter()
        .filter(|dep| {
            !direct_versions.contains(&(
                dep.package_name(),
                dep.version.as_deref().unwrap_or_default(),
            ))
        })
        .cloned()
        .collect();
    let (checkable, non_internal, internal) =
        classify_deps(&transitive_deps, ctx.config, ctx.ecosystem);
    let mut trans_acc = checks::ScanAccumulator::new();
    trans_acc.similarity_flagged = acc.similarity_flagged.clone();
    if !non_internal.is_empty() {
        let resolution = lockfile_data.resolve_transitive(&non_internal)?;
        let trans_ctx = checks::CheckContext {
            checkable_deps: &checkable,
            non_internal_deps: &non_internal,
            resolution: &resolution,
            ..*ctx
        };
        for check in checks::pipeline::default_pipeline() {
            if check.name() != "similarity" || ctx.opts.deep || ctx.ecosystem == Ecosystem::Npm {
                check.run(&trans_ctx, &mut trans_acc).await?;
            }
        }
    }
    if !internal.is_empty() {
        let resolution = lockfile_data.resolve_transitive(&internal)?;
        let internal_ctx = checks::CheckContext {
            checkable_deps: &[],
            non_internal_deps: &internal,
            resolution: &resolution,
            ..*ctx
        };
        checks::pipeline::MaliciousCheck
            .run(&internal_ctx, &mut trans_acc)
            .await?;
    }
    mark_source(&mut trans_acc.issues, "transitive");
    acc.issues.extend(trans_acc.issues);
    acc.review_candidates.extend(trans_acc.review_candidates);
    Ok(non_internal.len())
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
