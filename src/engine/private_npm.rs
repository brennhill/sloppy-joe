use crate::*;

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
) -> Issue {
    let (route, registry) = registries
        .private_route(dep.package_name())
        .expect("private npm issue requires a private route");
    let version = dep.version.as_deref().unwrap_or("locked version");
    // A route the repository controls and the out-of-repo config does not allowlist blocks in
    // every mode (like yarn's `npmRegistryServer`); an allowlisted route is trusted but unvetted.
    let mut issue = if !config.is_trusted_npm_registry(route, registry) {
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
    let mut lockfile_data = ecosystems::lockfile_data(&config, opts, project, &project.deps)?;
    if project.deps.is_empty()
        && lockfile_data.gated_direct_deps.is_empty()
        && lockfile_data.transitive_deps.is_empty()
        && lockfile_data.resolution.issues.is_empty()
    {
        return Ok(ScanReport::empty());
    }
    let mut private_issues = Vec::new();
    let mut public_deps = Vec::new();
    let mut private_direct = std::collections::HashSet::new();
    // Direct dependencies of other environments get the same direct checks; the plugin has
    // already resolved their versions and kept them out of the transitive list.
    for dep in project.deps.iter().chain(&lockfile_data.gated_direct_deps) {
        if registries.private_registry(dep.package_name()).is_some() {
            private_direct.insert((
                dep.package_name().to_string(),
                lockfile_data
                    .resolution
                    .exact_version(dep)
                    .map(str::to_string),
            ));
            private_issues.push(private_npm_issue(dep, "direct", &registries, &config));
        } else {
            public_deps.push(dep.clone());
        }
    }
    lockfile_data.transitive_deps.retain(|dep| {
        if registries.private_registry(dep.package_name()).is_none() {
            return true;
        }
        if !private_direct.contains(&(dep.package_name().to_string(), dep.version.clone())) {
            private_issues.push(private_npm_issue(dep, "transitive", &registries, &config));
        }
        false
    });
    let private_count = private_issues.len();
    let ProvenTiers {
        checkable,
        non_internal,
        internal,
        issues: proof_issues,
    } = classify_direct_deps(&public_deps, &config, ecosystem, registry, opts).await;

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
        acc.issues
            .extend(checks::unresolved::unresolved_version_policy_issues(
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
    acc.issues.extend(proof_issues);
    mark_source(&mut acc.issues, "direct");

    if !internal.is_empty() {
        // A lockfile that cannot be read for internal packages blocks: scanning them with no
        // resolved versions would skip their advisory checks silently.
        let internal_resolution =
            ecosystems::lockfile_data(&config, opts, project, &internal)?.resolution;
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
        if let Some(project) = projects
            .into_iter()
            .find(|project| project.spec.kind == project_kind)
        {
            let mut report =
                scan_parsed_project(&project, config, registry, osv_client, opts).await?;
            report.issues.splice(0..0, preflight_warnings);
            return Ok(report);
        }
    }
    let python_profile = (ecosystem == Ecosystem::PyPI)
        .then(|| active_python_lockfile_profile(opts, &PythonRootExtras::new()));

    // Classify deps into three tiers
    let ProvenTiers {
        checkable,
        non_internal,
        internal,
        issues: proof_issues,
    } = classify_direct_deps(&deps, &config, ecosystem, registry, opts).await;

    let lockfile_kind = project_kind.map_or_else(
        || lockfiles::LockfileKind::for_ecosystem(Some(ecosystem)),
        |kind| kind.lockfile_kind(),
    );

    // Parse lockfile once
    let lockfile_data = lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
        project_dir,
        lockfile_kind,
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
    acc.issues.extend(proof_issues);
    mark_source(&mut acc.issues, "direct");

    // Run OSV on internal packages (they skip all other checks but still need vuln scanning)
    if !internal.is_empty() {
        let internal_resolution =
            lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
                project_dir,
                lockfile_kind,
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
    let ProvenTiers {
        checkable,
        non_internal,
        internal,
        issues: proof_issues,
    } = classify_deps_with_source_proof(
        &transitive_deps,
        ctx.config,
        ctx.ecosystem,
        ctx.registry,
        "transitive",
    )
    .await;
    let mut trans_acc = checks::ScanAccumulator::new();
    trans_acc.issues.extend(proof_issues);
    trans_acc.similarity_flagged = acc.similarity_flagged.clone();
    if !non_internal.is_empty() {
        let resolution = lockfile_data.resolve_transitive(&non_internal)?;
        let trans_ctx = checks::CheckContext {
            checkable_deps: &checkable,
            non_internal_deps: &non_internal,
            resolution: &resolution,
            ..*ctx
        };
        let similarity_on_transitives =
            ecosystems::for_ecosystem(ctx.ecosystem)?.similarity_on_transitives();
        for check in checks::pipeline::default_pipeline() {
            if check.name() != "similarity" || ctx.opts.deep || similarity_on_transitives {
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
