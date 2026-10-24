use super::*;

mod gradle_plugin_scan;
#[cfg(test)]
pub(crate) use gradle_plugin_scan::implementation_advisory_issues;

pub(super) struct Jvm;

#[async_trait::async_trait]
impl EcosystemSupport for Jvm {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Gradle, ProjectInputKind::Maven]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Gradle => common::named_lockfile(spec),
            // Maven has no trusted lockfile format: scans continue with reduced confidence.
            ProjectInputKind::Maven => None,
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::jvm::parse_manifest(&spec.manifest_path)
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        match spec.kind {
            ProjectInputKind::Gradle => {
                gradle_plugin_scan::parse_gradle_project_input(spec, ctx.config)
            }
            ProjectInputKind::Maven => Ok(ParsedInput {
                deps: self.parse_manifest(ctx.scan_root, spec)?,
                ..ParsedInput::default()
            }),
            other => wrong_plugin(other),
        }
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        project: &ParsedProject,
        deps: &[Dependency],
    ) -> Result<lockfiles::LockfileData> {
        common::read_lockfile_data(project, deps, None)
    }

    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>> {
        Ok(common::kind_for_file_name(self.kinds(), path))
    }

    fn refine_specs(
        &self,
        _scan_root: &Path,
        _config: &config::SloppyJoeConfig,
        _specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()> {
        Ok(())
    }

    fn bind(
        &self,
        _scan_root: &Path,
        _specs: &mut [ProjectInputSpec],
    ) -> std::collections::HashMap<PathBuf, anyhow::Error> {
        std::collections::HashMap::new()
    }

    fn tooling_groups(&self, unlocked: Vec<Dependency>) -> Vec<Vec<Dependency>> {
        // Gradle plugin markers and buildscript classpath artifacts resolve from
        // different repositories, so each group gets its own project.
        let (markers, classpath) = gradle_plugin_scan::split_tooling_deps(unlocked);
        vec![markers, classpath]
    }

    fn scan_registry(
        &self,
        project: &ParsedProject,
        client: reqwest::Client,
    ) -> Result<Option<Box<dyn registry::Registry>>> {
        gradle_plugin_scan::plugin_registry_for(project, client)
    }

    async fn resolve_versions(
        &self,
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

    async fn implementation_issues(
        &self,
        project: &ParsedProject,
        client: reqwest::Client,
        osv_client: &dyn checks::malicious::OsvClient,
        opts: &ScanOptions<'_>,
    ) -> Result<Vec<Issue>> {
        gradle_plugin_scan::project_implementation_issues(project, client, osv_client, opts).await
    }

    fn validate_lockfile(
        &self,
        _ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        match spec.kind {
            ProjectInputKind::Gradle => {
                common::ensure_kind_lockfile(
                    spec,
                    &common::named_lockfile(spec).expect("Gradle names gradle.lockfile"),
                )?;
                common::ensure_no_locked_packages_without_declarations(spec, &parsed.deps)?;
                ensure_gradle_lockfile_pins_dependencies(spec, parsed.deps.len())?;
            }
            // Maven has no lockfile to validate; source_policy states what that means.
            ProjectInputKind::Maven => {}
            other => wrong_plugin(other),
        }
        Ok(Vec::new())
    }

    fn source_policy(
        &self,
        _ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy> {
        match spec.kind {
            ProjectInputKind::Gradle => Ok(SourcePolicy::LockfileBacked(Vec::new())),
            ProjectInputKind::Maven => Ok(SourcePolicy::ReducedConfidence(
                maven_no_lockfile_warning(spec),
            )),
            other => wrong_plugin(other),
        }
    }
}

fn maven_no_lockfile_warning(spec: &ProjectInputSpec) -> Issue {
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
    )
}

/// `gradle.lockfile` lines read `group:artifact:version=configurations`. A lockfile with none of
/// them cannot back declared dependencies.
fn ensure_gradle_lockfile_pins_dependencies(
    spec: &ProjectInputSpec,
    declared: usize,
) -> Result<()> {
    if declared == 0 {
        return Ok(());
    }
    let path = common::named_lockfile(spec).expect("Gradle names gradle.lockfile");
    let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
    let pins = content.lines().any(|line| {
        line.split_once('=')
            .is_some_and(|(coordinates, _)| coordinates.matches(':').count() == 2)
    });
    if !pins {
        anyhow::bail!(
            "Required lockfile '{}' pins no dependencies although the build declares {declared}: the lockfile is malformed or stale. Fix: regenerate it with 'gradle dependencies --write-locks'.",
            path.display()
        );
    }
    Ok(())
}
