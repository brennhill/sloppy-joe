use super::*;

pub(super) struct Go;

#[async_trait::async_trait]
impl EcosystemSupport for Go {
    fn scan_registry(
        &self,
        _project: &ParsedProject,
        _client: reqwest::Client,
    ) -> Result<Option<Box<dyn registry::Registry>>> {
        Ok(None)
    }

    async fn resolve_versions(
        &self,
        _project: &ParsedProject,
        _client: &reqwest::Client,
    ) -> Result<Option<ParsedProject>> {
        Ok(None)
    }

    async fn implementation_issues(
        &self,
        _project: &ParsedProject,
        _client: reqwest::Client,
        _osv_client: &dyn checks::malicious::OsvClient,
        _opts: &ScanOptions<'_>,
    ) -> Result<Vec<Issue>> {
        Ok(Vec::new())
    }

    fn similarity_on_transitives(&self) -> bool {
        false
    }

    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Go]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Go => common::named_lockfile(spec),
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::go_mod::parse(spec.project_dir())
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        Ok(ParsedInput {
            deps: self.parse_manifest(ctx.scan_root, spec)?,
            ..ParsedInput::default()
        })
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
        vec![unlocked]
    }

    fn validate_lockfile(
        &self,
        _ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        Ok(check_go_sum(spec)?.into_iter().collect())
    }

    fn source_policy(
        &self,
        _ctx: &PreflightCtx<'_>,
        _spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy> {
        Ok(SourcePolicy::EnforcedEarlier("manifest parse"))
    }
}

/// Go never checks vendored files against go.sum, so edited vendored code cannot be detected.
fn vendored_source_warning(spec: &ProjectInputSpec) -> Issue {
    Issue::new(
        spec.manifest_path.display().to_string(),
        checks::names::RESOLUTION_VENDORED_SOURCE_UNVERIFIED,
        Severity::Warning,
    )
    .message(
        "vendor/ is used for the build; Go does not verify vendored files against go.sum, so the vendored source may differ from the module versions that were scanned.",
    )
    .fix("Compare the vendor directory with `go mod vendor` output in CI (for example `go mod vendor && git diff --exit-code vendor`).")
}

fn check_go_sum(spec: &ProjectInputSpec) -> Result<Option<Issue>> {
    let manifest_content =
        parsers::read_file_limited(&spec.manifest_path, parsers::MAX_MANIFEST_BYTES)
            .map_err(|err| common::broken_manifest(spec, err))?;
    if !parsers::go_mod::requires_go_sum(&manifest_content) {
        return Ok(None);
    }
    let go_sum_path = common::named_lockfile(spec).expect("Go names go.sum");
    common::ensure_kind_lockfile(spec, &go_sum_path)?;
    // Vendored builds (go >= 1.14 with vendor/modules.txt) ignore go.sum, so the vendor listing
    // must cover go.mod instead. Its mere existence is not a substitute for either check.
    let modules_txt = spec.project_dir().join("vendor/modules.txt");
    if modules_txt.is_file() && parsers::go_mod::vendoring_applies(&manifest_content) {
        let listing = parsers::read_file_limited(&modules_txt, parsers::MAX_MANIFEST_BYTES)?;
        parsers::go_mod::check_vendor_modules(&manifest_content, &listing).map_err(|err| {
            anyhow::anyhow!(
                "Broken vendor directory '{}': {}",
                modules_txt.display(),
                err
            )
        })?;
        return Ok(Some(vendored_source_warning(spec)));
    }
    let go_sum = parsers::read_file_limited(&go_sum_path, parsers::MAX_MANIFEST_BYTES)?;
    parsers::go_mod::check_go_sum_entries(&manifest_content, &go_sum)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", go_sum_path.display(), err))?;
    Ok(None)
}

#[cfg(test)]
mod vendor_tests {
    use super::*;

    const HASH: &str = "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=";

    fn project(go_mod: &str, go_sum: &str, modules_txt: Option<&str>) -> ProjectInputSpec {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sj-go-vendor-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(dir.join("vendor")).unwrap();
        std::fs::write(dir.join("go.mod"), go_mod).unwrap();
        std::fs::write(dir.join("go.sum"), go_sum).unwrap();
        if let Some(listing) = modules_txt {
            std::fs::write(dir.join("vendor/modules.txt"), listing).unwrap();
        }
        ProjectInputSpec {
            kind: ProjectInputKind::Go,
            manifest_path: dir.join("go.mod"),
            lockfile_path_override: None,
            js_binding: None,
        }
    }

    const GO_MOD: &str = "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n";

    #[test]
    fn an_unrelated_vendor_listing_does_not_switch_off_the_checks() {
        // The red-team case: go.sum lacks the module and a one-line modules.txt "vendors" it.
        let spec = project(
            GO_MOD,
            &format!("example.com/other v1.0.0/go.mod {HASH}\n"),
            Some("# example.com/unrelated v1.0.0\n"),
        );
        let err = check_go_sum(&spec).unwrap_err().to_string();
        assert!(err.contains("vendor/modules.txt"), "{err}");
        // Without vendoring the same go.sum is rejected as before.
        let spec = project(
            GO_MOD,
            &format!("example.com/other v1.0.0/go.mod {HASH}\n"),
            None,
        );
        assert!(check_go_sum(&spec).is_err());
    }

    #[test]
    fn a_vendor_listing_that_covers_go_mod_replaces_go_sum_entries() {
        let listing =
            "# golang.org/x/text v0.14.0\n## explicit; go 1.18\ngolang.org/x/text/unicode\n";
        let spec = project(
            GO_MOD,
            &format!("example.com/other v1.0.0/go.mod {HASH}\n"),
            Some(listing),
        );
        let warning = check_go_sum(&spec).unwrap().expect("vendored builds warn");
        assert_eq!(
            warning.check,
            checks::names::RESOLUTION_VENDORED_SOURCE_UNVERIFIED
        );
    }

    #[test]
    fn a_vendor_directory_is_ignored_by_go_before_1_14() {
        let old = "module example.com/app\n\ngo 1.13\n\nrequire golang.org/x/text v0.14.0\n";
        let listing = "# golang.org/x/text v0.14.0\n";
        let spec = project(
            old,
            &format!("example.com/other v1.0.0/go.mod {HASH}\n"),
            Some(listing),
        );
        assert!(check_go_sum(&spec).is_err(), "go.sum still governs");
    }
}
