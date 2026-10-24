use super::*;

pub(super) struct Dotnet;

#[async_trait::async_trait]
impl EcosystemSupport for Dotnet {
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
        &[ProjectInputKind::Dotnet]
    }

    fn ambient_inputs(&self) -> &'static [ambient::AmbientInput] {
        ambient_inputs::AMBIENT
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Dotnet => common::named_lockfile(spec),
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>> {
        let deps = parsers::csproj::parse_file(&spec.manifest_path)?;
        check_project_references(scan_root, &spec.manifest_path)?;
        Ok(deps)
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        let (deps, applied) =
            parsers::csproj::parse_file_with(&spec.manifest_path, &ctx.config.config_key_allow)?;
        check_project_references(ctx.scan_root, &spec.manifest_path)?;
        Ok(ParsedInput {
            deps,
            warnings: crate::config_surface::issues(&applied),
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
        if path.file_name().and_then(|name| name.to_str()) == Some("packages.config") {
            parsers::csproj::reject_packages_config(path)?;
            return Ok(None);
        }
        Ok(parsers::csproj::is_project_file(path).then_some(ProjectInputKind::Dotnet))
    }

    fn refine_specs(
        &self,
        _scan_root: &Path,
        _config: &config::SloppyJoeConfig,
        specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()> {
        reject_shared_directories(specs)
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
        parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        let lockfile = common::named_lockfile(spec).expect("Dotnet names packages.lock.json");
        common::ensure_kind_lockfile(spec, &lockfile)?;
        common::ensure_no_locked_packages_without_declarations(spec, &parsed.deps)?;
        let value = common::read_json_lockfile(&lockfile)?;
        if !matches!(value["version"].as_u64(), Some(1 | 2)) || !value["dependencies"].is_object() {
            anyhow::bail!(
                "Broken lockfile '{}': expected a supported version and dependencies object",
                lockfile.display()
            );
        }
        Ok(Vec::new())
    }

    fn source_policy(
        &self,
        _ctx: &PreflightCtx<'_>,
        _spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy> {
        Ok(SourcePolicy::EnforcedEarlier("manifest parse"))
    }
}

/// One directory with several project files (`.csproj` beside `.fsproj`) would share a single
/// `packages.lock.json`, so the lockfile cannot vouch for each of them.
fn reject_shared_directories(specs: &[ProjectInputSpec]) -> Result<()> {
    let mut seen = std::collections::HashMap::new();
    for spec in specs
        .iter()
        .filter(|spec| spec.kind == ProjectInputKind::Dotnet)
    {
        if let Some(first) = seen.insert(spec.project_dir().to_path_buf(), &spec.manifest_path) {
            anyhow::bail!(
                "Ambiguous .NET project directory {}: {} and {} share one packages.lock.json",
                spec.project_dir().display(),
                first.display(),
                spec.manifest_path.display()
            );
        }
    }
    Ok(())
}

/// A `<ProjectReference>` builds another project's code and packages with this one. It must exist
/// inside the scan root, where discovery scans it like any other project.
fn check_project_references(scan_root: &Path, manifest: &Path) -> Result<()> {
    let root = std::fs::canonicalize(scan_root)?;
    let dir = manifest.parent().unwrap_or(Path::new("."));
    for include in parsers::csproj::project_reference_includes(manifest)? {
        let target = dir.join(include.replace('\\', "/"));
        match std::fs::canonicalize(&target) {
            Ok(resolved) if resolved.starts_with(&root) => {}
            _ => anyhow::bail!(
                "Unsupported ProjectReference '{}' in {}: the target must exist inside the scan root to be scanned",
                crate::report::sanitize_for_terminal(&include),
                manifest.display()
            ),
        }
    }
    Ok(())
}

/// Repository files MSBuild and NuGet read beside a .NET project and in every directory above it.
mod ambient_inputs {
    use crate::ecosystems::ambient::{AmbientInput as Row, Disposition::*, Scope::*};

    const GENERATED_WHY: &str = "MSBuild imports NuGet's generated props and targets from obj/ during build, and a committed copy can carry any content. Fix: do not commit obj/.";
    const IMPLICIT_IMPORT: &str = "implicit dependency imports are not trusted yet";

    pub(super) const AMBIENT: &[Row] = &[
        Row::new(
            "Directory.Build.props",
            AncestorsToRepoRoot,
            Blocked(IMPLICIT_IMPORT),
        ),
        Row::new(
            "Directory.Build.targets",
            AncestorsToRepoRoot,
            Blocked(IMPLICIT_IMPORT),
        ),
        Row::new(
            "Directory.Build.rsp",
            AncestorsToRepoRoot,
            Blocked(IMPLICIT_IMPORT),
        ),
        Row::new(
            "Directory.Packages.props",
            AncestorsToRepoRoot,
            Blocked(IMPLICIT_IMPORT),
        ),
        Row::new(
            "Directory.Solution.props",
            AncestorsToRepoRoot,
            Blocked(IMPLICIT_IMPORT),
        ),
        Row::new(
            "Directory.Solution.targets",
            AncestorsToRepoRoot,
            Blocked(IMPLICIT_IMPORT),
        ),
        Row::new(
            "nuget.config",
            AncestorsToRepoRoot,
            ModeledElsewhere(
                "parsers::nuget_config (nuget.config allowlist), with config_key_allow",
            ),
        ),
        Row::new(
            "global.json",
            AncestorsToRepoRoot,
            ModeledElsewhere("parsers::csproj::reject_global_json_msbuild_sdks"),
        ),
        Row::new(
            ".config/dotnet-tools.json",
            AncestorsToRepoRoot,
            ModeledElsewhere("parsers::csproj_hooks::reject_local_tools"),
        ),
        Row::new(
            "*.csproj.user",
            ProjectDir,
            ModeledElsewhere(
                "parsers::csproj::reject_user_file (MSBuild imports it unconditionally)",
            ),
        ),
        Row::new(
            "obj/*.nuget.g.props",
            ProjectDir,
            BlockedIfTracked(GENERATED_WHY),
        ),
        Row::new(
            "obj/*.nuget.g.targets",
            ProjectDir,
            BlockedIfTracked(GENERATED_WHY),
        ),
        Row::new(
            "obj/*.props",
            ProjectDir,
            ModeledElsewhere(
                "parsers::csproj_hooks (obj extension imports NuGet did not generate)",
            ),
        ),
        Row::new(
            "obj/*.targets",
            ProjectDir,
            ModeledElsewhere(
                "parsers::csproj_hooks (obj extension imports NuGet did not generate)",
            ),
        ),
    ];
}

#[cfg(test)]
mod project_reference_tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "sj-dotnet-refs-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        for (path, content) in files {
            let full = root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        root
    }

    fn spec(root: &Path, manifest: &str) -> ProjectInputSpec {
        ProjectInputSpec {
            kind: ProjectInputKind::Dotnet,
            manifest_path: root.join(manifest),
            lockfile_path_override: None,
            js_binding: None,
        }
    }

    const PROJECT: &str = "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"REF\" /></ItemGroup></Project>";

    #[test]
    fn a_project_reference_must_exist_inside_the_scan_root() {
        let root = tree(&[
            (
                "app/app.csproj",
                &PROJECT.replace("REF", "..\\lib\\lib.csproj"),
            ),
            ("lib/lib.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
        ]);
        check_project_references(&root, &root.join("app/app.csproj")).unwrap();

        for target in ["../evil/evil.csproj", "../../outside.csproj"] {
            let root = tree(&[("app/app.csproj", &PROJECT.replace("REF", target))]);
            let err = check_project_references(&root, &root.join("app/app.csproj"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("ProjectReference"), "{target}: {err}");
        }
    }

    #[test]
    fn two_project_files_in_one_directory_are_ambiguous() {
        let root = tree(&[("a.csproj", "<Project />"), ("a.fsproj", "<Project />")]);
        let specs = [spec(&root, "a.csproj"), spec(&root, "a.fsproj")];
        assert!(reject_shared_directories(&specs).is_err());
        assert!(reject_shared_directories(&specs[..1]).is_ok());
    }
}
