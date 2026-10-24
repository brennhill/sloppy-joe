//! The four JS package managers as strategies. Binding, preflight and workspace checks pick one
//! by manager and delegate; each states its lockfile files and validation explicitly.

use super::*;

/// Everything that differs between npm, pnpm, yarn and bun. Every method is required.
pub(super) trait JsManager: Sync {
    /// Lockfile file names, in preference order.
    fn lockfile_candidates(&self) -> &'static [&'static str];

    /// Files whose presence at an install root signals this manager (lockfiles and workspace or
    /// plug'n'play markers).
    fn root_markers(&self) -> &'static [&'static str];

    /// Config files that only this manager reads; their registry redirects and dependency
    /// rewrites cannot be verified, so their presence blocks.
    fn unverifiable_config_files(&self) -> &'static [&'static str];

    /// Check this manager's structured settings file in `dir` against its allowlist: denied
    /// settings block now, unlisted ones come back deferred until the operator's config is known.
    fn check_settings_file(&self, dir: &Path) -> Result<Vec<crate::config_surface::DeferredKey>>;

    /// The lockfile key of a project that is its own install root.
    fn root_package_entry_key(&self) -> &'static str;

    /// Whether the workspace root's lockfile `content` records the member at `key`. Managers
    /// whose format has no such check keep their existing ownership checks and answer `true`.
    fn lockfile_records_member(&self, path: &Path, content: &str, key: &str) -> Result<bool>;

    /// Workspace member patterns declared for this manager: in `package.json` for npm, yarn and
    /// bun, in `pnpm-workspace.yaml` for pnpm.
    fn declared_workspaces(
        &self,
        workspace_dir: &Path,
        manifest_path: &Path,
        manifest: &serde_json::Value,
    ) -> Result<Option<Vec<String>>>;

    /// Read the lockfile against the manifest and verify local (workspace, path) dependencies.
    /// Errors block; the returned issues are warnings.
    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        manifest: &serde_json::Value,
        scope_root: &Path,
    ) -> Result<Vec<Issue>>;
}

/// Every manager, in the order their signals are reported.
pub(super) const ALL: [JsPackageManager; 4] = [
    JsPackageManager::Npm,
    JsPackageManager::Pnpm,
    JsPackageManager::Yarn,
    JsPackageManager::Bun,
];

pub(super) fn manager(manager: JsPackageManager) -> &'static dyn JsManager {
    match manager {
        JsPackageManager::Npm => &Npm,
        JsPackageManager::Pnpm => &Pnpm,
        JsPackageManager::Yarn => &Yarn,
        JsPackageManager::Bun => &Bun,
    }
}

struct Npm;
struct Pnpm;
struct Yarn;
struct Bun;

impl JsManager for Npm {
    fn root_markers(&self) -> &'static [&'static str] {
        &["npm-shrinkwrap.json", "package-lock.json"]
    }

    fn unverifiable_config_files(&self) -> &'static [&'static str] {
        &[]
    }

    fn check_settings_file(&self, _dir: &Path) -> Result<Vec<crate::config_surface::DeferredKey>> {
        Ok(Vec::new())
    }

    fn declared_workspaces(
        &self,
        _workspace_dir: &Path,
        manifest_path: &Path,
        manifest: &serde_json::Value,
    ) -> Result<Option<Vec<String>>> {
        parse_npm_workspaces(manifest_path, manifest)
    }

    fn lockfile_candidates(&self) -> &'static [&'static str] {
        &["npm-shrinkwrap.json", "package-lock.json"]
    }

    fn root_package_entry_key(&self) -> &'static str {
        ""
    }

    fn lockfile_records_member(&self, path: &Path, content: &str, key: &str) -> Result<bool> {
        let value: serde_json::Value = serde_json::from_str(content)
            .map_err(|error| anyhow::anyhow!("Broken lockfile '{}': {error}", path.display()))?;
        Ok(value
            .get("packages")
            .and_then(|entries| entries.get(key))
            .is_some())
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        manifest: &serde_json::Value,
        scope_root: &Path,
    ) -> Result<Vec<Issue>> {
        let allowed_alias_targets = selected_lockfile_path(spec)
            .and_then(|path| ctx.js.alias_targets.get(&path))
            .cloned()
            .unwrap_or_default();
        let (lockfile, warnings) =
            read_validated_npm_lockfile(spec, manifest, ctx.scan.config, &allowed_alias_targets)?;
        validate_local_npm_dependencies(scope_root, spec, manifest, &lockfile, &ctx.js.index)?;
        Ok(warnings)
    }
}

impl JsManager for Pnpm {
    fn root_markers(&self) -> &'static [&'static str] {
        &["pnpm-lock.yaml", "pnpm-workspace.yaml"]
    }

    fn unverifiable_config_files(&self) -> &'static [&'static str] {
        // pnpm loads whichever of these exists (`.mjs` since pnpm 10); each runs code at install.
        &[
            ".pnpmfile.cjs",
            ".pnpmfile.mjs",
            ".pnpmfile.js",
            ".pnpmfile.mts",
            ".pnpmfile.cts",
            ".pnpmfile.ts",
        ]
    }

    fn check_settings_file(&self, dir: &Path) -> Result<Vec<crate::config_surface::DeferredKey>> {
        super::config_surfaces::check_pnpm_workspace(dir)
    }

    fn declared_workspaces(
        &self,
        workspace_dir: &Path,
        _manifest_path: &Path,
        _manifest: &serde_json::Value,
    ) -> Result<Option<Vec<String>>> {
        parse_pnpm_workspaces(workspace_dir)
    }

    fn lockfile_candidates(&self) -> &'static [&'static str] {
        &["pnpm-lock.yaml"]
    }

    fn root_package_entry_key(&self) -> &'static str {
        "."
    }

    fn lockfile_records_member(&self, path: &Path, content: &str, key: &str) -> Result<bool> {
        let value: serde_yaml::Value = crate::lockfiles::parse_pnpm_lock_guarded(content)
            .map_err(|error| anyhow::anyhow!("Broken lockfile '{}': {error}", path.display()))?;
        Ok(value
            .get("importers")
            .and_then(|entries| entries.get(key))
            .is_some())
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        manifest: &serde_json::Value,
        scope_root: &Path,
    ) -> Result<Vec<Issue>> {
        let (lockfile, warnings) = read_validated_pnpm_lockfile(spec, manifest, ctx.scan.config)?;
        validate_local_pnpm_dependencies(
            scope_root,
            spec,
            manifest,
            &lockfile,
            &ctx.js.index,
            &ctx.scan.config.ignore_dirs,
        )?;
        Ok(warnings)
    }
}

impl JsManager for Yarn {
    fn root_markers(&self) -> &'static [&'static str] {
        &["yarn.lock", ".pnp.cjs"]
    }

    fn unverifiable_config_files(&self) -> &'static [&'static str] {
        &[".yarnrc"]
    }

    fn check_settings_file(&self, dir: &Path) -> Result<Vec<crate::config_surface::DeferredKey>> {
        super::config_surfaces::check_yarnrc_yml(dir)
    }

    fn declared_workspaces(
        &self,
        _workspace_dir: &Path,
        manifest_path: &Path,
        manifest: &serde_json::Value,
    ) -> Result<Option<Vec<String>>> {
        parse_npm_workspaces(manifest_path, manifest)
    }

    fn lockfile_candidates(&self) -> &'static [&'static str] {
        &["yarn.lock"]
    }

    fn root_package_entry_key(&self) -> &'static str {
        ""
    }

    fn lockfile_records_member(&self, _path: &Path, _content: &str, _key: &str) -> Result<bool> {
        Ok(true)
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        manifest: &serde_json::Value,
        scope_root: &Path,
    ) -> Result<Vec<Issue>> {
        let (lockfile, warnings) = read_validated_yarn_lockfile(spec, manifest, ctx.scan.config)?;
        validate_local_yarn_dependencies(
            scope_root,
            spec,
            manifest,
            &lockfile,
            &ctx.scan.config.ignore_dirs,
        )?;
        Ok(warnings)
    }
}

impl JsManager for Bun {
    fn root_markers(&self) -> &'static [&'static str] {
        &["bun.lock", "bun.lockb"]
    }

    fn unverifiable_config_files(&self) -> &'static [&'static str] {
        &[]
    }

    fn check_settings_file(&self, dir: &Path) -> Result<Vec<crate::config_surface::DeferredKey>> {
        super::config_surfaces::check_bunfig(dir)
    }

    fn declared_workspaces(
        &self,
        _workspace_dir: &Path,
        manifest_path: &Path,
        manifest: &serde_json::Value,
    ) -> Result<Option<Vec<String>>> {
        parse_npm_workspaces(manifest_path, manifest)
    }

    fn lockfile_candidates(&self) -> &'static [&'static str] {
        &["bun.lock", "bun.lockb"]
    }

    fn root_package_entry_key(&self) -> &'static str {
        ""
    }

    fn lockfile_records_member(&self, _path: &Path, _content: &str, _key: &str) -> Result<bool> {
        Ok(true)
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        manifest: &serde_json::Value,
        scope_root: &Path,
    ) -> Result<Vec<Issue>> {
        let lockfile = read_validated_bun_lockfile(spec, manifest)?;
        validate_local_bun_dependencies(
            scope_root,
            spec,
            manifest,
            &lockfile,
            &ctx.js.index,
            &ctx.scan.config.ignore_dirs,
        )?;
        Ok(Vec::new())
    }
}
