//! The four JS package managers as strategies. Binding, preflight and workspace checks pick one
//! by manager and delegate; each states its lockfile files and validation explicitly.

use super::*;

/// Everything that differs between npm, pnpm, yarn and bun. Every method is required.
pub(super) trait JsManager: Sync {
    /// Lockfile file names, in preference order.
    fn lockfile_candidates(&self) -> &'static [&'static str];

    /// The lockfile key of a project that is its own install root.
    fn root_package_entry_key(&self) -> &'static str;

    /// Whether the workspace root's lockfile `content` records the member at `key`. Managers
    /// whose format has no such check keep their existing ownership checks and answer `true`.
    fn lockfile_records_member(&self, path: &Path, content: &str, key: &str) -> Result<bool>;

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
        let lockfile = read_validated_pnpm_lockfile(spec, manifest)?;
        validate_local_pnpm_dependencies(
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

impl JsManager for Yarn {
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
        let lockfile = read_validated_yarn_lockfile(spec, manifest)?;
        validate_local_yarn_dependencies(
            scope_root,
            spec,
            manifest,
            &lockfile,
            &ctx.scan.config.ignore_dirs,
        )?;
        Ok(Vec::new())
    }
}

impl JsManager for Bun {
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
