use super::*;

pub(crate) fn validate_js_manifest_security_policy(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<()> {
    if manifest.get("overrides").is_some() {
        return Err(crate::remedy::problem(
            &crate::remedy::JS_DEPENDENCY_REWRITE,
            format!(
                "package.json '{}' uses npm overrides. Overrides change the resolved dependency graph, and sloppy-joe does not yet have strict override verification.",
                spec.manifest_path.display()
            ),
        ));
    }
    if manifest.get("resolutions").is_some()
        || manifest.get("pnpm").is_some()
        || manifest.get("patchedDependencies").is_some()
    {
        return Err(crate::remedy::problem(
            &crate::remedy::JS_DEPENDENCY_REWRITE,
            format!(
                "Unsupported JS dependency rewrite configuration in '{}': resolutions, pnpm settings and patchedDependencies cannot be verified against the lockfile.",
                spec.manifest_path.display()
            ),
        ));
    }

    Ok(())
}

pub(crate) fn validate_npm_lockfile_version(
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let version = npm_lockfile_version(lockfile, lockfile_path)?;

    if version == 1 && !config.allow_legacy_npm_v1_lockfile {
        return Err(crate::remedy::problem(
            &crate::remedy::NPM_LOCKFILE_UPGRADE,
            format!(
                "This repo is using a legacy npm v5/v6 lockfile ('{}', lockfileVersion: 1). If you must keep it temporarily, set allow_legacy_npm_v1_lockfile to true.",
                lockfile_path.display()
            ),
        ));
    }

    Ok(())
}

/// Whether the Yarn project rooted at `root_dir` uses Yarn Berry (2+) rather than Yarn Classic:
/// the lockfile format decides, then `.yarnrc.yml` (Berry's settings file), then `packageManager`.
pub(crate) fn yarn_is_berry(root_dir: &Path) -> bool {
    let lockfile = root_dir.join("yarn.lock");
    if let Ok(content) = crate::untrusted::read_line_file(&lockfile) {
        return content.contains("__metadata:");
    }
    if crate::parsers::path_detected(&root_dir.join(".yarnrc.yml")).unwrap_or(false) {
        return true;
    }
    read_npm_manifest_value(&root_dir.join("package.json"))
        .ok()
        .and_then(|manifest| {
            let field = manifest.get("packageManager")?.as_str()?.to_string();
            let major = field
                .strip_prefix("yarn@")?
                .split('.')
                .next()?
                .parse::<u32>()
                .ok()?;
            Some(major >= 2)
        })
        .unwrap_or(false)
}

/// The command that writes this JS project's lockfile.
pub(crate) fn js_lockfile_remedy(spec: &ProjectInputSpec) -> &'static crate::remedy::Remedy {
    use crate::remedy::*;
    let Some(binding) = &spec.js_binding else {
        return &NPM_LOCKFILE;
    };
    match binding.manager {
        JsPackageManager::Npm => &NPM_LOCKFILE,
        JsPackageManager::Pnpm => &PNPM_LOCKFILE,
        JsPackageManager::Bun => &BUN_LOCKFILE,
        JsPackageManager::Yarn => {
            let root = binding
                .root_manifest_path
                .parent()
                .unwrap_or_else(|| spec.project_dir());
            if yarn_is_berry(root) {
                &YARN_BERRY_LOCKFILE
            } else {
                &YARN_CLASSIC_LOCKFILE
            }
        }
    }
}

pub(crate) fn ensure_authoritative_js_lockfile_readable(spec: &ProjectInputSpec) -> Result<()> {
    let remedy = js_lockfile_remedy(spec);
    let Some(binding) = &spec.js_binding else {
        return ensure_one_lockfile_readable(
            spec.project_dir(),
            &["npm-shrinkwrap.json", "package-lock.json"],
            remedy,
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
        return Err(crate::remedy::problem(
            &crate::remedy::JS_SHADOW_LOCKFILE,
            format!(
                "Found shadow JS lockfile '{}' under workspace project '{}'. The authoritative {} lockfile lives at '{}'.",
                shadow.display(),
                spec.manifest_path.display(),
                binding.manager.as_str(),
                binding
                    .lockfile_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<missing>".to_string())
            ),
        ));
    }
    let Some(path) = &binding.lockfile_path else {
        let expected = super::managers::manager(binding.manager)
            .lockfile_candidates()
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(" or ");
        return Err(crate::remedy::problem(
            remedy,
            format!(
                "Required lockfile {} is missing for {} project '{}'.",
                expected,
                binding.manager.as_str(),
                spec.manifest_path.display(),
            ),
        ));
    };
    ensure_lockfile_readable(path, remedy)
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn patched_dependencies_block_like_other_rewrites() {
        let spec = ProjectInputSpec {
            kind: ProjectInputKind::Npm,
            manifest_path: std::path::PathBuf::from("/p/package.json"),
            lockfile_path_override: None,
            js_binding: None,
        };
        let patched = serde_json::json!({"dependencies": {"left-pad": "1.3.0"},
            "patchedDependencies": {"left-pad@1.3.0": "patches/left-pad@1.3.0.patch"}});
        let err = validate_js_manifest_security_policy(&spec, &patched)
            .unwrap_err()
            .to_string();
        assert!(err.contains("patchedDependencies"), "{err}");
        let plain = serde_json::json!({"dependencies": {"left-pad": "1.3.0"}});
        assert!(validate_js_manifest_security_policy(&spec, &plain).is_ok());
    }
}
