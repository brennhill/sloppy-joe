use super::*;

pub(crate) fn validate_js_manifest_security_policy(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<()> {
    if manifest.get("overrides").is_some() {
        anyhow::bail!(
            "package.json '{}' uses npm overrides. Overrides change the resolved dependency graph, and sloppy-joe does not yet have strict override verification. Remove overrides or review this project with another control until strict support exists.",
            spec.manifest_path.display()
        );
    }
    if manifest.get("resolutions").is_some()
        || manifest.get("pnpm").is_some()
        || manifest.get("patchedDependencies").is_some()
    {
        anyhow::bail!(
            "Unsupported JS dependency rewrite configuration in '{}': resolutions, pnpm settings and patchedDependencies cannot be verified against the lockfile",
            spec.manifest_path.display()
        );
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
        anyhow::bail!(
            "This repo is using a legacy npm v5/v6 lockfile ('{}', lockfileVersion: 1). Regenerate with a modern npm. If you must keep it temporarily, set allow_legacy_npm_v1_lockfile to true.",
            lockfile_path.display()
        );
    }

    Ok(())
}

fn js_lockfile_help(spec: &ProjectInputSpec) -> String {
    match spec.js_binding.as_ref().map(|binding| binding.manager) {
        Some(JsPackageManager::Pnpm) => {
            "Run `pnpm install --lockfile-only` and commit pnpm-lock.yaml.".to_string()
        }
        Some(JsPackageManager::Yarn) => {
            "Commit the authoritative yarn.lock for this project.".to_string()
        }
        Some(JsPackageManager::Bun) => {
            "Commit the authoritative bun.lock or bun.lockb for this project.".to_string()
        }
        _ => spec
            .kind
            .missing_lockfile_help()
            .unwrap_or("Commit the authoritative lockfile for this project.")
            .to_string(),
    }
}

pub(crate) fn ensure_authoritative_js_lockfile_readable(spec: &ProjectInputSpec) -> Result<()> {
    let help = js_lockfile_help(spec);
    let Some(binding) = &spec.js_binding else {
        return ensure_one_lockfile_readable(
            spec.project_dir(),
            &["npm-shrinkwrap.json", "package-lock.json"],
            &help,
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
        anyhow::bail!(
            "Found shadow JS lockfile '{}' under workspace project '{}'. The authoritative {} lockfile lives at '{}'. Remove the child lockfile and keep the workspace root lockfile as the single source of truth.",
            shadow.display(),
            spec.manifest_path.display(),
            binding.manager.as_str(),
            binding
                .lockfile_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<missing>".to_string())
        );
    }
    let Some(path) = &binding.lockfile_path else {
        let expected = super::managers::manager(binding.manager)
            .lockfile_candidates()
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(" or ");
        anyhow::bail!(
            "Required lockfile {} is missing for {} project '{}'. Fix: {}",
            expected,
            binding.manager.as_str(),
            spec.manifest_path.display(),
            help
        );
    };
    ensure_lockfile_readable(path, &help)
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
