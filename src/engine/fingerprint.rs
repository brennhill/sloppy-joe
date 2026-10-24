use crate::*;

pub(crate) fn hash_json_value_canonical(
    value: &serde_json::Value,
    hasher: &mut std::collections::hash_map::DefaultHasher,
) {
    use std::hash::Hash;

    match value {
        serde_json::Value::Null => 0u8.hash(hasher),
        serde_json::Value::Bool(flag) => {
            1u8.hash(hasher);
            flag.hash(hasher);
        }
        serde_json::Value::Number(number) => {
            2u8.hash(hasher);
            number.to_string().hash(hasher);
        }
        serde_json::Value::String(string) => {
            3u8.hash(hasher);
            string.hash(hasher);
        }
        serde_json::Value::Array(items) => {
            4u8.hash(hasher);
            items.len().hash(hasher);
            for item in items {
                hash_json_value_canonical(item, hasher);
            }
        }
        serde_json::Value::Object(map) => {
            5u8.hash(hasher);
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            keys.len().hash(hasher);
            for key in keys {
                key.hash(hasher);
                hash_json_value_canonical(&map[key], hasher);
            }
        }
    }
}

pub(crate) fn policy_hash_value(
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<serde_json::Value, String> {
    serde_json::to_value(serde_json::json!({
        "config": config,
        "options": {
            "deep": opts.deep,
            "paranoid": opts.paranoid,
            "review_exceptions": opts.review_exceptions,
            "python_groups": opts.python_groups,
            "python_extras": opts.python_extras,
            "python_platform": opts.python_platform,
            "python_arch": opts.python_arch,
            "python_version": opts.python_version,
        },
        "hash_contract_version": 3u8,
    }))
    .map_err(|err| format!("cannot serialize scan policy for hashing: {err}"))
}

pub(crate) fn policy_hash_u64(
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<u64, String> {
    use std::hash::Hasher;
    let policy = policy_hash_value(config, opts)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hash_json_value_canonical(&policy, &mut hasher);
    Ok(hasher.finish())
}

pub(crate) fn project_state_hash_for_projects(
    projects: &[ParsedProject],
) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    type ProjectHashTuple<'a> = (String, &'a str, Option<&'a str>, &'a str, Option<&'a str>);

    let mut tuples: Vec<ProjectHashTuple<'_>> = projects
        .iter()
        .flat_map(|project| {
            project.deps.iter().map(|dep| {
                (
                    project.spec.manifest_path.display().to_string(),
                    dep.name.as_str(),
                    dep.version.as_deref(),
                    dep.ecosystem.as_str(),
                    dep.actual_name.as_deref(),
                )
            })
        })
        .collect();
    tuples.sort();
    tuples.hash(&mut hasher);
    for project in projects {
        project
            .spec
            .js_binding
            .as_ref()
            .map(|b| &b.npm_registries)
            .hash(&mut hasher);
    }

    let mut hashed_manifests = std::collections::HashSet::new();
    let mut manifests: Vec<_> = projects
        .iter()
        .map(|project| project.spec.manifest_path.clone())
        .filter(|path| hashed_manifests.insert(path.clone()))
        .collect();
    manifests.sort();

    for path in manifests {
        let content = parsers::read_bytes_limited(&path, parsers::MAX_MANIFEST_BYTES)
            .map_err(|err| format!("cannot safely hash {}: {}", path.display(), err))?;
        path.display().to_string().hash(&mut hasher);
        content.hash(&mut hasher);
    }

    let mut hashed_lockfiles = std::collections::HashSet::new();
    let mut lockfiles: Vec<_> = projects
        .iter()
        .flat_map(|project| lockfile_paths_for_project(&project.spec))
        .filter(|path| hashed_lockfiles.insert(path.clone()))
        .collect();
    lockfiles.sort();

    for path in lockfiles {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let content = parsers::read_bytes_limited(&path, parsers::MAX_MANIFEST_BYTES)
                    .map_err(|err| format!("cannot safely hash {}: {}", path.display(), err))?;
                path.display().to_string().hash(&mut hasher);
                content.hash(&mut hasher);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!("cannot safely hash {}: {}", path.display(), err));
            }
        }
    }

    Ok(hasher.finish())
}

pub(crate) fn project_binding_hash_for_projects(projects: &[ParsedProject]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    let mut bindings: Vec<_> = projects
        .iter()
        .map(|project| {
            (
                project.spec.manifest_path.display().to_string(),
                project.spec.kind.manifest_label(),
                project.spec.js_binding.as_ref().map(|binding| {
                    (
                        binding.manager.as_str(),
                        binding.root_manifest_path.display().to_string(),
                        binding
                            .lockfile_path
                            .as_ref()
                            .map(|path| path.display().to_string()),
                        binding.package_entry_key.clone(),
                        binding.npm_registries.clone(),
                        binding.independent_from_workspace.clone(),
                    )
                }),
            )
        })
        .collect::<Vec<_>>();
    bindings.sort();
    bindings.hash(&mut hasher);
    hasher.finish()
}

pub(crate) fn scan_hash_for_projects(
    projects: &[ParsedProject],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    project_state_hash_for_projects(projects)?.hash(&mut hasher);

    let policy = policy_hash_value(config, opts)?;
    hash_json_value_canonical(&policy, &mut hasher);

    Ok(hasher.finish())
}

#[cfg(test)]
pub(crate) fn scan_hash_for_projects_with_policy(
    projects: &[ParsedProject],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<u64, String> {
    scan_hash_for_projects(projects, config, opts)
}

/// Compute a hash of dependency tuples + lockfile content for change detection.
/// Includes lockfile so that resolved version changes (e.g., a compromised upstream
/// version satisfying the same range) invalidate the cache even when the manifest
/// is unchanged. If a known lockfile exists but cannot be safely hashed, hash-based
/// scan skipping is disabled for the run.
#[cfg(test)]
pub(crate) fn scan_hash(
    project_dir: &std::path::Path,
    deps: &[Dependency],
) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // Hash sorted dep tuples (manifest content)
    let mut tuples: Vec<(&str, Option<&str>, &str, Option<&str>)> = deps
        .iter()
        .map(|d| {
            (
                d.name.as_str(),
                d.version.as_deref(),
                d.ecosystem.as_str(),
                d.actual_name.as_deref(),
            )
        })
        .collect();
    tuples.sort();
    tuples.hash(&mut hasher);

    let lockfiles: Vec<std::path::PathBuf> = match deps.first().map(|dep| dep.ecosystem) {
        Some(Ecosystem::Npm) => {
            first_existing_lockfile(project_dir, &["npm-shrinkwrap.json", "package-lock.json"])
                .into_iter()
                .collect()
        }
        Some(Ecosystem::Cargo) => vec![project_dir.join("Cargo.lock")],
        Some(Ecosystem::Go) => vec![project_dir.join("go.sum")],
        Some(Ecosystem::Ruby) => vec![project_dir.join("Gemfile.lock")],
        Some(Ecosystem::PyPI) => vec![project_dir.join("poetry.lock")],
        Some(Ecosystem::Php) => vec![project_dir.join("composer.lock")],
        Some(Ecosystem::Jvm) => vec![project_dir.join("gradle.lockfile")],
        Some(Ecosystem::Dotnet) => vec![project_dir.join("packages.lock.json")],
        None => Vec::new(),
    };

    // Hash lockfile content (resolved versions) — catches upstream version changes
    for path in lockfiles {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let content = parsers::read_bytes_limited(&path, parsers::MAX_MANIFEST_BYTES)
                    .map_err(|err| format!("cannot safely hash {}: {}", path.display(), err))?;
                path.display().to_string().hash(&mut hasher);
                content.hash(&mut hasher);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!("cannot safely hash {}: {}", path.display(), err));
            }
        }
    }

    Ok(hasher.finish())
}

/// Cache entry for manifest hash skip.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ScanHashCache {
    pub(crate) timestamp: u64,
    pub(crate) hash: u64,
}

pub(crate) const FULL_SCAN_TTL_SECS: u64 = 24 * 3600;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct FullScanFingerprintCache {
    pub(crate) timestamp: u64,
    pub(crate) project_state_hash: u64,
    pub(crate) policy_hash: u64,
    pub(crate) binding_hash: u64,
}

pub(crate) fn full_scan_fingerprint_cache_path(cache_base: &std::path::Path) -> std::path::PathBuf {
    cache_base.join("full-scan-fingerprint.json")
}

pub(crate) fn full_scan_fingerprint_components_for_projects(
    projects: &[ParsedProject],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
    timestamp: u64,
) -> std::result::Result<FullScanFingerprintCache, String> {
    Ok(FullScanFingerprintCache {
        timestamp,
        project_state_hash: project_state_hash_for_projects(projects)?,
        policy_hash: policy_hash_u64(config, opts)?,
        binding_hash: project_binding_hash_for_projects(projects),
    })
}

pub(crate) fn read_full_scan_fingerprint_cache(
    cache_base: &std::path::Path,
) -> std::result::Result<Option<FullScanFingerprintCache>, String> {
    let path = full_scan_fingerprint_cache_path(cache_base);
    if !path.exists() {
        return Ok(None);
    }
    cache::ensure_no_symlink(&path)
        .map_err(|err| format!("cannot safely read {}: {}", path.display(), err))?;
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {}: {}", path.display(), err))?;
    let parsed = serde_json::from_str::<FullScanFingerprintCache>(&content)
        .map_err(|err| format!("cannot parse {}: {}", path.display(), err))?;
    Ok(Some(parsed))
}

pub(crate) fn persist_successful_full_scan_fingerprint(
    projects: &[ParsedProject],
    cache_base: &std::path::Path,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<(), String> {
    let fingerprint =
        full_scan_fingerprint_components_for_projects(projects, config, opts, cache::now_epoch())?;
    let path = full_scan_fingerprint_cache_path(cache_base);
    cache::atomic_write_json(&path, &fingerprint);
    Ok(())
}

pub(crate) fn full_scan_recommendation_reasons_for_projects(
    projects: &[ParsedProject],
    cache_base: &std::path::Path,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
    now_epoch: u64,
) -> std::result::Result<Vec<report::FullScanRecommendationReason>, String> {
    let current = full_scan_fingerprint_components_for_projects(projects, config, opts, now_epoch)?;
    let Some(previous) = read_full_scan_fingerprint_cache(cache_base)? else {
        return Ok(vec![
            report::FullScanRecommendationReason::NoSuccessfulFullScan,
        ]);
    };

    let mut reasons = Vec::new();
    if previous.timestamp > now_epoch
        || now_epoch.saturating_sub(previous.timestamp) >= FULL_SCAN_TTL_SECS
    {
        reasons.push(report::FullScanRecommendationReason::LastFullScanStale);
    }
    if previous.project_state_hash != current.project_state_hash {
        reasons.push(report::FullScanRecommendationReason::DependencyStateChanged);
    }
    if previous.policy_hash != current.policy_hash {
        reasons.push(report::FullScanRecommendationReason::PolicyChanged);
    }
    if previous.binding_hash != current.binding_hash {
        reasons.push(report::FullScanRecommendationReason::ManagerBindingChanged);
    }
    Ok(reasons)
}

#[cfg(test)]
pub(crate) fn full_scan_fingerprint_for_projects(
    projects: &[ParsedProject],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> std::result::Result<u64, String> {
    use std::hash::{Hash, Hasher};
    let fingerprint =
        full_scan_fingerprint_components_for_projects(projects, config, opts, cache::now_epoch())?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    fingerprint.project_state_hash.hash(&mut hasher);
    fingerprint.policy_hash.hash(&mut hasher);
    fingerprint.binding_hash.hash(&mut hasher);
    Ok(hasher.finish())
}

#[cfg(test)]
pub(crate) fn scan_hash_matches_cache(
    project_dir: &std::path::Path,
    deps: &[Dependency],
    cache_base: &std::path::Path,
) -> std::result::Result<bool, String> {
    let hash = scan_hash(project_dir, deps)?;
    let hash_path = cache_base.join("scan-hash.json");
    Ok(matches!(
        cache::read_json_cache::<ScanHashCache>(&hash_path, 7 * 24 * 3600, |c| c.timestamp),
        Some(cached) if cached.hash == hash
    ))
}
