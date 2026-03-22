use crate::Dependency;
use crate::report::{Issue, Severity};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionSource {
    Lockfile,
    ManifestExact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVersion {
    pub version: String,
    pub source: ResolutionSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolutionKey {
    package: String,
    requested_version: Option<String>,
}

impl From<&Dependency> for ResolutionKey {
    fn from(dep: &Dependency) -> Self {
        Self {
            package: dep.name.clone(),
            requested_version: dep.version.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResolutionResult {
    pub exact_versions: HashMap<ResolutionKey, ResolvedVersion>,
    pub issues: Vec<Issue>,
}

impl ResolutionResult {
    pub fn resolved_version(&self, dep: &Dependency) -> Option<&ResolvedVersion> {
        self.exact_versions.get(&ResolutionKey::from(dep))
    }

    pub fn exact_version(&self, dep: &Dependency) -> Option<&str> {
        self.resolved_version(dep)
            .map(|resolved| resolved.version.as_str())
    }

    pub fn is_unresolved(&self, dep: &Dependency) -> bool {
        dep.has_unresolved_version() && self.exact_version(dep).is_none()
    }
}

pub fn resolve_versions(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(first) = deps.first() else {
        return Ok(ResolutionResult::default());
    };

    match first.ecosystem.as_str() {
        "npm" => resolve_npm(project_dir, deps),
        "cargo" => resolve_cargo(project_dir, deps),
        _ => {
            let mut result = ResolutionResult::default();
            add_manifest_exact_fallbacks(&mut result, deps);
            Ok(result)
        }
    }
}

/// Parse ALL packages from the lockfile and return only the transitive ones
/// (those not in `direct_deps`). Each returned Dependency has an exact version
/// from the lockfile.
pub fn parse_all_lockfile_deps(
    project_dir: &Path,
    direct_deps: &[Dependency],
) -> Result<Vec<Dependency>> {
    let Some(first) = direct_deps.first() else {
        return Ok(vec![]);
    };
    match first.ecosystem.as_str() {
        "npm" => parse_all_npm(project_dir, direct_deps),
        "cargo" => parse_all_cargo(project_dir, direct_deps),
        _ => Ok(vec![]),
    }
}

fn parse_all_npm(project_dir: &Path, direct_deps: &[Dependency]) -> Result<Vec<Dependency>> {
    let Some(path) = first_existing(project_dir, &["package-lock.json", "npm-shrinkwrap.json"])
    else {
        return Ok(vec![]);
    };
    let content = std::fs::read_to_string(&path)?;
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Ok(vec![]),
    };

    let direct_names: HashSet<&str> = direct_deps.iter().map(|d| d.name.as_str()).collect();
    let mut transitive = Vec::new();

    // Try v2/v3 format first (packages section)
    if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            // Skip the root entry
            if key.is_empty() {
                continue;
            }
            // Extract package name: strip "node_modules/" prefix, handle scoped packages
            // Keys can be nested like "node_modules/foo/node_modules/bar"
            let name = key
                .rsplit_once("node_modules/")
                .map(|(_, n)| n)
                .unwrap_or(key);
            if name.is_empty() {
                continue;
            }
            let version = entry
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !direct_names.contains(name) && !version.is_empty() {
                transitive.push(Dependency {
                    name: name.to_string(),
                    version: Some(version),
                    ecosystem: "npm".to_string(),
                });
            }
        }
    } else if let Some(dependencies) = parsed.get("dependencies").and_then(|v| v.as_object()) {
        // v1 format: recursive dependencies
        collect_npm_v1_deps(dependencies, &direct_names, &mut transitive);
    }

    // Deduplicate by name (keep first occurrence)
    let mut seen = HashSet::new();
    transitive.retain(|dep| seen.insert(dep.name.clone()));

    Ok(transitive)
}

fn collect_npm_v1_deps(
    deps_obj: &serde_json::Map<String, serde_json::Value>,
    direct_names: &HashSet<&str>,
    out: &mut Vec<Dependency>,
) {
    for (name, entry) in deps_obj {
        let version = entry
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !direct_names.contains(name.as_str()) && !version.is_empty() {
            out.push(Dependency {
                name: name.clone(),
                version: Some(version),
                ecosystem: "npm".to_string(),
            });
        }
        // Recurse into nested dependencies
        if let Some(nested) = entry.get("dependencies").and_then(|v| v.as_object()) {
            collect_npm_v1_deps(nested, direct_names, out);
        }
    }
}

fn parse_all_cargo(project_dir: &Path, direct_deps: &[Dependency]) -> Result<Vec<Dependency>> {
    let path = project_dir.join("Cargo.lock");
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(&path)?;
    let parsed: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Ok(vec![]),
    };

    let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };

    let direct_names: HashSet<&str> = direct_deps.iter().map(|d| d.name.as_str()).collect();
    let mut transitive = Vec::new();

    for package in packages {
        let Some(table) = package.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        if !direct_names.contains(name) {
            transitive.push(Dependency {
                name: name.to_string(),
                version: Some(version.to_string()),
                ecosystem: "cargo".to_string(),
            });
        }
    }

    Ok(transitive)
}

fn resolve_npm(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(path) = first_existing(project_dir, &["package-lock.json", "npm-shrinkwrap.json"])
    else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("package-lock.json")
        .to_string();
    let content = std::fs::read_to_string(&path)?;
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(parsed) => parsed,
        Err(err) => {
            let mut result = ResolutionResult::default();
            result
                .issues
                .push(parse_failed_issue(&file_name, err.to_string()));
            add_manifest_exact_fallbacks(&mut result, deps);
            return Ok(result);
        }
    };

    let packages = parsed.get("packages").and_then(|value| value.as_object());
    let dependencies = parsed
        .get("dependencies")
        .and_then(|value| value.as_object());
    if packages.is_none() && dependencies.is_none() {
        let mut result = ResolutionResult::default();
        result.issues.push(parse_failed_issue(
            &file_name,
            "lockfile did not contain a supported packages or dependencies section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    }

    let mut result = ResolutionResult::default();
    for dep in deps {
        let resolved = packages
            .and_then(|packages| {
                packages
                    .get(&format!("node_modules/{}", dep.name))
                    .and_then(|entry| entry.get("version"))
                    .and_then(|value| value.as_str())
            })
            .or_else(|| {
                dependencies.and_then(|dependencies| {
                    dependencies
                        .get(&dep.name)
                        .and_then(|entry| entry.get("version"))
                        .and_then(|value| value.as_str())
                })
            });

        match resolved {
            Some(version) => {
                if let Some(exact_manifest) = dep.exact_version()
                    && exact_manifest != version
                {
                    result.issues.push(out_of_sync_issue(dep, version));
                    add_manifest_exact_fallback(&mut result, dep);
                    continue;
                }
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: version.to_string(),
                        source: ResolutionSource::Lockfile,
                    },
                );
            }
            None => {
                result.issues.push(missing_entry_issue(dep, &file_name));
                add_manifest_exact_fallback(&mut result, dep);
            }
        }
    }

    Ok(result)
}

fn resolve_cargo(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let path = project_dir.join("Cargo.lock");
    if !path.exists() {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    }

    let content = std::fs::read_to_string(&path)?;
    let parsed: toml::Value = match toml::from_str(&content) {
        Ok(parsed) => parsed,
        Err(err) => {
            let mut result = ResolutionResult::default();
            result
                .issues
                .push(parse_failed_issue("Cargo.lock", err.to_string()));
            add_manifest_exact_fallbacks(&mut result, deps);
            return Ok(result);
        }
    };

    let Some(packages) = parsed.get("package").and_then(|value| value.as_array()) else {
        let mut result = ResolutionResult::default();
        result.issues.push(parse_failed_issue(
            "Cargo.lock",
            "lockfile did not contain a package array".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let mut versions_by_name: HashMap<String, Vec<String>> = HashMap::new();
    for package in packages {
        let Some(table) = package.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|value| value.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|value| value.as_str()) else {
            continue;
        };
        versions_by_name
            .entry(name.to_string())
            .or_default()
            .push(version.to_string());
    }

    let mut result = ResolutionResult::default();
    for dep in deps {
        let Some(versions) = versions_by_name.get(&dep.name) else {
            result.issues.push(missing_entry_issue(dep, "Cargo.lock"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };

        if versions.len() == 1 {
            let version = &versions[0];
            if let Some(exact_manifest) = dep.exact_version()
                && exact_manifest != *version
            {
                result.issues.push(out_of_sync_issue(dep, version));
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
            result.exact_versions.insert(
                ResolutionKey::from(dep),
                ResolvedVersion {
                    version: version.clone(),
                    source: ResolutionSource::Lockfile,
                },
            );
            continue;
        }

        if let Some(exact_manifest) = dep.exact_version() {
            if versions.iter().any(|version| version == &exact_manifest) {
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: exact_manifest,
                        source: ResolutionSource::Lockfile,
                    },
                );
            } else {
                result
                    .issues
                    .push(out_of_sync_issue(dep, &versions.join(", ")));
                add_manifest_exact_fallback(&mut result, dep);
            }
        } else {
            result.issues.push(ambiguous_issue(dep));
        }
    }

    Ok(result)
}

fn first_existing(project_dir: &Path, names: &[&str]) -> Option<PathBuf> {
    names
        .iter()
        .map(|name| project_dir.join(name))
        .find(|path| path.exists())
}

fn add_manifest_exact_fallbacks(result: &mut ResolutionResult, deps: &[Dependency]) {
    for dep in deps {
        add_manifest_exact_fallback(result, dep);
    }
}

fn add_manifest_exact_fallback(result: &mut ResolutionResult, dep: &Dependency) {
    if let Some(exact_version) = dep.exact_version() {
        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version: exact_version,
                source: ResolutionSource::ManifestExact,
            },
        );
    }
}

fn parse_failed_issue(lockfile: &str, detail: String) -> Issue {
    Issue {
        package: "<lockfile>".to_string(),
        check: "resolution/parse-failed".to_string(),
        severity: Severity::Error,
        message: format!(
            "Could not parse '{}'. Exact lockfile resolution is unavailable, so version-sensitive checks cannot trust this project state. {}",
            lockfile, detail
        ),
        fix: format!(
            "Repair or regenerate '{}', then rerun sloppy-joe.",
            lockfile
        ),
        suggestion: None,
        registry_url: None,
        source: None,
    }
}

fn missing_entry_issue(dep: &Dependency, lockfile: &str) -> Issue {
    Issue {
        package: dep.name.clone(),
        check: "resolution/missing-lockfile-entry".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' is declared in the manifest but was not found in '{}'. Exact version-sensitive checks cannot trust this lockfile state.",
            dep.name, lockfile
        ),
        fix: format!(
            "Regenerate '{}' so it contains the direct dependency '{}', then rerun sloppy-joe.",
            lockfile, dep.name
        ),
        suggestion: None,
        registry_url: None,
        source: None,
    }
}

fn out_of_sync_issue(dep: &Dependency, resolved_version: &str) -> Issue {
    Issue {
        package: dep.name.clone(),
        check: "resolution/lockfile-out-of-sync".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' is pinned to '{}' in the manifest but resolves to '{}' in the lockfile. Exact version-sensitive checks cannot trust this project state.",
            dep.name,
            dep.version.as_deref().unwrap_or(""),
            resolved_version
        ),
        fix: "Update the manifest or regenerate the lockfile so both describe the same direct dependency version.".to_string(),
        suggestion: None,
        registry_url: None,
        source: None,
    }
}

fn ambiguous_issue(dep: &Dependency) -> Issue {
    Issue {
        package: dep.name.clone(),
        check: "resolution/ambiguous".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' resolves to multiple locked versions and the direct dependency version cannot be proven exactly from the manifest.",
            dep.name
        ),
        fix: "Pin an exact manifest version or regenerate the lockfile so the direct dependency version is unambiguous.".to_string(),
        suggestion: None,
        registry_url: None,
        source: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Dependency;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-lockfiles-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn npm_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: "npm".to_string(),
        }
    }

    fn cargo_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: "cargo".to_string(),
        }
    }

    #[test]
    fn uses_manifest_exact_when_no_supported_lockfile_exists() {
        let dir = unique_dir();
        let deps = vec![npm_dep("react", "18.3.1")];

        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();

        assert_eq!(resolved.version, "18.3.1");
        assert_eq!(resolved.source, ResolutionSource::ManifestExact);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn npm_package_lock_v3_resolves_direct_dependency() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"react": "^18.2.0"}},
                "node_modules/react": {"version": "18.3.1"}
              }
            }"#,
        )
        .unwrap();

        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();

        assert_eq!(resolved.version, "18.3.1");
        assert_eq!(resolved.source, ResolutionSource::Lockfile);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn npm_package_lock_v1_resolves_direct_dependency() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 1,
              "dependencies": {
                "react": {"version": "18.3.1"}
              }
            }"#,
        )
        .unwrap();

        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();

        assert_eq!(resolved.version, "18.3.1");
    }

    #[test]
    fn npm_exact_pin_out_of_sync_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"react": "18.2.0"}},
                "node_modules/react": {"version": "18.3.1"}
              }
            }"#,
        )
        .unwrap();

        let deps = vec![npm_dep("react", "18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();

        assert_eq!(resolved.version, "18.2.0");
        assert_eq!(resolved.source, ResolutionSource::ManifestExact);
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.check == "resolution/lockfile-out-of-sync")
        );
    }

    #[test]
    fn npm_missing_direct_dependency_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo"}
              }
            }"#,
        )
        .unwrap();

        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();

        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.check == "resolution/missing-lockfile-entry")
        );
    }

    #[test]
    fn npm_malformed_lockfile_emits_parse_failed_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();

        let deps = vec![npm_dep("react", "18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();

        assert_eq!(resolved.version, "18.2.0");
        assert_eq!(resolved.source, ResolutionSource::ManifestExact);
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.check == "resolution/parse-failed")
        );
    }

    #[test]
    fn cargo_lock_resolves_single_locked_version() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.lock"),
            r#"
[[package]]
name = "serde"
version = "1.0.203"
"#,
        )
        .unwrap();

        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();

        assert_eq!(resolved.version, "1.0.203");
        assert_eq!(resolved.source, ResolutionSource::Lockfile);
    }

    #[test]
    fn cargo_lock_uses_exact_manifest_match_when_multiple_versions_exist() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.lock"),
            r#"
[[package]]
name = "serde"
version = "1.0.201"

[[package]]
name = "serde"
version = "1.0.203"
"#,
        )
        .unwrap();

        let deps = vec![cargo_dep("serde", "=1.0.203")];
        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();

        assert_eq!(resolved.version, "1.0.203");
    }

    #[test]
    fn cargo_lock_ambiguous_versions_emit_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.lock"),
            r#"
[[package]]
name = "serde"
version = "1.0.201"

[[package]]
name = "serde"
version = "1.0.203"
"#,
        )
        .unwrap();

        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();

        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.check == "resolution/ambiguous")
        );
    }

    #[test]
    fn cargo_lock_missing_direct_dependency_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.lock"),
            r#"
[[package]]
name = "tokio"
version = "1.42.0"
"#,
        )
        .unwrap();

        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();

        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.check == "resolution/missing-lockfile-entry")
        );
    }

    #[test]
    fn cargo_lock_malformed_lockfile_emits_parse_failed_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]").unwrap();

        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();

        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.check == "resolution/parse-failed")
        );
    }

    #[test]
    fn parse_all_npm_v3_returns_transitive_deps() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"react": "^18.2.0"}},
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/js-tokens": {"version": "4.0.0"},
                "node_modules/loose-envify": {"version": "1.4.0"}
              }
            }"#,
        )
        .unwrap();

        let direct = vec![npm_dep("react", "^18.2.0")];
        let transitive = parse_all_lockfile_deps(&dir, &direct).unwrap();

        let names: Vec<&str> = transitive.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"js-tokens"));
        assert!(names.contains(&"loose-envify"));
        assert!(!names.contains(&"react"));
        assert_eq!(transitive.len(), 2);

        for dep in &transitive {
            assert!(dep.version.is_some());
        }
    }

    #[test]
    fn parse_all_npm_v1_returns_transitive_deps() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 1,
              "dependencies": {
                "react": {
                  "version": "18.3.1",
                  "dependencies": {
                    "loose-envify": {"version": "1.4.0"}
                  }
                },
                "js-tokens": {"version": "4.0.0"}
              }
            }"#,
        )
        .unwrap();

        let direct = vec![npm_dep("react", "^18.2.0")];
        let transitive = parse_all_lockfile_deps(&dir, &direct).unwrap();

        let names: Vec<&str> = transitive.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"js-tokens"));
        assert!(names.contains(&"loose-envify"));
        assert!(!names.contains(&"react"));
    }

    #[test]
    fn parse_all_cargo_lock_returns_transitive_deps() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.lock"),
            r#"
[[package]]
name = "serde"
version = "1.0.203"

[[package]]
name = "serde_derive"
version = "1.0.203"

[[package]]
name = "proc-macro2"
version = "1.0.86"
"#,
        )
        .unwrap();

        let direct = vec![cargo_dep("serde", "1")];
        let transitive = parse_all_lockfile_deps(&dir, &direct).unwrap();

        let names: Vec<&str> = transitive.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"serde_derive"));
        assert!(names.contains(&"proc-macro2"));
        assert!(!names.contains(&"serde"));
        assert_eq!(transitive.len(), 2);
    }

    #[test]
    fn parse_all_returns_empty_when_no_lockfile() {
        let dir = unique_dir();
        let direct = vec![npm_dep("react", "^18.2.0")];
        let transitive = parse_all_lockfile_deps(&dir, &direct).unwrap();
        assert!(transitive.is_empty());
    }

    #[test]
    fn parse_all_deduplicates_npm_packages() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"express": "4.0.0"}},
                "node_modules/express": {"version": "4.0.0"},
                "node_modules/debug": {"version": "2.6.9"},
                "node_modules/express/node_modules/debug": {"version": "2.6.9"}
              }
            }"#,
        )
        .unwrap();

        let direct = vec![npm_dep("express", "4.0.0")];
        let transitive = parse_all_lockfile_deps(&dir, &direct).unwrap();

        let debug_count = transitive.iter().filter(|d| d.name == "debug").count();
        assert_eq!(debug_count, 1);
    }
}
