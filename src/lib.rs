pub mod checks;
pub mod config;
pub mod parsers;
pub mod registry;
pub mod report;

use anyhow::Result;
use report::ScanReport;

/// Run all checks on the detected or specified project type.
///
/// `config_path` must point to a file outside the project directory.
/// If None, only existence and similarity checks run (no canonical check).
///
/// Three tiers of packages:
/// - **internal**: skip ALL checks (your org's packages, change constantly)
/// - **allowed**: skip existence + similarity, still subject to canonical + age gate
/// - **everything else**: full checks
pub async fn scan(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_path: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let config = config::load_config(config_path);
    let deps = parsers::parse_dependencies(project_dir, project_type)?;

    if deps.is_empty() {
        return Ok(ScanReport::empty());
    }

    let ecosystem = deps[0].ecosystem.clone();
    let registry = registry::registry_for(&ecosystem);

    // Split deps into three tiers
    let (internal, rest): (Vec<&Dependency>, Vec<&Dependency>) = deps
        .iter()
        .partition(|dep| config.is_internal(&ecosystem, &dep.name));

    let (allowed, checkable): (Vec<&Dependency>, Vec<&Dependency>) = rest
        .iter()
        .copied()
        .partition(|dep| config.is_allowed(&ecosystem, &dep.name));

    if !internal.is_empty() {
        let names: Vec<_> = internal.iter().map(|d| d.name.as_str()).collect();
        eprintln!("Skipping {} internal package(s): {}", names.len(), names.join(", "));
    }

    if !allowed.is_empty() {
        let names: Vec<_> = allowed.iter().map(|d| d.name.as_str()).collect();
        eprintln!("Skipping existence/similarity for {} allowed package(s): {}", names.len(), names.join(", "));
    }

    // Checkable deps get full checks
    let checkable_owned: Vec<Dependency> = checkable.into_iter().cloned().collect();
    let existence_results = checks::existence::check_existence(&*registry, &checkable_owned).await?;
    let similarity_results = checks::similarity::check_similarity(&checkable_owned, &ecosystem);

    // Canonical check runs on all non-internal deps (allowed + checkable)
    let non_internal: Vec<Dependency> = deps
        .iter()
        .filter(|dep| !config.is_internal(&ecosystem, &dep.name))
        .cloned()
        .collect();
    let canonical_results = checks::canonical::check_canonical(&non_internal, &config, &ecosystem);

    // Metadata/age check runs on all non-internal deps (allowed ARE subject to age gate)
    let metadata_results = checks::metadata::check_metadata(&*registry, &non_internal, &config).await?;

    Ok(ScanReport::new(
        deps.len(),
        existence_results,
        similarity_results,
        canonical_results,
        metadata_results,
    ))
}

/// A dependency parsed from a project file.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-lib-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn scan_empty_project_returns_empty_report() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name": "test", "version": "1.0"}"#,
        ).unwrap();
        let report = scan(&dir, Some("npm"), None).await.unwrap();
        assert_eq!(report.packages_checked, 0);
        assert!(!report.has_issues());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_with_deps_returns_report() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18.0"}}"#,
        ).unwrap();
        let report = scan(&dir, Some("npm"), None).await.unwrap();
        assert_eq!(report.packages_checked, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_with_internal_skips_all_checks() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18.0", "@myorg/utils": "1.0"}}"#,
        ).unwrap();
        let config_dir = unique_dir();
        let config_path = config_dir.join("config.json");
        std::fs::write(
            &config_path,
            r#"{"canonical":{},"internal":{"npm":["@myorg/*"]},"allowed":{}}"#,
        ).unwrap();
        let report = scan(&dir, Some("npm"), Some(config_path.as_path())).await.unwrap();
        assert_eq!(report.packages_checked, 2);
        // @myorg/utils should not appear in any issues
        let myorg_issues: Vec<_> = report.issues.iter().filter(|i| i.package.contains("myorg")).collect();
        assert!(myorg_issues.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&config_dir);
    }

    #[tokio::test]
    async fn scan_with_canonical_config_flags_alternatives() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"moment": "^2.0"}}"#,
        ).unwrap();
        let config_dir = unique_dir();
        let config_path = config_dir.join("config.json");
        std::fs::write(
            &config_path,
            r#"{"canonical":{"npm":{"dayjs":["moment"]}},"internal":{},"allowed":{}}"#,
        ).unwrap();
        let report = scan(&dir, Some("npm"), Some(config_path.as_path())).await.unwrap();
        let canonical_issues: Vec<_> = report.issues.iter().filter(|i| i.check == "canonical").collect();
        assert_eq!(canonical_issues.len(), 1);
        assert_eq!(canonical_issues[0].package, "moment");
        assert_eq!(canonical_issues[0].suggestion, Some("dayjs".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&config_dir);
    }
}
