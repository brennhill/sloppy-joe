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

    // Split deps: allowed packages skip existence + similarity checks
    let (allowed, checkable): (Vec<_>, Vec<_>) = deps
        .iter()
        .partition(|dep| config.is_allowed(&ecosystem, &dep.name));

    if !allowed.is_empty() {
        let names: Vec<_> = allowed.iter().map(|d| d.name.as_str()).collect();
        eprintln!("Skipping {} allowed package(s): {}", names.len(), names.join(", "));
    }

    // Convert &[&Dependency] back to &[Dependency] for the check functions
    let checkable_owned: Vec<Dependency> = checkable.into_iter().cloned().collect();

    let existence_results = checks::existence::check_existence(&*registry, &checkable_owned).await?;
    let similarity_results = checks::similarity::check_similarity(&checkable_owned, &ecosystem);
    // Canonical check runs on ALL deps — allowed packages still must be canonical
    let canonical_results = checks::canonical::check_canonical(&deps, &config, &ecosystem);

    Ok(ScanReport::new(
        deps.len(),
        existence_results,
        similarity_results,
        canonical_results,
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
        )
        .unwrap();
        let report = scan(&dir, Some("npm"), None).await.unwrap();
        assert_eq!(report.packages_checked, 0);
        assert!(!report.has_issues());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_with_deps_returns_report() {
        let dir = unique_dir();
        // Use a well-known package that exists on npm
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18.0"}}"#,
        )
        .unwrap();
        let report = scan(&dir, Some("npm"), None).await.unwrap();
        assert_eq!(report.packages_checked, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_with_config_and_allowed() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18.0", "@myorg/utils": "1.0"}}"#,
        )
        .unwrap();
        let config_dir = unique_dir();
        let config_path = config_dir.join("config.json");
        std::fs::write(
            &config_path,
            r#"{"canonical":{},"allowed":{"npm":["@myorg/*"]}}"#,
        )
        .unwrap();
        let report = scan(&dir, Some("npm"), Some(config_path.as_path()))
            .await
            .unwrap();
        // 2 packages total, but @myorg/utils is allowed so it skips existence check
        assert_eq!(report.packages_checked, 2);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&config_dir);
    }

    #[tokio::test]
    async fn scan_with_canonical_config_flags_alternatives() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"moment": "^2.0"}}"#,
        )
        .unwrap();
        let config_dir = unique_dir();
        let config_path = config_dir.join("config.json");
        std::fs::write(
            &config_path,
            r#"{"canonical":{"npm":{"dayjs":["moment"]}},"allowed":{}}"#,
        )
        .unwrap();
        let report = scan(&dir, Some("npm"), Some(config_path.as_path()))
            .await
            .unwrap();
        // moment should be flagged as non-canonical
        let canonical_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.check == "canonical")
            .collect();
        assert_eq!(canonical_issues.len(), 1);
        assert_eq!(canonical_issues[0].package, "moment");
        assert_eq!(canonical_issues[0].suggestion, Some("dayjs".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&config_dir);
    }
}
