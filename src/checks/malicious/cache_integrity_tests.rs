//! RT19 reproducer: an `osv-cache.json` edited (or planted) to claim a package has no
//! advisories must not clear it. The entry is discarded and OSV is asked again.

use super::*;
use async_trait::async_trait;

struct VulnerableOsv;

#[async_trait]
impl OsvClient for VulnerableOsv {
    async fn query(
        &self,
        _name: &str,
        _ecosystem: &str,
        _version: Option<&str>,
    ) -> Result<Vec<String>> {
        Ok(vec!["GHSA-real-advisory".to_string()])
    }
}

fn dep() -> Dependency {
    Dependency {
        name: "some-pkg".into(),
        version: None,
        ecosystem: crate::Ecosystem::Npm,
        actual_name: None,
    }
}

fn clean_cache() -> String {
    serde_json::json!({
        "timestamp": cache::now_epoch(),
        "entries": {"npm:some-pkg:": {"vuln_ids": []}}
    })
    .to_string()
}

async fn issues_with_cache(path: &Path) -> Vec<Issue> {
    check_malicious_with_cache(
        &VulnerableOsv,
        &[dep()],
        &ResolutionResult::default(),
        &[],
        Some(path),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn planted_clean_osv_cache_does_not_hide_advisories() {
    let dir = crate::parsers::test_utils::empty_test_dir("osv-planted-cache");
    let path = dir.join("osv-cache.json");
    std::fs::write(&path, clean_cache()).unwrap();
    let issues = issues_with_cache(&path).await;
    assert!(
        issues.iter().any(|i| i.message.contains("GHSA-real-advisory")),
        "a cache file sloppy-joe did not write must be refetched: {issues:?}"
    );
    crate::parsers::test_utils::cleanup(&dir);
}

#[tokio::test]
async fn edited_osv_cache_does_not_hide_advisories() {
    let dir = crate::parsers::test_utils::empty_test_dir("osv-edited-cache");
    let path = dir.join("osv-cache.json");
    cache::atomic_write_json(
        &path,
        &DiskCache {
            timestamp: cache::now_epoch(),
            entries: HashMap::from([(
                "npm:some-pkg:".to_string(),
                CacheEntry {
                    vuln_ids: vec!["GHSA-real-advisory".to_string()],
                },
            )]),
        },
    );
    std::fs::write(&path, clean_cache()).unwrap();
    let issues = issues_with_cache(&path).await;
    assert!(
        issues.iter().any(|i| i.message.contains("GHSA-real-advisory")),
        "an edited cache must be refetched: {issues:?}"
    );
    crate::parsers::test_utils::cleanup(&dir);
}
