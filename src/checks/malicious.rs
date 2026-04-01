use crate::Dependency;
use crate::cache;
use crate::lockfiles::ResolutionResult;
use crate::report::{Issue, Severity};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::path::Path;
const CACHE_TTL_SECS: u64 = 3600; // 1 hour — short TTL since OSV re-queries are cheap

/// Cached OSV query result: list of vulnerability IDs (empty = clean).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    vuln_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DiskCache {
    timestamp: u64,
    entries: HashMap<String, CacheEntry>,
}

fn default_cache_file() -> std::path::PathBuf {
    cache::user_cache_dir()
        .join("sloppy-joe")
        .join("osv-cache.json")
}

use crate::Ecosystem;

/// Map ecosystem to OSV ecosystem names.
fn osv_ecosystem(ecosystem: Ecosystem) -> &'static str {
    ecosystem.osv_name()
}

/// An OSV client that can be swapped out for testing.
#[async_trait::async_trait]
pub trait OsvClient: Send + Sync {
    async fn query(
        &self,
        name: &str,
        ecosystem: &str,
        version: Option<&str>,
    ) -> Result<Vec<String>>;
}

/// Real OSV client that hits the API.
pub struct RealOsvClient {
    client: reqwest::Client,
}

impl RealOsvClient {
    pub fn new() -> Self {
        Self {
            client: crate::registry::http_client(),
        }
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for RealOsvClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl OsvClient for RealOsvClient {
    async fn query(
        &self,
        name: &str,
        ecosystem: &str,
        version: Option<&str>,
    ) -> Result<Vec<String>> {
        let eco: Ecosystem = ecosystem.parse().unwrap_or(Ecosystem::Npm);
        let osv_eco = osv_ecosystem(eco);
        let mut body = serde_json::json!({
            "package": {
                "name": name,
                "ecosystem": osv_eco
            }
        });
        // Include version to filter to only vulnerabilities affecting this version
        if let Some(ver) = version {
            body["version"] = serde_json::Value::String(ver.to_string());
        }
        let resp = self
            .client
            .post("https://api.osv.dev/v1/query")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("OSV query for '{}' returned HTTP {}", name, resp.status());
        }

        let json: serde_json::Value = resp.json().await?;
        let vuln_ids = json["vulns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v["id"].as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(vuln_ids)
    }
}

/// Check all dependencies against the OSV vulnerability database.
/// Uses a 1-hour disk cache at the default path.
pub async fn check_malicious(
    osv_client: &dyn OsvClient,
    deps: &[Dependency],
    resolution: &ResolutionResult,
) -> Result<Vec<Issue>> {
    let cache_path = default_cache_file();
    check_malicious_with_cache(osv_client, deps, resolution, Some(cache_path.as_path())).await
}

/// Check all dependencies against the OSV vulnerability database.
/// `cache_path` controls disk caching: None disables disk cache entirely.
pub async fn check_malicious_with_cache(
    osv_client: &dyn OsvClient,
    deps: &[Dependency],
    resolution: &ResolutionResult,
    cache_path: Option<&Path>,
) -> Result<Vec<Issue>> {
    // Load disk cache if fresh (using shared cache utilities: symlink protection, atomic writes)
    let initial_entries = cache_path
        .and_then(|p| cache::read_json_cache::<DiskCache>(p, CACHE_TTL_SECS, |c| c.timestamp))
        .map(|c| c.entries)
        .unwrap_or_default();
    let mut cache = initial_entries;

    let mut issues = Vec::new();
    let mut pending = HashMap::new();

    for dep in deps {
        // Query OSV even for unresolved deps — OSV supports name-only queries
        // and will return all known vulnerabilities for the package.
        let exact_version = resolution.exact_version(dep).map(str::to_string);
        let version_suffix = exact_version.clone().unwrap_or_default();
        let cache_key = format!(
            "{}:{}:{}",
            dep.ecosystem,
            dep.package_name(),
            version_suffix
        );
        if !cache.contains_key(&cache_key) {
            pending
                .entry(cache_key)
                .or_insert_with(|| (dep.package_name().to_string(), dep.ecosystem, exact_version));
        }
    }

    let results: Vec<_> = stream::iter(pending.into_iter())
        .map(|(cache_key, (name, ecosystem, version))| async move {
            let result = osv_client
                .query(&name, ecosystem.as_str(), version.as_deref())
                .await;
            (cache_key, result)
        })
        .buffer_unordered(10)
        .collect()
        .await;

    let total_queries = results.len();
    let mut error_count = 0usize;

    for (cache_key, result) in results {
        match result {
            Ok(ids) => {
                cache.insert(cache_key, CacheEntry { vuln_ids: ids });
            }
            Err(_) => {
                error_count += 1;
            }
        }
    }

    if crate::checks::has_query_errors(error_count) {
        let error_rate = error_count as f64 / total_queries.max(1) as f64;
        issues.push(
            Issue::new(
                "<registry>",
                crate::checks::names::MALICIOUS_REGISTRY_UNREACHABLE,
                Severity::Error,
            )
            .message(format!(
                "OSV queries failed for {} of {} vulnerability checks ({:.0}%). \
                     Vulnerability detection is unreliable. Fix network connectivity or retry.",
                error_count,
                total_queries,
                error_rate * 100.0
            ))
            .fix("Ensure the OSV API is reachable and retry the scan."),
        );
    }

    for dep in deps {
        // Check cache for results (including unresolved deps which now get queried)
        let version_suffix = resolution.exact_version(dep).unwrap_or_default();
        let cache_key = format!(
            "{}:{}:{}",
            dep.ecosystem,
            dep.package_name(),
            version_suffix
        );
        let vuln_ids = cache
            .get(&cache_key)
            .map(|entry| entry.vuln_ids.clone())
            .unwrap_or_default();

        if !vuln_ids.is_empty() {
            issues.push(
                Issue::new(dep.package_name(), crate::checks::names::MALICIOUS_KNOWN_VULNERABILITY, Severity::Error)
                    .message(format!(
                        "'{}' has known security vulnerabilities in the OSV database. Vulnerability IDs: {}",
                        dep.package_name(),
                        vuln_ids.join(", ")
                    ))
                    .fix(format!(
                        "Remove '{}' or update to a non-vulnerable version.",
                        dep.package_name()
                    )),
            );
        }
    }

    // Save cache to disk (atomic writes, symlink protection, 0o600 permissions)
    if let Some(path) = cache_path {
        let disk_cache = DiskCache {
            timestamp: cache::now_epoch(),
            entries: cache.clone(),
        };
        cache::atomic_write_json(path, &disk_cache);
    }

    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOsvClient {
        responses: HashMap<String, Vec<String>>,
    }

    #[async_trait::async_trait]
    impl OsvClient for MockOsvClient {
        async fn query(
            &self,
            name: &str,
            _ecosystem: &str,
            _version: Option<&str>,
        ) -> Result<Vec<String>> {
            Ok(self.responses.get(name).cloned().unwrap_or_default())
        }
    }

    use crate::test_helpers::npm_dep as dep;

    fn dep_with_version(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        }
    }

    #[tokio::test]
    async fn known_vulnerable_package_flagged() {
        let mut responses = HashMap::new();
        responses.insert(
            "event-stream".to_string(),
            vec!["GHSA-xxx-yyy".to_string(), "MAL-2024-1234".to_string()],
        );
        let client = MockOsvClient { responses };

        let deps = vec![dep_with_version("event-stream", "3.3.6")];
        let issues = check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), None)
            .await
            .unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].package, "event-stream");
        assert_eq!(issues[0].check, "malicious/known-vulnerability");
        assert!(issues[0].message.contains("GHSA-xxx-yyy"));
        assert!(issues[0].message.contains("MAL-2024-1234"));
    }

    #[tokio::test]
    async fn clean_package_not_flagged() {
        let client = MockOsvClient {
            responses: HashMap::new(),
        };

        let deps = vec![dep_with_version("react", "18.2.0")];
        let issues = check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), None)
            .await
            .unwrap();

        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn unresolved_version_still_queries_osv() {
        let mut responses = HashMap::new();
        responses.insert(
            "vulnerable-pkg".to_string(),
            vec!["CVE-2024-9999".to_string()],
        );
        let client = MockOsvClient { responses };

        // Dep with no version (unresolved) — should still query OSV
        let deps = vec![Dependency {
            name: "vulnerable-pkg".to_string(),
            version: None,
            ecosystem: crate::Ecosystem::Npm,
            actual_name: None,
        }];
        let issues = check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), None)
            .await
            .unwrap();

        assert!(
            issues
                .iter()
                .any(|i| i.package == "vulnerable-pkg" && i.check.contains("known-vulnerability")),
            "Unresolved deps should still get OSV checks. Issues: {:?}",
            issues.iter().map(|i| &i.check).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn single_osv_error_triggers_fail_closed() {
        struct ErrorClient;

        #[async_trait::async_trait]
        impl OsvClient for ErrorClient {
            async fn query(
                &self,
                _name: &str,
                _ecosystem: &str,
                _version: Option<&str>,
            ) -> Result<Vec<String>> {
                anyhow::bail!("osv unavailable");
            }
        }

        let deps = vec![dep_with_version("react", "18.2.0")];
        let issues =
            check_malicious_with_cache(&ErrorClient, &deps, &ResolutionResult::default(), None)
                .await
                .unwrap();

        assert!(
            issues
                .iter()
                .any(|i| i.check.contains("registry-unreachable")),
            "Any OSV lookup failure should trigger fail-closed"
        );
    }

    #[tokio::test]
    async fn cache_used_when_fresh() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingClient {
            call_count: Arc<AtomicU32>,
            responses: HashMap<String, Vec<String>>,
        }

        #[async_trait::async_trait]
        impl OsvClient for CountingClient {
            async fn query(
                &self,
                name: &str,
                _ecosystem: &str,
                _version: Option<&str>,
            ) -> Result<Vec<String>> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Ok(self.responses.get(name).cloned().unwrap_or_default())
            }
        }

        let call_count = Arc::new(AtomicU32::new(0));
        let mut responses = HashMap::new();
        responses.insert("some-pkg".to_string(), vec!["VULN-1".to_string()]);

        let client = CountingClient {
            call_count: call_count.clone(),
            responses,
        };

        // Two identical deps — second should use in-memory cache
        let deps = vec![
            dep_with_version("some-pkg", "1.2.3"),
            dep_with_version("some-pkg", "1.2.3"),
        ];
        let issues = check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), None)
            .await
            .unwrap();

        // Should have 2 issues (one per dep occurrence) but only 1 API call
        assert_eq!(issues.len(), 2);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_exact_versions_skip_osv_queries() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingClient(Arc<AtomicU32>);

        #[async_trait::async_trait]
        impl OsvClient for CountingClient {
            async fn query(
                &self,
                _name: &str,
                _ecosystem: &str,
                _version: Option<&str>,
            ) -> Result<Vec<String>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(vec![])
            }
        }

        let call_count = Arc::new(AtomicU32::new(0));
        let client = CountingClient(call_count.clone());
        let deps = vec![dep_with_version("react", "^18.0.0")];
        let issues = check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), None)
            .await
            .unwrap();

        assert!(issues.is_empty());
        // Non-exact versions now DO query OSV (with version: None) — fail-closed, not fail-open
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "Unresolved deps should still query OSV"
        );
    }

    #[tokio::test]
    async fn versionless_dependencies_skip_osv_queries() {
        let client = MockOsvClient {
            responses: HashMap::new(),
        };

        let deps = vec![dep("react")];
        let issues = check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), None)
            .await
            .unwrap();

        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn distinct_queries_run_in_parallel() {
        use std::time::{Duration, Instant};

        struct SlowClient;

        #[async_trait::async_trait]
        impl OsvClient for SlowClient {
            async fn query(
                &self,
                _name: &str,
                _ecosystem: &str,
                _version: Option<&str>,
            ) -> Result<Vec<String>> {
                tokio::time::sleep(Duration::from_millis(75)).await;
                Ok(vec![])
            }
        }

        let deps = vec![
            dep_with_version("a", "1.0.0"),
            dep_with_version("b", "1.0.0"),
            dep_with_version("c", "1.0.0"),
            dep_with_version("d", "1.0.0"),
        ];
        let start = Instant::now();
        let issues =
            check_malicious_with_cache(&SlowClient, &deps, &ResolutionResult::default(), None)
                .await
                .unwrap();
        let elapsed = start.elapsed();

        assert!(issues.is_empty());
        assert!(
            elapsed < Duration::from_millis(220),
            "expected bounded parallelism, took {:?}",
            elapsed
        );
    }

    #[test]
    fn default_cache_path_uses_user_cache_directory() {
        let path = default_cache_file();
        assert!(path.ends_with("sloppy-joe/osv-cache.json"));
        assert!(path.starts_with(cache::user_cache_dir()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unwritable_cache_path_is_ignored() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("sj-cache-ro-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&dir, perms).unwrap();

        let client = MockOsvClient {
            responses: HashMap::new(),
        };
        let cache_path = dir.join("osv-cache.json");
        let issues = check_malicious_with_cache(
            &client,
            &[dep_with_version("react", "18.2.0")],
            &ResolutionResult::default(),
            Some(&cache_path),
        )
        .await
        .unwrap();
        assert!(issues.is_empty());

        let mut cleanup_perms = std::fs::metadata(&dir).unwrap().permissions();
        cleanup_perms.set_mode(0o700);
        let _ = std::fs::set_permissions(&dir, cleanup_perms);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
