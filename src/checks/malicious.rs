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
#[allow(clippy::double_must_use)] // async_trait generates this attribute on already-must-use futures.
#[async_trait::async_trait]
pub trait OsvClient: Send + Sync {
    async fn query(
        &self,
        name: &str,
        ecosystem: &str,
        version: Option<&str>,
    ) -> Result<Vec<String>>;
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OsvPage {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
    next_page_token: Option<String>,
}

#[derive(serde::Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(serde::Deserialize)]
struct OsvAffected {
    #[serde(default)]
    database_specific: serde_json::Value,
}

/// Real OSV client that hits the API.
pub struct RealOsvClient {
    client: reqwest::Client,
    endpoint: String,
}

impl RealOsvClient {
    pub fn new() -> Self {
        Self {
            client: crate::registry::http_client(),
            endpoint: "https://api.osv.dev/v1/query".to_owned(),
        }
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            endpoint: "https://api.osv.dev/v1/query".to_owned(),
        }
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
        let mut vuln_ids = Vec::new();
        let mut seen_tokens = std::collections::HashSet::new();
        // shortcut: cap at 100 pages; raise after measuring legitimate larger OSV responses.
        for _ in 0..100 {
            let resp = self.client.post(&self.endpoint).json(&body).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("OSV query for '{}' returned HTTP {}", name, resp.status());
            }
            let page: OsvPage = resp.json().await?;
            for vulnerability in page.vulns {
                if vulnerability.id.is_empty() {
                    anyhow::bail!("OSV returned a vulnerability without an ID");
                }
                let maintenance_only = !vulnerability.affected.is_empty()
                    && vulnerability.affected.iter().all(|affected| {
                        affected.database_specific["informational"].as_str() == Some("unmaintained")
                    });
                if !maintenance_only {
                    vuln_ids.push(vulnerability.id);
                }
            }
            let Some(token) = page.next_page_token.filter(|token| !token.is_empty()) else {
                vuln_ids.sort();
                vuln_ids.dedup();
                return Ok(vuln_ids);
            };
            if !seen_tokens.insert(token.clone()) {
                anyhow::bail!("OSV repeated a pagination token; advisory retrieval is incomplete");
            }
            body["page_token"] = token.into();
        }
        anyhow::bail!("OSV pagination limit exceeded; advisory retrieval is incomplete")
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
    let initial_cache = cache_path
        .and_then(|p| cache::read_json_cache::<DiskCache>(p, CACHE_TTL_SECS, |c| c.timestamp));
    let timestamp = initial_cache
        .as_ref()
        .map_or_else(cache::now_epoch, |c| c.timestamp);
    let mut cache = initial_cache.map(|c| c.entries).unwrap_or_default();

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

    let results: Vec<_> = stream::iter(pending)
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
                crate::names::MALICIOUS_REGISTRY_UNREACHABLE,
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
                Issue::new(dep.package_name(), crate::names::MALICIOUS_KNOWN_VULNERABILITY, Severity::Error)
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
            timestamp,
            entries: cache.clone(),
        };
        cache::atomic_write_json(path, &disk_cache);
    }

    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mock_osv_server(
        responses: Vec<serde_json::Value>,
    ) -> (
        RealOsvClient,
        tokio::task::JoinHandle<Vec<serde_json::Value>>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/query", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            requests.push(
                                serde_json::from_slice(&request[end + 4..end + 4 + length])
                                    .unwrap(),
                            );
                            break;
                        }
                    }
                }
                let body = response.to_string();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
            requests
        });
        (
            RealOsvClient {
                client: reqwest::Client::builder().no_proxy().build().unwrap(),
                endpoint,
            },
            server,
        )
    }

    #[tokio::test]
    async fn osv_query_follows_token_only_pages() {
        let (client, server) = mock_osv_server(vec![
            serde_json::json!({"next_page_token":"page-two"}),
            serde_json::json!({"vulns":[{"id":"GHSA-example"}]}),
        ])
        .await;
        let ids = client.query("example", "npm", Some("1.0.0")).await.unwrap();
        assert_eq!(ids, vec!["GHSA-example"]);
        let requests = server.await.unwrap();
        assert_eq!(requests[1]["page_token"], "page-two");
        assert_eq!(requests[1]["version"], "1.0.0");
        assert_eq!(requests[1]["package"]["name"], "example");
    }

    #[tokio::test]
    async fn incomplete_osv_responses_fail_closed() {
        for responses in [
            vec![serde_json::json!({"vulns":[{"id":null}]})],
            vec![serde_json::json!({"error":"upstream unavailable"})],
            vec![serde_json::json!({"vulns":null})],
            vec![
                serde_json::json!({"next_page_token":"again"}),
                serde_json::json!({"next_page_token":"again"}),
            ],
            (0..100)
                .map(|page| serde_json::json!({"next_page_token":page.to_string()}))
                .collect(),
        ] {
            let (client, server) = mock_osv_server(responses).await;
            assert!(client.query("example", "npm", Some("1.0.0")).await.is_err());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn maintenance_notices_are_not_reported_as_vulnerabilities() {
        let (client, server) = mock_osv_server(vec![serde_json::json!({"vulns":[
            {"id":"RUSTSEC-MAINTENANCE", "affected":[{"database_specific":{"informational":"unmaintained"}}]},
            {"id":"RUSTSEC-UNSOUND", "affected":[{"database_specific":{"informational":"unsound"}}]},
            {"id":"GHSA-VULNERABILITY"}
        ]})]).await;
        let ids = client
            .query("example", "cargo", Some("1.0.0"))
            .await
            .unwrap();
        assert_eq!(ids, vec!["GHSA-VULNERABILITY", "RUSTSEC-UNSOUND"]);
        server.await.unwrap();
    }

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
    async fn reusing_cached_results_does_not_extend_their_expiry() {
        let dir = crate::parsers::test_utils::empty_test_dir("osv-expiry");
        let path = dir.join("osv-cache.json");
        let timestamp = cache::now_epoch() - 60;
        cache::atomic_write_json(
            &path,
            &DiskCache {
                timestamp,
                entries: HashMap::from([(
                    "npm:some-pkg:".to_string(),
                    CacheEntry { vuln_ids: vec![] },
                )]),
            },
        );
        let client = MockOsvClient {
            responses: HashMap::from([(
                "some-pkg".to_string(),
                vec!["NEW-VULNERABILITY".to_string()],
            )]),
        };
        let issues = check_malicious_with_cache(
            &client,
            &[dep("some-pkg")],
            &ResolutionResult::default(),
            Some(&path),
        )
        .await
        .unwrap();
        assert!(issues.is_empty(), "fresh cached results should be reused");
        let saved: DiskCache =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            saved.timestamp, timestamp,
            "a cache hit must not postpone refresh"
        );
        crate::parsers::test_utils::cleanup(&dir);
    }

    #[tokio::test]
    async fn future_dated_clean_cache_does_not_hide_vulnerabilities() {
        let dir = crate::parsers::test_utils::empty_test_dir("osv-future-cache");
        let path = dir.join("osv-cache.json");
        cache::atomic_write_json(
            &path,
            &serde_json::json!({
                "timestamp": cache::now_epoch() + 86400,
                "entries": {"npm:some-pkg:": {"vuln_ids": []}}
            }),
        );
        let client = MockOsvClient {
            responses: HashMap::from([(
                "some-pkg".to_string(),
                vec!["NEW-VULNERABILITY".to_string()],
            )]),
        };
        let issues = check_malicious_with_cache(
            &client,
            &[dep("some-pkg")],
            &ResolutionResult::default(),
            Some(&path),
        )
        .await
        .unwrap();
        assert!(
            issues
                .iter()
                .any(|issue| issue.message.contains("NEW-VULNERABILITY"))
        );
        crate::parsers::test_utils::cleanup(&dir);
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
