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
                            serde_json::from_slice(&request[end + 4..end + 4 + length]).unwrap(),
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
    let issues =
        check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), &[], None)
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
    let issues =
        check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), &[], None)
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
    let issues =
        check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), &[], None)
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
        check_malicious_with_cache(&ErrorClient, &deps, &ResolutionResult::default(), &[], None)
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
        &[],
        Some(&path),
    )
    .await
    .unwrap();
    assert!(issues.is_empty(), "fresh cached results should be reused");
    let saved: DiskCache = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
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
        &[],
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
    let issues =
        check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), &[], None)
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
    let issues =
        check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), &[], None)
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
    let issues =
        check_malicious_with_cache(&client, &deps, &ResolutionResult::default(), &[], None)
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
        check_malicious_with_cache(&SlowClient, &deps, &ResolutionResult::default(), &[], None)
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
        &[],
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

/// Answers only for the exact (ecosystem, name) pairs it knows, the way
/// OSV matches names; records every query.
struct ExactOsv {
    known: HashMap<(String, String), Vec<String>>,
    seen: std::sync::Mutex<Vec<(String, String)>>,
}

impl ExactOsv {
    fn new(ecosystem: &str, name: &str, ids: &[&str]) -> Self {
        Self {
            known: HashMap::from([(
                (ecosystem.to_string(), name.to_string()),
                ids.iter().map(|id| id.to_string()).collect(),
            )]),
            seen: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl OsvClient for ExactOsv {
    async fn query(
        &self,
        name: &str,
        ecosystem: &str,
        _version: Option<&str>,
    ) -> Result<Vec<String>> {
        let key = (ecosystem.to_string(), name.to_string());
        self.seen.lock().unwrap().push(key.clone());
        Ok(self.known.get(&key).cloned().unwrap_or_default())
    }
}

fn eco_dep(ecosystem: Ecosystem, name: &str, version: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem,
        actual_name: None,
    }
}

fn lookup(dep: &Dependency, registry_ids: &[&str]) -> crate::checks::metadata::MetadataLookup {
    crate::checks::metadata::MetadataLookup {
        package: dep.package_name().to_string(),
        ecosystem: dep.ecosystem,
        version: dep.version.clone(),
        resolved_version: dep.version.clone(),
        unresolved_version: false,
        exists: true,
        metadata: Some(crate::registry::PackageMetadata {
            registry_ids: registry_ids.iter().map(|id| id.to_string()).collect(),
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn packagist_names_are_queried_in_their_lowercase_registry_form() {
    let osv = ExactOsv::new("php", "symfony/http-kernel", &["GHSA-PHP"]);
    let deps = [eco_dep(Ecosystem::Php, "Symfony/Http-Kernel", "4.4.0")];
    let issues = check_malicious_with_cache(&osv, &deps, &ResolutionResult::default(), &[], None)
        .await
        .unwrap();
    assert!(
        issues.iter().any(|i| i.message.contains("GHSA-PHP")),
        "{issues:?}"
    );
}

#[tokio::test]
async fn nuget_ids_are_queried_with_the_spelling_the_registry_publishes() {
    let osv = ExactOsv::new("dotnet", "Newtonsoft.Json", &["GHSA-NUGET"]);
    let deps = [eco_dep(Ecosystem::Dotnet, "newtonsoft.json", "12.0.1")];
    let lookups = [lookup(&deps[0], &["Newtonsoft.Json"])];
    let issues =
        check_malicious_with_cache(&osv, &deps, &ResolutionResult::default(), &lookups, None)
            .await
            .unwrap();
    assert!(
        issues.iter().any(|i| i.package == "newtonsoft.json"
            && i.check == crate::names::MALICIOUS_KNOWN_VULNERABILITY
            && i.message.contains("GHSA-NUGET")),
        "{issues:?}"
    );
}

#[tokio::test]
async fn nuget_package_without_a_known_registry_spelling_blocks() {
    let osv = ExactOsv::new("dotnet", "Newtonsoft.Json", &["GHSA-NUGET"]);
    let deps = [eco_dep(Ecosystem::Dotnet, "newtonsoft.json", "12.0.1")];
    let lookups = [lookup(&deps[0], &[])];
    let issues =
        check_malicious_with_cache(&osv, &deps, &ResolutionResult::default(), &lookups, None)
            .await
            .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check == crate::names::MALICIOUS_REGISTRY_UNREACHABLE
                && i.severity == Severity::Error
                && i.message.contains("newtonsoft.json")),
        "{issues:?}"
    );
}

#[tokio::test]
async fn cached_result_for_the_written_spelling_does_not_hide_the_registry_spelling() {
    let dir = crate::parsers::test_utils::empty_test_dir("osv-spelling-cache");
    let path = dir.join("osv-cache.json");
    cache::atomic_write_json(
        &path,
        &DiskCache {
            timestamp: cache::now_epoch(),
            entries: HashMap::from([(
                "dotnet:newtonsoft.json:12.0.1".to_string(),
                CacheEntry { vuln_ids: vec![] },
            )]),
        },
    );
    let osv = ExactOsv::new("dotnet", "Newtonsoft.Json", &["GHSA-NUGET"]);
    let deps = [eco_dep(Ecosystem::Dotnet, "newtonsoft.json", "12.0.1")];
    let lookups = [lookup(&deps[0], &["Newtonsoft.Json"])];
    let issues = check_malicious_with_cache(
        &osv,
        &deps,
        &ResolutionResult::default(),
        &lookups,
        Some(&path),
    )
    .await
    .unwrap();
    assert!(
        issues.iter().any(|i| i.message.contains("GHSA-NUGET")),
        "{issues:?}"
    );
    crate::parsers::test_utils::cleanup(&dir);
}

#[test]
fn query_names_follow_each_registry_rule() {
    let names = |eco, name, ids: &[&str]| {
        let ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        osv_query_names(&eco_dep(eco, name, "1.0.0"), &ids)
    };
    assert_eq!(names(Ecosystem::Php, "Acme/Lib", &[]), ["acme/lib"]);
    assert_eq!(
        names(Ecosystem::PyPI, "Zope.Interface", &[]),
        ["zope-interface"]
    );
    assert_eq!(
        names(Ecosystem::Dotnet, "acme.lib", &["Acme.Lib", "acme.lib"]),
        ["Acme.Lib", "acme.lib"]
    );
    assert_eq!(names(Ecosystem::Npm, "JSONStream", &[]), ["JSONStream"]);
    assert_eq!(names(Ecosystem::Ruby, "Rails", &["rails"]), ["Rails"]);
}

#[tokio::test]
async fn unknown_ecosystem_is_an_error_not_npm() {
    let client = RealOsvClient::with_client(reqwest::Client::new());
    assert!(client.query("left-pad", "bogus", None).await.is_err());
}
