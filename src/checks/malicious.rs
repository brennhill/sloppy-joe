use crate::report::{Issue, Severity};
use crate::Dependency;
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

const DEFAULT_CACHE_FILE: &str = "/tmp/sloppy-joe-osv-cache.json";
const CACHE_TTL_SECS: u64 = 6 * 3600; // 6 hours

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

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_disk_cache(path: &Path) -> Option<DiskCache> {
    let content = std::fs::read_to_string(path).ok()?;
    let cache: DiskCache = serde_json::from_str(&content).ok()?;
    let age = now_epoch().saturating_sub(cache.timestamp);
    if age < CACHE_TTL_SECS {
        Some(cache)
    } else {
        None
    }
}

fn save_disk_cache(path: &Path, entries: &HashMap<String, CacheEntry>) {
    let cache = DiskCache {
        timestamp: now_epoch(),
        entries: entries.clone(),
    };
    if let Ok(json) = serde_json::to_string(&cache) {
        let _ = std::fs::write(path, json);
    }
}

/// Map ecosystem strings to OSV ecosystem names.
fn osv_ecosystem(ecosystem: &str) -> &str {
    match ecosystem {
        "npm" => "npm",
        "pypi" => "PyPI",
        "cargo" => "crates.io",
        "go" => "Go",
        "ruby" => "RubyGems",
        "jvm" => "Maven",
        "dotnet" => "NuGet",
        "php" => "Packagist",
        _ => ecosystem,
    }
}

/// Strip semver prefixes like ^, ~, >= from a version string.
fn strip_version_prefix(version: &str) -> String {
    version.trim_start_matches(|c: char| c == '^' || c == '~' || c == '>' || c == '=' || c == '<' || c == ' ').to_string()
}

/// An OSV client that can be swapped out for testing.
#[async_trait::async_trait]
pub trait OsvClient: Send + Sync {
    async fn query(&self, name: &str, ecosystem: &str, version: Option<&str>) -> Result<Vec<String>>;
}

/// Real OSV client that hits the API.
pub struct RealOsvClient {
    client: reqwest::Client,
}

impl RealOsvClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl OsvClient for RealOsvClient {
    async fn query(&self, name: &str, ecosystem: &str, version: Option<&str>) -> Result<Vec<String>> {
        let osv_eco = osv_ecosystem(ecosystem);
        let mut body = serde_json::json!({
            "package": {
                "name": name,
                "ecosystem": osv_eco
            }
        });
        // Include version to filter to only vulnerabilities affecting this version
        if let Some(ver) = version {
            let base_ver = strip_version_prefix(ver);
            if !base_ver.is_empty() {
                body["version"] = serde_json::Value::String(base_ver);
            }
        }
        let resp = self.client
            .post("https://api.osv.dev/v1/query")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(vec![]);
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
/// Uses a 6-hour disk cache at the default path.
pub async fn check_malicious(
    osv_client: &dyn OsvClient,
    deps: &[Dependency],
) -> Result<Vec<Issue>> {
    check_malicious_with_cache(osv_client, deps, Some(Path::new(DEFAULT_CACHE_FILE))).await
}

/// Check all dependencies against the OSV vulnerability database.
/// `cache_path` controls disk caching: None disables disk cache entirely.
pub async fn check_malicious_with_cache(
    osv_client: &dyn OsvClient,
    deps: &[Dependency],
    cache_path: Option<&Path>,
) -> Result<Vec<Issue>> {
    // Load disk cache if fresh
    let initial_entries = cache_path
        .and_then(|p| load_disk_cache(p))
        .map(|c| c.entries)
        .unwrap_or_default();
    let cache: Mutex<HashMap<String, CacheEntry>> = Mutex::new(initial_entries);

    let mut issues = Vec::new();

    for dep in deps {
        let version_suffix = dep.version.as_deref().map(|v| strip_version_prefix(v)).unwrap_or_default();
        let cache_key = format!("{}:{}:{}", dep.ecosystem, dep.name, version_suffix);

        // Check in-memory/disk cache first
        let cached = {
            let c = cache.lock().unwrap();
            c.get(&cache_key).cloned()
        };

        let vuln_ids = if let Some(entry) = cached {
            entry.vuln_ids
        } else {
            let ids = osv_client.query(&dep.name, &dep.ecosystem, dep.version.as_deref()).await?;
            let entry = CacheEntry { vuln_ids: ids.clone() };
            cache.lock().unwrap().insert(cache_key, entry);
            ids
        };

        if !vuln_ids.is_empty() {
            issues.push(Issue {
                package: dep.name.clone(),
                check: "malicious/known-vulnerability".to_string(),
                severity: Severity::Error,
                message: format!(
                    "'{}' has known security vulnerabilities in the OSV database. Vulnerability IDs: {}",
                    dep.name,
                    vuln_ids.join(", ")
                ),
                fix: format!(
                    "Remove '{}' or update to a non-vulnerable version.",
                    dep.name
                ),
                suggestion: None,
                registry_url: None,
            });
        }
    }

    // Save cache to disk
    if let Some(path) = cache_path {
        let c = cache.lock().unwrap();
        save_disk_cache(path, &c);
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
        async fn query(&self, name: &str, _ecosystem: &str, _version: Option<&str>) -> Result<Vec<String>> {
            Ok(self.responses.get(name).cloned().unwrap_or_default())
        }
    }

    fn dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: "npm".to_string(),
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

        let deps = vec![dep("event-stream")];
        let issues = check_malicious_with_cache(&client, &deps, None).await.unwrap();

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

        let deps = vec![dep("react")];
        let issues = check_malicious_with_cache(&client, &deps, None).await.unwrap();

        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn cache_used_when_fresh() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        struct CountingClient {
            call_count: Arc<AtomicU32>,
            responses: HashMap<String, Vec<String>>,
        }

        #[async_trait::async_trait]
        impl OsvClient for CountingClient {
            async fn query(&self, name: &str, _ecosystem: &str, _version: Option<&str>) -> Result<Vec<String>> {
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
        let deps = vec![dep("some-pkg"), dep("some-pkg")];
        let issues = check_malicious_with_cache(&client, &deps, None).await.unwrap();

        // Should have 2 issues (one per dep occurrence) but only 1 API call
        assert_eq!(issues.len(), 2);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
