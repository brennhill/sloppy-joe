use crate::Dependency;
use crate::cache;
use crate::checks::metadata::MetadataLookup;
use crate::lockfiles::ResolutionResult;
use crate::lockfiles::python_hashes::normalize_name;
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
        let eco: Ecosystem = ecosystem
            .parse()
            .map_err(|e| anyhow::anyhow!("OSV query for '{name}': {e}"))?;
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

/// The spellings OSV is queried with for one dependency. OSV matches package
/// names exactly, so each name is put in the form its registry publishes:
/// Packagist names are lowercase, PyPI names are PEP 503 normalized, and
/// NuGet ids keep the casing their publisher chose, which only the registry
/// knows (`registry_ids`, every spelling it reports, plus the name as written).
pub(crate) fn osv_query_names(dep: &Dependency, registry_ids: &[String]) -> Vec<String> {
    let name = dep.package_name();
    let mut names = match dep.ecosystem {
        Ecosystem::PyPI => vec![normalize_name(name)],
        Ecosystem::Php => vec![name.to_ascii_lowercase()],
        Ecosystem::Dotnet => std::iter::once(name.to_string())
            .chain(registry_ids.iter().cloned())
            .collect(),
        _ => vec![name.to_string()],
    };
    names.sort();
    names.dedup();
    names
}

/// Registry-published id spellings per (ecosystem, package) from metadata.
fn registry_ids_by_package(lookups: &[MetadataLookup]) -> HashMap<(Ecosystem, &str), &[String]> {
    lookups
        .iter()
        .filter_map(|lookup| {
            let metadata = lookup.metadata.as_ref()?;
            Some((
                (lookup.ecosystem, lookup.package.as_str()),
                metadata.registry_ids.as_slice(),
            ))
        })
        .collect()
}

/// A NuGet package the registry knows but whose published id spelling is
/// unknown cannot be matched against OSV, which compares names exactly.
fn unmatchable_nuget_ids(deps: &[Dependency], lookups: &[MetadataLookup]) -> Vec<Issue> {
    deps.iter()
        .filter(|dep| dep.ecosystem == Ecosystem::Dotnet)
        .filter(|dep| {
            lookups.iter().any(|lookup| {
                lookup.ecosystem == dep.ecosystem
                    && lookup.package == dep.package_name()
                    && lookup.exists
                    && lookup
                        .metadata
                        .as_ref()
                        .is_none_or(|metadata| metadata.registry_ids.is_empty())
            })
        })
        .map(|dep| {
            Issue::new(
                dep.package_name(),
                crate::names::MALICIOUS_REGISTRY_UNREACHABLE,
                Severity::Error,
            )
            .message(format!(
                "NuGet did not report the published id of '{}', and OSV matches NuGet ids \
                 case-sensitively. Known vulnerabilities for it cannot be looked up.",
                dep.package_name()
            ))
            .fix("Retry the scan; if it persists, check that the package is on nuget.org.")
        })
        .collect()
}

#[derive(Clone)]
struct OsvQuery {
    names: Vec<String>,
    ecosystem: Ecosystem,
    version: Option<String>,
}

impl OsvQuery {
    fn new(dep: &Dependency, resolution: &ResolutionResult, ids: &[String]) -> Self {
        Self {
            names: osv_query_names(dep, ids),
            ecosystem: dep.ecosystem,
            version: resolution.exact_version(dep).map(str::to_string),
        }
    }

    /// Cache key over every spelling queried, so a result cached for fewer
    /// spellings never answers a query that needs more.
    fn cache_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.ecosystem,
            self.names.join("|"),
            self.version.as_deref().unwrap_or_default()
        )
    }

    async fn run(&self, osv_client: &dyn OsvClient) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        for name in &self.names {
            ids.extend(
                osv_client
                    .query(name, self.ecosystem.as_str(), self.version.as_deref())
                    .await?,
            );
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
}

fn osv_unreachable_issue(error_count: usize, total_queries: usize) -> Issue {
    let error_rate = error_count as f64 / total_queries.max(1) as f64;
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
    .fix("Ensure the OSV API is reachable and retry the scan.")
}

fn known_vulnerability_issue(dep: &Dependency, vuln_ids: &[String]) -> Issue {
    Issue::new(
        dep.package_name(),
        crate::names::MALICIOUS_KNOWN_VULNERABILITY,
        Severity::Error,
    )
    .message(format!(
        "'{}' has known security vulnerabilities in the OSV database. Vulnerability IDs: {}",
        dep.package_name(),
        vuln_ids.join(", ")
    ))
    .fix(format!(
        "Remove '{}' or update to a non-vulnerable version.",
        dep.package_name()
    ))
}

/// Check all dependencies against the OSV vulnerability database.
/// Uses a 1-hour disk cache at the default path.
pub async fn check_malicious(
    osv_client: &dyn OsvClient,
    deps: &[Dependency],
    resolution: &ResolutionResult,
    lookups: &[MetadataLookup],
) -> Result<Vec<Issue>> {
    let cache_path = default_cache_file();
    check_malicious_with_cache(
        osv_client,
        deps,
        resolution,
        lookups,
        Some(cache_path.as_path()),
    )
    .await
}

/// Check all dependencies against the OSV vulnerability database.
/// `lookups` carries registry metadata (for registry-published id spellings).
/// `cache_path` controls disk caching: None disables disk cache entirely.
pub async fn check_malicious_with_cache(
    osv_client: &dyn OsvClient,
    deps: &[Dependency],
    resolution: &ResolutionResult,
    lookups: &[MetadataLookup],
    cache_path: Option<&Path>,
) -> Result<Vec<Issue>> {
    // Load disk cache if fresh (using shared cache utilities: symlink protection, atomic writes)
    let initial_cache = cache_path
        .and_then(|p| cache::read_json_cache::<DiskCache>(p, CACHE_TTL_SECS, |c| c.timestamp));
    let timestamp = initial_cache
        .as_ref()
        .map_or_else(cache::now_epoch, |c| c.timestamp);
    let mut cache = initial_cache.map(|c| c.entries).unwrap_or_default();

    let registry_ids = registry_ids_by_package(lookups);
    // Query OSV even for unresolved deps — OSV supports name-only queries
    // and will return all known vulnerabilities for the package.
    let queries: Vec<OsvQuery> = deps
        .iter()
        .map(|dep| {
            let ids = registry_ids
                .get(&(dep.ecosystem, dep.package_name()))
                .copied()
                .unwrap_or_default();
            OsvQuery::new(dep, resolution, ids)
        })
        .collect();

    let mut pending = HashMap::new();
    for query in &queries {
        let key = query.cache_key();
        if !cache.contains_key(&key) {
            pending.entry(key).or_insert_with(|| query.clone());
        }
    }

    let results: Vec<_> = stream::iter(pending)
        .map(|(cache_key, query)| async move { (cache_key, query.run(osv_client).await) })
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
            Err(_) => error_count += 1,
        }
    }

    let mut issues = unmatchable_nuget_ids(deps, lookups);
    if crate::checks::has_query_errors(error_count) {
        issues.push(osv_unreachable_issue(error_count, total_queries));
    }

    for (dep, query) in deps.iter().zip(&queries) {
        if let Some(entry) = cache.get(&query.cache_key())
            && !entry.vuln_ids.is_empty()
        {
            issues.push(known_vulnerability_issue(dep, &entry.vuln_ids));
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
mod cache_integrity_tests;

#[cfg(test)]
#[path = "malicious_tests.rs"]
mod tests;
