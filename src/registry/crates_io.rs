//! crates.io: existence from the sparse index, metadata from the web API.
//!
//! The web API (`crates.io/api/v1`) is rate limited per client address: a burst
//! is answered with HTTP 429 (no `Retry-After`) for minutes, and its policy asks
//! automated clients to keep their request rate low. The sparse index
//! (`index.crates.io`) is the CDN Cargo itself reads and carries no such limit,
//! so every existence question (similarity probes, the existence fallback) goes
//! there, and only the metadata the index lacks (creation date, downloads,
//! publishers, repository) is asked of the API, once per crate and with a
//! bounded number of requests in flight.
use super::RegistryExistence;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{OnceCell, Semaphore};

const API_BASE: &str = "https://crates.io/api/v1/crates";
const INDEX_BASE: &str = "https://index.crates.io";
/// Web API requests in flight at once, across the whole process.
const API_CONCURRENCY: usize = 4;
static API_PERMITS: Semaphore = Semaphore::const_new(API_CONCURRENCY);
/// Names with more separators than this are checked on the web API instead of
/// probing every `-`/`_` spelling on the index (2^n spellings).
const MAX_INDEX_SEPARATORS: usize = 3;

/// One API answer per crate name for this registry's lifetime (one scan):
/// `None` when the crate does not exist.
type CrateCell = Arc<OnceCell<Option<Arc<CrateRecord>>>>;

pub struct CratesIoRegistry {
    client: reqwest::Client,
    api_base: String,
    index_base: String,
    crates: Mutex<HashMap<String, CrateCell>>,
}

impl CratesIoRegistry {
    pub fn new() -> Self {
        Self::with_client(super::http_client())
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self::with_endpoints(client, API_BASE.to_string(), INDEX_BASE.to_string())
    }

    fn with_endpoints(client: reqwest::Client, api_base: String, index_base: String) -> Self {
        Self {
            client,
            api_base,
            index_base,
            crates: Mutex::new(HashMap::new()),
        }
    }

    /// Whether the sparse index has a file for exactly this spelling.
    async fn index_has(&self, spelling: &str) -> Result<bool> {
        let url = format!("{}/{}", self.index_base, sparse_index_path(spelling));
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "crates.io sparse index", spelling)
    }

    async fn api_exists(&self, package_name: &str) -> Result<bool> {
        let _permit = API_PERMITS.acquire().await?;
        let url = format!("{}/{}", self.api_base, package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "crates.io", package_name)
    }

    /// The crate's API record, fetched at most once per name. Failures are not
    /// remembered, so a later caller asks again.
    async fn crate_record(&self, package_name: &str) -> Result<Option<Arc<CrateRecord>>> {
        let cell = {
            let mut crates = self
                .crates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            crates.entry(package_name.to_string()).or_default().clone()
        };
        let record = cell
            .get_or_try_init(|| async {
                let _permit = API_PERMITS.acquire().await?;
                let url = format!("{}/{}", self.api_base, package_name);
                let resp = super::retry_get(&self.client, &url).await?;
                if super::check_metadata_status(resp.status(), "crates.io", package_name)?.is_none()
                {
                    return Ok::<_, anyhow::Error>(None);
                }
                let body: serde_json::Value = resp.json().await?;
                Ok(Some(Arc::new(CrateRecord::from_body(&body))))
            })
            .await?;
        Ok(record.clone())
    }
}

impl Default for CratesIoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Where Cargo's sparse index keeps a crate's file (names are lowercased).
fn sparse_index_path(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let prefix: String = lower.chars().take(4).collect();
    match prefix.chars().count() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &prefix[..1]),
        _ => format!("{}/{}/{lower}", &prefix[..2], &prefix[2..4]),
    }
}

/// Every other spelling crates.io treats as the same name (`-` and `_` are
/// interchangeable), or `None` when there are too many to probe.
fn separator_spellings(name: &str) -> Option<Vec<String>> {
    let positions: Vec<usize> = name
        .char_indices()
        .filter(|(_, ch)| matches!(ch, '-' | '_'))
        .map(|(index, _)| index)
        .collect();
    if positions.len() > MAX_INDEX_SEPARATORS {
        return None;
    }
    let spellings = (0u32..1 << positions.len())
        .map(|mask| {
            let mut bytes = name.as_bytes().to_vec();
            for (bit, &position) in positions.iter().enumerate() {
                bytes[position] = if mask & (1 << bit) != 0 { b'_' } else { b'-' };
            }
            String::from_utf8(bytes).expect("only ASCII separators were replaced")
        })
        .filter(|spelling| spelling != name)
        .collect();
    Some(spellings)
}

/// The parts of a crates.io crate record the metadata signals read.
#[derive(Debug, Default)]
struct CrateRecord {
    created: Option<String>,
    updated: Option<String>,
    downloads: Option<u64>,
    repository: Option<String>,
    /// Newest first, as the API lists them; `None` when the body had no list.
    versions: Option<Vec<VersionEntry>>,
}

#[derive(Debug)]
struct VersionEntry {
    num: Option<String>,
    created_at: Option<String>,
    publisher: Option<String>,
}

impl CrateRecord {
    fn from_body(body: &serde_json::Value) -> Self {
        let text = |value: &serde_json::Value| value.as_str().map(str::to_string);
        let versions = body["versions"].as_array().map(|versions| {
            versions
                .iter()
                .map(|version| VersionEntry {
                    num: text(&version["num"]),
                    created_at: text(&version["created_at"]),
                    publisher: text(&version["published_by"]["login"]),
                })
                .collect()
        });
        Self {
            created: text(&body["crate"]["created_at"]),
            updated: text(&body["crate"]["updated_at"]),
            downloads: body["crate"]["downloads"].as_u64(),
            repository: text(&body["crate"]["repository"]),
            versions,
        }
    }

    fn metadata(&self, version: Option<&str>) -> Option<super::PackageMetadata> {
        let versions = self.versions.as_ref()?;
        let selected_index = match version {
            Some(ver) => {
                let base_ver = super::strip_version_prefix(ver);
                versions
                    .iter()
                    .position(|v| v.num.as_deref() == Some(base_ver.as_str()))?
            }
            None => 0,
        };
        let selected = versions.get(selected_index)?;
        let previous = versions.get(selected_index + 1);
        Some(super::PackageMetadata {
            created: self.created.clone(),
            latest_version_date: selected.created_at.clone().or_else(|| self.updated.clone()),
            downloads: self.downloads,
            current_publisher: selected.publisher.clone(),
            previous_publisher: previous.and_then(|v| v.publisher.clone()),
            repository_url: self.repository.clone(),
            ..Default::default()
        })
    }
}

#[cfg(test)]
fn metadata_from_body(
    body: &serde_json::Value,
    version: Option<&str>,
) -> Option<super::PackageMetadata> {
    CrateRecord::from_body(body).metadata(version)
}

#[async_trait]
impl super::RegistryExistence for CratesIoRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        if self.index_has(package_name).await? {
            return Ok(true);
        }
        let Some(spellings) = separator_spellings(package_name) else {
            return self.api_exists(package_name).await;
        };
        let probes = spellings.iter().map(|spelling| self.index_has(spelling));
        let mut failure = None;
        for result in futures::future::join_all(probes).await {
            match result {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(err) => failure = failure.or(Some(err)),
            }
        }
        failure.map_or(Ok(false), Err)
    }

    fn ecosystem(&self) -> &str {
        "cargo"
    }
}

#[async_trait]
impl super::RegistryMetadata for CratesIoRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        self.validate_name(package_name)?;
        let Some(record) = self.crate_record(package_name).await? else {
            return Ok(None);
        };
        Ok(record.metadata(version))
    }

    async fn owners(&self, package_name: &str) -> Result<Option<Vec<String>>> {
        self.validate_name(package_name)?;
        let _permit = API_PERMITS.acquire().await?;
        let url = format!("{}/{}/owners", self.api_base, package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        if super::check_metadata_status(resp.status(), "crates.io", package_name)?.is_none() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await?;
        let owners = body["users"]
            .as_array()
            .map(|users| {
                users
                    .iter()
                    .filter_map(|user| user["login"].as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(Some(owners))
    }
}

#[cfg(test)]
#[path = "crates_io_tests.rs"]
mod tests;
