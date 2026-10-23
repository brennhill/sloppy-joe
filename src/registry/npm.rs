use super::RegistryExistence;
use anyhow::Result;
use async_trait::async_trait;

use super::strip_version_prefix;

use super::npm_tarball::{self, NpmManifestFacts, NpmTarballRef, TarballLimits};

/// The public npm registry. Packument and tarball URLs must use this origin.
const NPM_REGISTRY_ORIGIN: &str = "https://registry.npmjs.org";
const NPM_DOWNLOADS_BASE: &str = "https://api.npmjs.org/downloads/point/last-month";

pub struct NpmRegistry {
    client: reqwest::Client,
    /// Separate client for tarballs: never follows redirects, HTTPS only.
    tarball_client: reqwest::Client,
    origin: reqwest::Url,
    downloads_base: String,
    tarball_limits: TarballLimits,
}

impl NpmRegistry {
    pub fn new() -> Self {
        Self::with_client(super::http_client())
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            tarball_client: tarball_http_client(),
            origin: reqwest::Url::parse(NPM_REGISTRY_ORIGIN).expect("valid registry origin"),
            downloads_base: NPM_DOWNLOADS_BASE.to_string(),
            tarball_limits: TarballLimits::default(),
        }
    }

    /// Registry rooted at a local test server (plain HTTP, no proxy).
    #[cfg(test)]
    pub(crate) fn for_test(origin: &str, tarball_limits: TarballLimits) -> Self {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self {
            client: client.clone(),
            tarball_client: client,
            origin: reqwest::Url::parse(origin).unwrap(),
            downloads_base: format!("{origin}/downloads"),
            tarball_limits,
        }
    }
}

impl NpmRegistry {
    fn packument_url(&self, package_name: &str) -> String {
        format!(
            "{}/{package_name}",
            self.origin.as_str().trim_end_matches('/')
        )
    }
}

impl Default for NpmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn tarball_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("sloppy-joe (https://github.com/brennhill/sloppy-joe)")
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .expect("failed to build HTTP client")
}

fn metadata_from_body(
    body: &serde_json::Value,
    version: Option<&str>,
) -> Option<super::PackageMetadata> {
    if is_unpublished_packument(body) {
        return None;
    }
    let time = &body["time"];
    let created = time["created"].as_str().map(|s| s.to_string());
    let repository_url = body["repository"]["url"]
        .as_str()
        .or_else(|| body["repository"].as_str())
        .map(|s| s.to_string());

    let requested_ver = version.map(strip_version_prefix);
    if let Some(ref requested_ver) = requested_ver
        && !body["versions"][requested_ver.as_str()].is_object()
    {
        return Some(super::PackageMetadata {
            created,
            repository_url,
            ..Default::default()
        });
    }

    // If a specific version is requested, look up its publish date
    let latest_version_date = if let Some(ver) = version {
        let base_ver = strip_version_prefix(ver);
        time[&base_ver].as_str().map(|s| s.to_string())
    } else {
        time["modified"].as_str().map(|s| s.to_string())
    };

    let downloads = None;

    let version_list = ordered_versions(time);
    let selected_ver = requested_ver.or_else(|| {
        body["dist-tags"]["latest"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| version_list.last().cloned())
    })?;

    // The previous version is the nearest earlier publish that still exists in
    // `versions`. `time` keeps entries for removed versions; skipping over one
    // must not blank the previous publisher, but it is reported.
    let (previous_ver, removed_previous_version) =
        previous_existing_version(&version_list, &body["versions"], &selected_ver);

    let install = install_script_facts(&body["versions"][selected_ver.as_str()]);
    let has_install_scripts = install.has_install_scripts;
    let manifest_inconsistency = install.inconsistency;

    let dependency_count = runtime_dependency_count(&body["versions"][selected_ver.as_str()]);

    let previous_dependency_count = previous_ver
        .as_ref()
        .and_then(|pv| runtime_dependency_count(&body["versions"][pv.as_str()]));

    let npm_tarball = Some(npm_tarball::tarball_ref_from_version(
        &selected_ver,
        &body["versions"][selected_ver.as_str()],
    ));

    let current_publisher = body["versions"][selected_ver.as_str()]["_npmUser"]["name"]
        .as_str()
        .map(|s| s.to_string());

    let previous_publisher = previous_ver.as_ref().and_then(|pv| {
        body["versions"][pv.as_str()]["_npmUser"]["name"]
            .as_str()
            .map(|s| s.to_string())
    });

    // Build version history: collect publisher + scripts + date for versions within 12 months
    let version_history =
        build_version_history(&body["versions"], time, super::VERSION_HISTORY_WINDOW_HOURS);

    Some(super::PackageMetadata {
        created,
        latest_version_date,
        downloads,
        has_install_scripts,
        dependency_count,
        previous_dependency_count,
        current_publisher,
        previous_publisher,
        repository_url,
        version_history,
        downloads_unavailable: None,
        manifest_inconsistency,
        removed_previous_version,
        npm_tarball,
    })
}

/// Runtime dependency count: names in `dependencies` and
/// `optionalDependencies` (npm's publish normalisation moves names between
/// them, and the tarball check compares the same union). `None` when the
/// version declares neither section.
fn runtime_dependency_count(version_obj: &serde_json::Value) -> Option<u64> {
    let sections: Vec<_> = ["dependencies", "optionalDependencies"]
        .iter()
        .filter_map(|section| version_obj[*section].as_object())
        .collect();
    if sections.is_empty() {
        return None;
    }
    let names: std::collections::BTreeSet<&String> =
        sections.iter().flat_map(|deps| deps.keys()).collect();
    Some(names.len() as u64)
}

/// A packument with no installable versions. registry.npmjs.org answers a
/// fully unpublished package with HTTP 200 and a `time.unpublished` stub; the
/// name is then free for anyone to claim, so it must not count as existing.
fn is_unpublished_packument(body: &serde_json::Value) -> bool {
    body["versions"].as_object().is_none_or(|v| v.is_empty())
}

/// Find the nearest version published before `selected` that still exists in
/// `versions`. Also returns the version published immediately before
/// `selected` when that one has been removed from `versions`.
fn previous_existing_version(
    version_list: &[String],
    versions: &serde_json::Value,
    selected: &str,
) -> (Option<String>, Option<String>) {
    let Some(position) = version_list.iter().position(|v| v == selected) else {
        return (None, None);
    };
    let earlier = &version_list[..position];
    let removed = earlier
        .last()
        .filter(|v| !versions[v.as_str()].is_object())
        .cloned();
    let previous = earlier
        .iter()
        .rev()
        .find(|v| versions[v.as_str()].is_object())
        .cloned();
    (previous, removed)
}

struct InstallScriptFacts {
    has_install_scripts: bool,
    inconsistency: Option<String>,
}

/// Derive install-script facts from a packument version object.
///
/// The packument is publisher-supplied and npm does not validate it against
/// the tarball ("manifest confusion"). As a partial mitigation, every install
/// indicator is honoured (declared `scripts`, the registry's `hasInstallScript`
/// flag, and `gypfile`, which makes npm run `node-gyp rebuild` implicitly), and
/// disagreement between them is reported as an inconsistency.
fn install_script_facts(version_obj: &serde_json::Value) -> InstallScriptFacts {
    let scripts = &version_obj["scripts"];
    let lifecycle = ["preinstall", "install", "postinstall"]
        .iter()
        .any(|hook| scripts[*hook].is_string());
    let prepare = scripts["prepare"].is_string();
    let gypfile = version_obj["gypfile"].as_bool() == Some(true);
    let registry_flag = version_obj["hasInstallScript"].as_bool();

    let inconsistency = match registry_flag {
        Some(true) if !lifecycle && !gypfile => Some(
            "the registry reports an install script (hasInstallScript) but the published manifest declares no preinstall/install/postinstall script or gypfile"
                .to_string(),
        ),
        Some(false) if lifecycle => Some(
            "the published manifest declares a preinstall/install/postinstall script but the registry reports hasInstallScript=false"
                .to_string(),
        ),
        _ => None,
    };

    InstallScriptFacts {
        has_install_scripts: lifecycle || prepare || gypfile || registry_flag == Some(true),
        inconsistency,
    }
}

/// Interpret an npm downloads API response. Any non-success status or a body
/// without a numeric count means downloads are unavailable.
fn downloads_from_response(
    status: reqwest::StatusCode,
    body: &serde_json::Value,
) -> std::result::Result<u64, String> {
    if !status.is_success() {
        return Err(format!(
            "npm downloads API returned HTTP {}",
            status.as_u16()
        ));
    }
    body["downloads"]
        .as_u64()
        .ok_or_else(|| "npm downloads API response had no download count".to_string())
}

/// Record a downloads lookup outcome on the metadata. Failures are kept
/// visible via `downloads_unavailable` instead of silently disabling the
/// download-based signals.
fn apply_downloads(meta: &mut super::PackageMetadata, result: Result<u64>) {
    match result {
        Ok(count) => {
            meta.downloads = Some(count);
            meta.downloads_unavailable = None;
        }
        Err(err) => {
            meta.downloads = None;
            meta.downloads_unavailable = Some(err.to_string());
        }
    }
}

/// Get ordered version list from the `time` object, excluding "created" and "modified" meta-keys.
/// Returns versions in chronological order.
fn ordered_versions(time: &serde_json::Value) -> Vec<String> {
    let Some(obj) = time.as_object() else {
        return vec![];
    };
    let mut versions: Vec<(String, String)> = obj
        .iter()
        .filter(|(k, _)| k.as_str() != "created" && k.as_str() != "modified")
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect();
    versions.sort_by(|a, b| a.1.cmp(&b.1));
    versions.into_iter().map(|(k, _)| k).collect()
}

/// Build version history records from npm `versions` object and `time` object.
/// Only includes versions published within the given age threshold (in hours).
/// Versions without a date in the `time` object are included (can't be age-filtered).
/// Returns records in chronological order (oldest first).
fn build_version_history(
    versions: &serde_json::Value,
    time: &serde_json::Value,
    max_age_hours: u64,
) -> Vec<super::VersionRecord> {
    let Some(versions_obj) = versions.as_object() else {
        return Vec::new();
    };

    let mut records: Vec<(super::VersionRecord, String)> = Vec::new();
    for (ver, ver_data) in versions_obj {
        let date_str = time[ver.as_str()].as_str().map(|s| s.to_string());

        // Filter by age: if date is available and older than threshold, skip
        if let Some(ref d) = date_str
            && let Some(age) = crate::checks::metadata::age_in_hours(d)
            && age > max_age_hours
        {
            continue;
        }

        let publisher = ver_data["_npmUser"]["name"].as_str().map(|s| s.to_string());

        let has_install_scripts = install_script_facts(ver_data).has_install_scripts;

        let sort_key = date_str
            .clone()
            .unwrap_or_else(|| "9999-12-31T23:59:59Z".to_string());
        records.push((
            super::VersionRecord {
                version: ver.clone(),
                publisher,
                has_install_scripts,
                date: date_str,
            },
            sort_key,
        ));
    }

    // Sort chronologically (oldest first)
    records.sort_by(|a, b| a.1.cmp(&b.1));
    records.into_iter().map(|(r, _)| r).collect()
}

/// Fetch last-month download count from the npm downloads API.
/// Any failure (transport, non-2xx, malformed body) is an error so callers
/// can surface it rather than silently dropping download-based signals.
async fn fetch_downloads(
    client: &reqwest::Client,
    downloads_base: &str,
    package_name: &str,
) -> Result<u64> {
    let url = format!("{downloads_base}/{package_name}");
    let resp = super::retry_get(client, &url)
        .await
        .map_err(|e| anyhow::anyhow!("npm downloads API request failed: {e}"))?;
    let status = resp.status();
    let body: serde_json::Value = if status.is_success() {
        resp.json()
            .await
            .map_err(|e| anyhow::anyhow!("npm downloads API returned invalid JSON: {e}"))?
    } else {
        serde_json::Value::Null
    };
    downloads_from_response(status, &body).map_err(anyhow::Error::msg)
}

#[async_trait]
impl super::RegistryExistence for NpmRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let url = self.packument_url(package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        if !super::check_existence_status(resp.status(), "npm registry", package_name)? {
            return Ok(false);
        }
        // A 200 can still be a fully unpublished stub; an unreadable body is
        // an error (fail closed), never "exists".
        let body: serde_json::Value = resp.json().await.map_err(|e| {
            anyhow::anyhow!(
                "npm registry returned an unreadable document for '{package_name}': {e}"
            )
        })?;
        Ok(!is_unpublished_packument(&body))
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl super::RegistryMetadata for NpmRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        self.validate_name(package_name)?;
        let url = self.packument_url(package_name);

        // Fetch registry doc and download counts concurrently
        let (registry_resp, downloads_result) = tokio::join!(
            super::retry_get(&self.client, &url),
            fetch_downloads(&self.client, &self.downloads_base, package_name)
        );

        let resp = registry_resp?;
        if super::check_metadata_status(resp.status(), "npm registry", package_name)?.is_none() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await?;
        let mut meta = match metadata_from_body(&body, version) {
            Some(m) => m,
            None => return Ok(None),
        };

        apply_downloads(&mut meta, downloads_result);

        Ok(Some(meta))
    }

    async fn verify_npm_tarball(
        &self,
        package_name: &str,
        tarball: &NpmTarballRef,
    ) -> Result<Option<NpmManifestFacts>> {
        self.validate_name(package_name)?;
        npm_tarball::fetch_and_verify(
            &self.tarball_client,
            &self.origin,
            package_name,
            tarball,
            self.tarball_limits,
        )
        .await
        .map(Some)
    }
}

#[cfg(test)]
#[path = "npm_hardening_tests.rs"]
mod hardening_tests;

#[cfg(test)]
#[path = "npm_tarball_tests.rs"]
mod tarball_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: returns an ISO 8601 date string approximately N months ago.
    /// Uses relative time so tests don't rot when hardcoded dates age out.
    fn months_ago(months: u64) -> String {
        let secs = crate::cache::now_epoch() as i64 - (months as i64 * 30 * 24 * 3600);
        // Use cache module's now_iso8601 style formatting
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hour = time_of_day / 3600;
        let min = (time_of_day % 3600) / 60;
        let sec = time_of_day % 60;
        let mut year = 1970i64;
        let mut rem_days = days;
        loop {
            let ydays = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            };
            if rem_days < ydays {
                break;
            }
            rem_days -= ydays;
            year += 1;
        }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let mdays = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut month = 0i64;
        for (i, &md) in mdays.iter().enumerate() {
            if rem_days < md {
                month = i as i64 + 1;
                break;
            }
            rem_days -= md;
        }
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year,
            month,
            rem_days + 1,
            hour,
            min,
            sec
        )
    }

    #[test]
    fn metadata_from_body_downloads_defaults_to_none() {
        // metadata_from_body itself does not populate downloads —
        // that comes from the separate downloads API call in metadata().
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": "2024-02-01T00:00:00Z",
                "1.0.0": "2020-01-02T00:00:00Z"
            },
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "scripts": {},
                    "dependencies": {},
                    "_npmUser": { "name": "alice" }
                }
            }
        });
        let metadata = metadata_from_body(&body, None).unwrap();
        // downloads is None until enriched by fetch_downloads
        assert_eq!(metadata.downloads, None);
    }

    #[test]
    fn version_history_populated_from_npm_json() {
        // Use relative dates so this test doesn't rot
        let date_8mo = months_ago(8);
        let date_1mo = months_ago(1);
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": &date_1mo,
                "1.0.0": &date_8mo,
                "2.0.0": &date_1mo
            },
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": {
                    "scripts": {},
                    "dependencies": {},
                    "_npmUser": { "name": "alice" }
                },
                "2.0.0": {
                    "scripts": { "postinstall": "node setup.js" },
                    "dependencies": { "a": "^1.0.0" },
                    "_npmUser": { "name": "bob" }
                }
            }
        });
        let metadata = metadata_from_body(&body, None).unwrap();
        assert_eq!(metadata.version_history.len(), 2);
        // Chronological order (oldest first)
        assert_eq!(metadata.version_history[0].version, "1.0.0");
        assert_eq!(
            metadata.version_history[0].publisher.as_deref(),
            Some("alice")
        );
        assert!(!metadata.version_history[0].has_install_scripts);
        assert_eq!(
            metadata.version_history[0].date.as_deref(),
            Some(date_8mo.as_str())
        );

        assert_eq!(metadata.version_history[1].version, "2.0.0");
        assert_eq!(
            metadata.version_history[1].publisher.as_deref(),
            Some("bob")
        );
        assert!(metadata.version_history[1].has_install_scripts);
        assert_eq!(
            metadata.version_history[1].date.as_deref(),
            Some(date_1mo.as_str())
        );
    }

    #[test]
    fn version_history_filters_old_versions() {
        // Versions older than 12 months should be excluded
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": "2026-02-01T00:00:00Z",
                "1.0.0": "2020-01-02T00:00:00Z",
                "2.0.0": "2026-01-15T00:00:00Z"
            },
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": {
                    "scripts": {},
                    "dependencies": {},
                    "_npmUser": { "name": "alice" }
                },
                "2.0.0": {
                    "scripts": {},
                    "dependencies": {},
                    "_npmUser": { "name": "bob" }
                }
            }
        });
        let metadata = metadata_from_body(&body, None).unwrap();
        // 1.0.0 from 2020 should be filtered out (older than 12 months)
        assert_eq!(metadata.version_history.len(), 1);
        assert_eq!(metadata.version_history[0].version, "2.0.0");
    }

    #[test]
    fn version_history_handles_missing_npm_user() {
        let date_1mo = months_ago(1);
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": &date_1mo,
                "1.0.0": &date_1mo
            },
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "scripts": {},
                    "dependencies": {}
                    // no _npmUser
                }
            }
        });
        let metadata = metadata_from_body(&body, None).unwrap();
        assert_eq!(metadata.version_history.len(), 1);
        assert_eq!(metadata.version_history[0].publisher, None);
    }

    #[test]
    fn version_history_handles_missing_scripts() {
        let date_1mo = months_ago(1);
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": &date_1mo,
                "1.0.0": &date_1mo
            },
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "dependencies": {},
                    "_npmUser": { "name": "alice" }
                    // no scripts object
                }
            }
        });
        let metadata = metadata_from_body(&body, None).unwrap();
        assert_eq!(metadata.version_history.len(), 1);
        assert!(!metadata.version_history[0].has_install_scripts);
    }

    #[test]
    fn version_history_handles_missing_time_entry() {
        // Version exists but has no time entry — should be included with date=None
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": "2026-02-01T00:00:00Z"
                // no time entry for 1.0.0
            },
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "scripts": {},
                    "dependencies": {},
                    "_npmUser": { "name": "alice" }
                }
            }
        });
        let metadata = metadata_from_body(&body, None).unwrap();
        // Version without a date can't be age-filtered, so include it
        assert_eq!(metadata.version_history.len(), 1);
        assert_eq!(metadata.version_history[0].date, None);
    }

    #[test]
    fn version_history_empty_for_no_versions() {
        let date_1mo = months_ago(1);
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": &date_1mo,
                "1.0.0": &date_1mo
            },
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "scripts": {},
                    "dependencies": {},
                    "_npmUser": { "name": "alice" }
                }
            }
        });
        // This test just verifies that when versions object is present,
        // version_history is populated (already tested above)
        let metadata = metadata_from_body(&body, None).unwrap();
        assert!(!metadata.version_history.is_empty());
    }

    #[test]
    fn dateless_versions_sort_to_end() {
        let date_2mo = months_ago(2);
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": &date_2mo,
                "1.0.0": &date_2mo
                // no time entry for 2.0.0
            },
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": {
                    "scripts": {},
                    "dependencies": {},
                    "_npmUser": { "name": "alice" }
                },
                "2.0.0": {
                    "scripts": {},
                    "dependencies": {},
                    "_npmUser": { "name": "bob" }
                }
            }
        });
        let metadata = metadata_from_body(&body, None).unwrap();
        assert_eq!(metadata.version_history.len(), 2);
        // Dated version comes first; dateless version sorts to the end
        assert_eq!(metadata.version_history[0].version, "1.0.0");
        assert!(metadata.version_history[0].date.is_some());
        assert_eq!(metadata.version_history[1].version, "2.0.0");
        assert!(metadata.version_history[1].date.is_none());
    }

    #[test]
    fn metadata_uses_requested_version_for_release_signals() {
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": "2024-02-01T00:00:00Z",
                "1.0.0": "2020-01-02T00:00:00Z",
                "1.1.0": "2020-02-01T00:00:00Z"
            },
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": {
                    "scripts": {},
                    "dependencies": { "a": "^1.0.0" },
                    "_npmUser": { "name": "alice" }
                },
                "1.1.0": {
                    "scripts": { "postinstall": "node setup.js" },
                    "dependencies": { "a": "^1.0.0", "b": "^2.0.0" },
                    "_npmUser": { "name": "bob" }
                }
            }
        });

        let metadata = metadata_from_body(&body, Some("1.0.0")).unwrap();
        assert_eq!(
            metadata.latest_version_date,
            Some("2020-01-02T00:00:00Z".to_string())
        );
        assert!(!metadata.has_install_scripts);
        assert_eq!(metadata.dependency_count, Some(1));
        assert_eq!(metadata.current_publisher, Some("alice".to_string()));
        assert_eq!(metadata.previous_dependency_count, None);
        assert_eq!(metadata.previous_publisher, None);
    }

    #[test]
    fn metadata_does_not_fallback_to_latest_when_requested_version_is_missing() {
        let body = serde_json::json!({
            "time": {
                "created": "2020-01-01T00:00:00Z",
                "modified": "2024-02-01T00:00:00Z",
                "1.1.0": "2020-02-01T00:00:00Z"
            },
            "dist-tags": { "latest": "1.1.0" },
            "repository": { "url": "https://github.com/example/pkg" },
            "versions": {
                "1.1.0": {
                    "scripts": { "postinstall": "node setup.js" },
                    "dependencies": { "a": "^1.0.0", "b": "^2.0.0" },
                    "_npmUser": { "name": "bob" }
                }
            }
        });

        let metadata = metadata_from_body(&body, Some("1.0.0")).unwrap();
        assert_eq!(metadata.latest_version_date, None);
        assert!(!metadata.has_install_scripts);
        assert_eq!(metadata.current_publisher, None);
        assert_eq!(
            metadata.repository_url.as_deref(),
            Some("https://github.com/example/pkg")
        );
    }
}
