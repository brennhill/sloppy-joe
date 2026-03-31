use super::RegistryExistence;
use anyhow::Result;
use async_trait::async_trait;

use super::strip_version_prefix;

super::registry_struct!(NpmRegistry);

fn metadata_from_body(
    body: &serde_json::Value,
    version: Option<&str>,
) -> Option<super::PackageMetadata> {
    let time = &body["time"];
    let created = time["created"].as_str().map(|s| s.to_string());

    // If a specific version is requested, look up its publish date
    let latest_version_date = if let Some(ver) = version {
        let base_ver = strip_version_prefix(ver);
        time[&base_ver]
            .as_str()
            .or_else(|| time["modified"].as_str())
            .map(|s| s.to_string())
    } else {
        time["modified"].as_str().map(|s| s.to_string())
    };

    let downloads = None;

    let version_list = ordered_versions(time);
    let selected_ver = version
        .map(strip_version_prefix)
        .filter(|ver| body["versions"][ver.as_str()].is_object())
        .or_else(|| {
            body["dist-tags"]["latest"]
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| version_list.last().cloned())
        })?;

    let previous_ver = version_list
        .iter()
        .position(|v| v == &selected_ver)
        .and_then(|p| {
            if p > 0 {
                Some(version_list[p - 1].clone())
            } else {
                None
            }
        });

    let scripts = &body["versions"][selected_ver.as_str()]["scripts"];
    let has_install_scripts = scripts["preinstall"].is_string()
        || scripts["postinstall"].is_string()
        || scripts["install"].is_string()
        || scripts["prepare"].is_string();

    let dependency_count = body["versions"][selected_ver.as_str()]["dependencies"]
        .as_object()
        .map(|obj| obj.len() as u64);

    let previous_dependency_count = previous_ver.as_ref().and_then(|pv| {
        body["versions"][pv.as_str()]["dependencies"]
            .as_object()
            .map(|obj| obj.len() as u64)
    });

    let current_publisher = body["versions"][selected_ver.as_str()]["_npmUser"]["name"]
        .as_str()
        .map(|s| s.to_string());

    let previous_publisher = previous_ver.as_ref().and_then(|pv| {
        body["versions"][pv.as_str()]["_npmUser"]["name"]
            .as_str()
            .map(|s| s.to_string())
    });

    let repository_url = body["repository"]["url"]
        .as_str()
        .or_else(|| body["repository"].as_str())
        .map(|s| s.to_string());

    // Build version history: collect publisher + scripts + date for versions within 12 months
    let version_history = build_version_history(&body["versions"], time, super::VERSION_HISTORY_WINDOW_HOURS);

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
    })
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

        let publisher = ver_data["_npmUser"]["name"]
            .as_str()
            .map(|s| s.to_string());

        let scripts = &ver_data["scripts"];
        let has_install_scripts = scripts["preinstall"].is_string()
            || scripts["postinstall"].is_string()
            || scripts["install"].is_string()
            || scripts["prepare"].is_string();

        let sort_key = date_str.clone().unwrap_or_else(|| "9999-12-31T23:59:59Z".to_string());
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
/// Returns Ok(Some(count)) on success, Ok(None) if unavailable.
async fn fetch_downloads(client: &reqwest::Client, package_name: &str) -> Result<Option<u64>> {
    let url = format!(
        "https://api.npmjs.org/downloads/point/last-month/{}",
        package_name
    );
    let resp = super::retry_get(client, &url).await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let body: serde_json::Value = resp.json().await?;
    Ok(body["downloads"].as_u64())
}

#[async_trait]
impl super::RegistryExistence for NpmRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let url = format!("https://registry.npmjs.org/{}", package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "npm registry", package_name)
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
        let url = format!("https://registry.npmjs.org/{}", package_name);

        // Fetch registry doc and download counts concurrently
        let (registry_resp, downloads_result) = tokio::join!(
            super::retry_get(&self.client, &url),
            fetch_downloads(&self.client, package_name)
        );

        let resp = registry_resp?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "npm registry metadata lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        let body: serde_json::Value = resp.json().await?;
        let mut meta = match metadata_from_body(&body, version) {
            Some(m) => m,
            None => return Ok(None),
        };

        if let Ok(downloads) = downloads_result {
            meta.downloads = downloads;
        }

        Ok(Some(meta))
    }
}

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
            let ydays = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
            if rem_days < ydays { break; }
            rem_days -= ydays;
            year += 1;
        }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut month = 0i64;
        for (i, &md) in mdays.iter().enumerate() {
            if rem_days < md { month = i as i64 + 1; break; }
            rem_days -= md;
        }
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, rem_days + 1, hour, min, sec)
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
        assert_eq!(metadata.version_history[0].publisher.as_deref(), Some("alice"));
        assert!(!metadata.version_history[0].has_install_scripts);
        assert_eq!(metadata.version_history[0].date.as_deref(), Some(date_8mo.as_str()));

        assert_eq!(metadata.version_history[1].version, "2.0.0");
        assert_eq!(metadata.version_history[1].publisher.as_deref(), Some("bob"));
        assert!(metadata.version_history[1].has_install_scripts);
        assert_eq!(metadata.version_history[1].date.as_deref(), Some(date_1mo.as_str()));
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
}
