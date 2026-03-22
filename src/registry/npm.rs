use anyhow::Result;
use async_trait::async_trait;

/// Strip semver prefixes like ^, ~, >= from a version string.
fn strip_version_prefix(version: &str) -> String {
    version
        .trim_start_matches(['^', '~', '>', '=', '<', ' '])
        .to_string()
}

pub struct NpmRegistry {
    client: reqwest::Client,
}

impl NpmRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }
}

impl Default for NpmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

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

    Some(super::PackageMetadata {
        created,
        latest_version_date,
        downloads,
        has_install_scripts,
        dependency_count,
        previous_dependency_count,
        current_publisher,
        previous_publisher,
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

/// Fetch last-month download count from the npm downloads API.
/// Returns Ok(Some(count)) on success, Ok(None) if unavailable.
async fn fetch_downloads(
    client: &reqwest::Client,
    package_name: &str,
) -> Result<Option<u64>> {
    let url = format!(
        "https://api.npmjs.org/downloads/point/last-month/{}",
        package_name
    );
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let body: serde_json::Value = resp.json().await?;
    Ok(body["downloads"].as_u64())
}

#[async_trait]
impl super::Registry for NpmRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let url = format!("https://registry.npmjs.org/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "npm registry lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        Ok(true)
    }

    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        let url = format!("https://registry.npmjs.org/{}", package_name);
        let resp = self.client.get(&url).send().await?;
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

        // Fetch download counts from the npm downloads API.
        // This is a separate service; failures are non-fatal.
        if let Ok(downloads) = fetch_downloads(&self.client, package_name).await {
            meta.downloads = downloads;
        }

        Ok(Some(meta))
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
