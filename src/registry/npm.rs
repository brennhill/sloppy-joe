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

        let downloads = None; // npm requires a separate API call for downloads

        // Determine the latest and previous versions from the time object
        let version_list = ordered_versions(time);
        let latest_ver = body["dist-tags"]["latest"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| version_list.last().cloned());

        let previous_ver = if let Some(ref lv) = latest_ver {
            let pos = version_list.iter().position(|v| v == lv);
            pos.and_then(|p| {
                if p > 0 {
                    Some(version_list[p - 1].clone())
                } else {
                    None
                }
            })
        } else {
            None
        };

        // Check for install scripts in the latest version
        let has_install_scripts = if let Some(ref lv) = latest_ver {
            let scripts = &body["versions"][lv.as_str()]["scripts"];
            scripts["preinstall"].is_string()
                || scripts["postinstall"].is_string()
                || scripts["install"].is_string()
                || scripts["prepare"].is_string()
        } else {
            false
        };

        // Count dependencies in current and previous versions
        let dependency_count = latest_ver.as_ref().and_then(|lv| {
            body["versions"][lv.as_str()]["dependencies"]
                .as_object()
                .map(|obj| obj.len() as u64)
        });

        let previous_dependency_count = previous_ver.as_ref().and_then(|pv| {
            body["versions"][pv.as_str()]["dependencies"]
                .as_object()
                .map(|obj| obj.len() as u64)
        });

        // Publisher info
        let current_publisher = latest_ver.as_ref().and_then(|lv| {
            body["versions"][lv.as_str()]["_npmUser"]["name"]
                .as_str()
                .map(|s| s.to_string())
        });

        let previous_publisher = previous_ver.as_ref().and_then(|pv| {
            body["versions"][pv.as_str()]["_npmUser"]["name"]
                .as_str()
                .map(|s| s.to_string())
        });

        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            downloads,
            has_install_scripts,
            dependency_count,
            previous_dependency_count,
            current_publisher,
            previous_publisher,
        }))
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}
