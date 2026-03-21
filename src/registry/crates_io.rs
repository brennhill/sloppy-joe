use anyhow::Result;
use async_trait::async_trait;

pub struct CratesIoRegistry {
    client: reqwest::Client,
}

impl CratesIoRegistry {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("sloppy-joe (https://github.com/brennhill/sloppy-joe)")
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }
}

#[async_trait]
impl super::Registry for CratesIoRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let url = format!("https://crates.io/api/v1/crates/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    async fn metadata(&self, package_name: &str, version: Option<&str>) -> Result<Option<super::PackageMetadata>> {
        let url = format!("https://crates.io/api/v1/crates/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await?;

        let created = body["crate"]["created_at"].as_str().map(|s| s.to_string());
        let downloads = body["crate"]["downloads"].as_u64();

        let latest_version_date = if let Some(ver) = version {
            let base_ver = ver.trim_start_matches(|c: char| c == '^' || c == '~' || c == '>' || c == '=' || c == '<' || c == ' ');
            // Search the versions array for the matching version
            body["versions"]
                .as_array()
                .and_then(|versions| {
                    versions.iter().find(|v| v["num"].as_str() == Some(base_ver))
                })
                .and_then(|v| v["created_at"].as_str())
                .or_else(|| body["crate"]["updated_at"].as_str())
                .map(|s| s.to_string())
        } else {
            body["crate"]["updated_at"].as_str().map(|s| s.to_string())
        };

        // Publisher info from versions array (index 0 = latest, index 1 = previous)
        let versions_arr = body["versions"].as_array();

        let current_publisher = versions_arr
            .and_then(|v| v.first())
            .and_then(|v| v["published_by"]["login"].as_str())
            .map(|s| s.to_string());

        let previous_publisher = versions_arr
            .and_then(|v| v.get(1))
            .and_then(|v| v["published_by"]["login"].as_str())
            .map(|s| s.to_string());

        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            downloads,
            has_install_scripts: false, // crates.io doesn't have install scripts
            dependency_count: None,     // Not easily available from crates.io API
            previous_dependency_count: None,
            current_publisher,
            previous_publisher,
        }))
    }

    fn ecosystem(&self) -> &str {
        "cargo"
    }
}
