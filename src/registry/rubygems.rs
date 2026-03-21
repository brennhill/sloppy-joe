use anyhow::Result;
use async_trait::async_trait;

pub struct RubyGemsRegistry {
    client: reqwest::Client,
}

impl RubyGemsRegistry {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl super::Registry for RubyGemsRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let url = format!("https://rubygems.org/api/v1/gems/{}.json", package_name);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    async fn metadata(&self, package_name: &str, _version: Option<&str>) -> Result<Option<super::PackageMetadata>> {
        let url = format!("https://rubygems.org/api/v1/gems/{}.json", package_name);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await?;

        let created = body["created_at"].as_str().map(|s| s.to_string());
        let latest_version_date = body["version_created_at"].as_str().map(|s| s.to_string());
        let downloads = body["downloads"].as_u64();

        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            downloads,
            has_install_scripts: false,
            dependency_count: None,
            previous_dependency_count: None,
            current_publisher: None,
            previous_publisher: None,
        }))
    }

    fn ecosystem(&self) -> &str {
        "ruby"
    }
}
