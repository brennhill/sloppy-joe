use anyhow::Result;
use async_trait::async_trait;

pub struct NpmRegistry {
    client: reqwest::Client,
}

impl NpmRegistry {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl super::Registry for NpmRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let url = format!("https://registry.npmjs.org/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    async fn metadata(&self, package_name: &str) -> Result<Option<super::PackageMetadata>> {
        let url = format!("https://registry.npmjs.org/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await?;
        let time = &body["time"];
        let created = time["created"].as_str().map(|s| s.to_string());
        // Find the latest version date from the "time" object
        let latest_version_date = time["modified"].as_str().map(|s| s.to_string());
        let downloads = None; // npm requires a separate API call for downloads
        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            downloads,
        }))
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}
