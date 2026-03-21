use anyhow::Result;
use async_trait::async_trait;

pub struct PackagistRegistry {
    client: reqwest::Client,
}

impl PackagistRegistry {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl super::Registry for PackagistRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        // Package names are vendor/package format
        let url = format!("https://repo.packagist.org/p2/{}.json", package_name);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    fn ecosystem(&self) -> &str {
        "php"
    }
}
