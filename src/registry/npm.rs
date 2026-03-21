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

    fn ecosystem(&self) -> &str {
        "npm"
    }
}
