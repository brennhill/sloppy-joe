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

    fn ecosystem(&self) -> &str {
        "ruby"
    }
}
