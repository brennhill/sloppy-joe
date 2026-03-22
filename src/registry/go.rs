use anyhow::Result;
use async_trait::async_trait;

pub struct GoRegistry {
    client: reqwest::Client,
}

impl GoRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }
}

impl Default for GoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::Registry for GoRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let url = format!("https://pkg.go.dev/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "Go package lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        Ok(true)
    }

    fn ecosystem(&self) -> &str {
        "go"
    }
}
