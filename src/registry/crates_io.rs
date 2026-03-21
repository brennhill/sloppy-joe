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

    fn ecosystem(&self) -> &str {
        "cargo"
    }
}
