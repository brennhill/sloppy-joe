use anyhow::Result;
use async_trait::async_trait;

pub struct GoRegistry {
    client: reqwest::Client,
}

impl GoRegistry {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("sloppy-joe (https://github.com/brennhill/sloppy-joe)")
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }
}

#[async_trait]
impl super::Registry for GoRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let url = format!("https://pkg.go.dev/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    fn ecosystem(&self) -> &str {
        "go"
    }
}
