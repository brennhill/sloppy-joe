use anyhow::Result;
use async_trait::async_trait;

pub struct PypiRegistry {
    client: reqwest::Client,
}

impl PypiRegistry {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl super::Registry for PypiRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let url = format!("https://pypi.org/pypi/{}/json", package_name);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    fn ecosystem(&self) -> &str {
        "pypi"
    }
}
