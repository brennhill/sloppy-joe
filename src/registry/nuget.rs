use anyhow::Result;
use async_trait::async_trait;

pub struct NugetRegistry {
    client: reqwest::Client,
}

impl NugetRegistry {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl super::Registry for NugetRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let lower = package_name.to_lowercase();
        let url = format!(
            "https://api.nuget.org/v3-flatcontainer/{}/index.json",
            lower
        );
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    fn ecosystem(&self) -> &str {
        "dotnet"
    }
}
