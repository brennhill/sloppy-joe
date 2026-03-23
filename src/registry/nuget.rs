use anyhow::Result;
use async_trait::async_trait;

pub struct NugetRegistry {
    client: reqwest::Client,
}

impl NugetRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }
}

impl Default for NugetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::Registry for NugetRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let lower = package_name.to_lowercase();
        let url = format!(
            "https://api.nuget.org/v3-flatcontainer/{}/index.json",
            lower
        );
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "NuGet lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        Ok(true)
    }

    fn ecosystem(&self) -> &str {
        "dotnet"
    }
}
