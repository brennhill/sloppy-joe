use anyhow::Result;
use async_trait::async_trait;

pub struct PackagistRegistry {
    client: reqwest::Client,
}

impl PackagistRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for PackagistRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::RegistryExistence for PackagistRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        // Package names are vendor/package format
        let url = format!("https://repo.packagist.org/p2/{}.json", package_name);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "Packagist lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        Ok(true)
    }

    fn ecosystem(&self) -> &str {
        "php"
    }
}

#[async_trait]
impl super::RegistryMetadata for PackagistRegistry {}
