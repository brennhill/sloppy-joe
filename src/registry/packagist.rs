use anyhow::Result;
use async_trait::async_trait;

super::registry_struct!(PackagistRegistry);

#[async_trait]
impl super::RegistryExistence for PackagistRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let url = format!("https://repo.packagist.org/p2/{}.json", package_name);
        let resp = self.client.get(&url).send().await?;
        super::check_existence_status(resp.status(), "Packagist", package_name)
    }

    fn ecosystem(&self) -> &str {
        "php"
    }
}

#[async_trait]
impl super::RegistryMetadata for PackagistRegistry {}
