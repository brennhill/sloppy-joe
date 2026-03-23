use anyhow::Result;
use async_trait::async_trait;

super::registry_struct!(NugetRegistry);

#[async_trait]
impl super::RegistryExistence for NugetRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let lower = package_name.to_lowercase();
        let url = format!(
            "https://api.nuget.org/v3-flatcontainer/{}/index.json",
            lower
        );
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "NuGet", package_name)
    }

    fn ecosystem(&self) -> &str {
        "dotnet"
    }
}

#[async_trait]
impl super::RegistryMetadata for NugetRegistry {}
