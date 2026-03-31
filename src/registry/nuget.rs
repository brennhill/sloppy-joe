use super::RegistryExistence;
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
impl super::RegistryMetadata for NugetRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        self.validate_name(package_name)?;
        let lower = package_name.to_lowercase();

        // NuGet registration API: returns all versions with publish dates
        let url = format!(
            "https://api.nuget.org/v3/registration5-semver1/{}/index.json",
            lower
        );
        let resp = super::retry_get(&self.client, &url).await?;
        if super::check_metadata_status(resp.status(), "NuGet", package_name)?.is_none() {
            return Ok(None);
        }

        let body: serde_json::Value = resp.json().await?;

        // Registration response has pages -> items -> catalogEntry with published date
        let items = body["items"].as_array();
        if items.is_none() {
            return Ok(None);
        }

        // Find the specific version or use the latest
        let target_ver = version.map(super::strip_version_prefix);
        let mut created: Option<String> = None;
        let mut latest_version_date: Option<String> = None;

        if let Some(pages) = items {
            for page in pages {
                let page_items = page["items"].as_array();
                if let Some(entries) = page_items {
                    for entry in entries {
                        let cat = &entry["catalogEntry"];
                        let ver = cat["version"].as_str().unwrap_or_default();
                        let published = cat["published"].as_str();

                        // Track earliest publish date
                        if let Some(pub_date) = published
                            && (created.is_none() || pub_date < created.as_deref().unwrap_or("z"))
                        {
                            created = Some(pub_date.to_string());
                        }

                        // Match specific version or take latest
                        if let Some(ref target) = target_ver {
                            if ver == target.as_str() {
                                latest_version_date = published.map(|s| s.to_string());
                            }
                        } else {
                            // Last entry in last page is typically latest
                            latest_version_date = published.map(|s| s.to_string());
                        }
                    }
                } else {
                    // Page might be a reference without inline items — use upper/lower bounds
                    // For now, skip pages that need separate fetching
                }
            }
        }

        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            ..Default::default()
        }))
    }
}
