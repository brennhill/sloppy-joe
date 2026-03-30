use super::RegistryExistence;
use anyhow::Result;
use async_trait::async_trait;

super::registry_struct!(PackagistRegistry);

#[async_trait]
impl super::RegistryExistence for PackagistRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let url = format!("https://repo.packagist.org/p2/{}.json", package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "Packagist", package_name)
    }

    fn ecosystem(&self) -> &str {
        "php"
    }
}

#[async_trait]
impl super::RegistryMetadata for PackagistRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        self.validate_name(package_name)?;

        // Packagist p2 API returns all versions with time fields
        let url = format!("https://repo.packagist.org/p2/{}.json", package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "Packagist metadata for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }

        let body: serde_json::Value = resp.json().await?;

        // p2 response: {"packages": {"vendor/name": [{"version": "1.0", "time": "2024-..."}]}}
        let versions = body["packages"][package_name].as_array();
        let Some(versions) = versions else {
            return Ok(None);
        };

        let target_ver = version.map(super::strip_version_prefix);
        let mut created: Option<String> = None;
        let mut latest_version_date: Option<String> = None;

        for entry in versions {
            let ver = entry["version"].as_str().unwrap_or_default();
            let time = entry["time"].as_str();

            // Track earliest publish
            if let Some(t) = time
                && (created.is_none() || t < created.as_deref().unwrap_or("z"))
            {
                created = Some(t.to_string());
            }

            if let Some(ref target) = target_ver
                && ver == target.as_str()
            {
                latest_version_date = time.map(|s| s.to_string());
            }
        }

        // If no specific version matched, use the first entry (latest)
        if latest_version_date.is_none() {
            latest_version_date = versions
                .first()
                .and_then(|v| v["time"].as_str())
                .map(|s| s.to_string());
        }

        let repository_url = versions
            .first()
            .and_then(|v| v["source"]["url"].as_str())
            .map(|s| s.to_string());

        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            downloads: None,
            has_install_scripts: false,
            dependency_count: None,
            previous_dependency_count: None,
            current_publisher: None,
            previous_publisher: None,
            repository_url,
            version_history: Vec::new(),
        }))
    }
}
