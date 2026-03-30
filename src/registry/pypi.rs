use super::RegistryExistence;
use anyhow::Result;
use async_trait::async_trait;

super::registry_struct!(PypiRegistry);

#[async_trait]
impl super::RegistryExistence for PypiRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let url = format!("https://pypi.org/pypi/{}/json", package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "PyPI", package_name)
    }

    fn ecosystem(&self) -> &str {
        "pypi"
    }
}

#[async_trait]
impl super::RegistryMetadata for PypiRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        self.validate_name(package_name)?;
        let url = format!("https://pypi.org/pypi/{}/json", package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "PyPI metadata lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        let body: serde_json::Value = resp.json().await?;

        let created = body["releases"]
            .as_object()
            .and_then(|releases| {
                releases
                    .values()
                    .filter_map(|files| files.as_array()?.first()?.get("upload_time")?.as_str())
                    .min()
                    .map(|s| s.to_string())
            })
            .or_else(|| body["info"]["upload_time"].as_str().map(|s| s.to_string()));

        let latest_version_date = if let Some(ver) = version {
            let base_ver = super::strip_version_prefix(ver);
            body["releases"][base_ver]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v["upload_time"].as_str())
                .or_else(|| body["info"]["upload_time"].as_str())
                .map(|s| s.to_string())
        } else {
            body["info"]["upload_time"].as_str().map(|s| s.to_string())
        };

        // PyPI project_urls or home_page for repository link
        let repository_url = body["info"]["project_urls"]["Repository"]
            .as_str()
            .or_else(|| body["info"]["project_urls"]["Source"].as_str())
            .or_else(|| body["info"]["project_urls"]["Source Code"].as_str())
            .or_else(|| {
                body["info"]["home_page"].as_str().filter(|u| {
                    u.contains("github.com")
                        || u.contains("gitlab.com")
                        || u.contains("bitbucket.org")
                })
            })
            .map(|s| s.to_string());

        // PyPI main API doesn't expose download counts
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
