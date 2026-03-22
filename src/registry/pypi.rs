use anyhow::Result;
use async_trait::async_trait;

pub struct PypiRegistry {
    client: reqwest::Client,
}

impl PypiRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }
}

impl Default for PypiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::Registry for PypiRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let url = format!("https://pypi.org/pypi/{}/json", package_name);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "PyPI lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        Ok(true)
    }

    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        let url = format!("https://pypi.org/pypi/{}/json", package_name);
        let resp = self.client.get(&url).send().await?;
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

        let created = body["info"]["upload_time"].as_str().map(|s| s.to_string());

        let latest_version_date = if let Some(ver) = version {
            let base_ver = ver.trim_start_matches(['^', '~', '>', '=', '<', ' ']);
            body["releases"][base_ver]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v["upload_time"].as_str())
                .or_else(|| body["info"]["upload_time"].as_str())
                .map(|s| s.to_string())
        } else {
            body["info"]["upload_time"].as_str().map(|s| s.to_string())
        };

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
        }))
    }

    fn ecosystem(&self) -> &str {
        "pypi"
    }
}
