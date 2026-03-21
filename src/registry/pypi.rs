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

    async fn metadata(&self, package_name: &str, version: Option<&str>) -> Result<Option<super::PackageMetadata>> {
        let url = format!("https://pypi.org/pypi/{}/json", package_name);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await?;

        let created = body["info"]["upload_time"].as_str().map(|s| s.to_string());

        let latest_version_date = if let Some(ver) = version {
            let base_ver = ver.trim_start_matches(|c: char| c == '^' || c == '~' || c == '>' || c == '=' || c == '<' || c == ' ');
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
