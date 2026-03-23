use super::RegistryExistence;
use anyhow::Result;
use async_trait::async_trait;

fn gem_url(package_name: &str) -> String {
    format!("https://rubygems.org/api/v1/gems/{}.json", package_name)
}

fn gem_version_url(package_name: &str, version: &str) -> String {
    format!(
        "https://rubygems.org/api/v2/rubygems/{}/versions/{}.json",
        package_name, version
    )
}

pub struct RubyGemsRegistry {
    client: reqwest::Client,
}

impl RubyGemsRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for RubyGemsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::RegistryExistence for RubyGemsRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let url = gem_url(package_name);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "RubyGems lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        Ok(true)
    }

    fn ecosystem(&self) -> &str {
        "ruby"
    }
}

#[async_trait]
impl super::RegistryMetadata for RubyGemsRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        self.validate_name(package_name)?;
        let url = gem_url(package_name);

        // Fetch gem info and version-specific endpoints concurrently when a version is provided
        let gem_fut = self.client.get(&url).send();
        let version_fut = async {
            if let Some(ver) = version {
                Some(self.client.get(gem_version_url(package_name, ver)).send().await)
            } else {
                None
            }
        };
        let (gem_resp, version_resp_opt) = tokio::join!(gem_fut, version_fut);

        let resp = gem_resp?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "RubyGems metadata lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        let body: serde_json::Value = resp.json().await?;

        let created = body["created_at"].as_str().map(|s| s.to_string());
        let downloads = body["downloads"].as_u64();

        let latest_version_date = if let Some(ver_resp_result) = version_resp_opt {
            let version_resp = ver_resp_result?;
            if version_resp.status() == reqwest::StatusCode::NOT_FOUND {
                body["version_created_at"].as_str().map(|s| s.to_string())
            } else if !version_resp.status().is_success() {
                anyhow::bail!(
                    "RubyGems version metadata lookup for '{}' {} returned HTTP {}",
                    package_name,
                    version.unwrap_or("unknown"),
                    version_resp.status()
                );
            } else {
                let version_body: serde_json::Value = version_resp.json().await?;
                version_body["version_created_at"]
                    .as_str()
                    .or_else(|| body["version_created_at"].as_str())
                    .map(|s| s.to_string())
            }
        } else {
            body["version_created_at"].as_str().map(|s| s.to_string())
        };

        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            downloads,
            has_install_scripts: false,
            dependency_count: None,
            previous_dependency_count: None,
            current_publisher: None,
            previous_publisher: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_metadata_url_uses_specific_version_endpoint() {
        let url = gem_version_url("rails", "7.0.4");
        assert_eq!(
            url,
            "https://rubygems.org/api/v2/rubygems/rails/versions/7.0.4.json"
        );
    }
}
