use anyhow::Result;
use async_trait::async_trait;

pub struct CratesIoRegistry {
    client: reqwest::Client,
}

impl CratesIoRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for CratesIoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn metadata_from_body(
    body: &serde_json::Value,
    version: Option<&str>,
) -> Option<super::PackageMetadata> {
    let created = body["crate"]["created_at"].as_str().map(|s| s.to_string());
    let downloads = body["crate"]["downloads"].as_u64();

    let versions_arr = body["versions"].as_array()?;
    let selected_index = if let Some(ver) = version {
        let base_ver = ver.trim_start_matches(['^', '~', '>', '=', '<', ' ']);
        versions_arr
            .iter()
            .position(|v| v["num"].as_str() == Some(base_ver))?
    } else {
        0
    };

    let selected = &versions_arr[selected_index];
    let previous = versions_arr.get(selected_index + 1);

    let latest_version_date = selected["created_at"]
        .as_str()
        .or_else(|| body["crate"]["updated_at"].as_str())
        .map(|s| s.to_string());

    let current_publisher = selected["published_by"]["login"]
        .as_str()
        .map(|s| s.to_string());

    let previous_publisher = previous
        .and_then(|v| v["published_by"]["login"].as_str())
        .map(|s| s.to_string());

    Some(super::PackageMetadata {
        created,
        latest_version_date,
        downloads,
        has_install_scripts: false,
        dependency_count: None,
        previous_dependency_count: None,
        current_publisher,
        previous_publisher,
    })
}

#[async_trait]
impl super::Registry for CratesIoRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let url = format!("https://crates.io/api/v1/crates/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "crates.io lookup for '{}' returned HTTP {}",
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
        self.validate_name(package_name)?;
        let url = format!("https://crates.io/api/v1/crates/{}", package_name);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "crates.io metadata lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(metadata_from_body(&body, version))
    }

    fn ecosystem(&self) -> &str {
        "cargo"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_uses_requested_version_for_publisher_history() {
        let body = serde_json::json!({
            "crate": {
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2020-03-01T00:00:00Z",
                "downloads": 1234
            },
            "versions": [
                {
                    "num": "1.2.0",
                    "created_at": "2020-03-01T00:00:00Z",
                    "published_by": { "login": "carol" }
                },
                {
                    "num": "1.1.0",
                    "created_at": "2020-02-01T00:00:00Z",
                    "published_by": { "login": "bob" }
                },
                {
                    "num": "1.0.0",
                    "created_at": "2020-01-02T00:00:00Z",
                    "published_by": { "login": "alice" }
                }
            ]
        });

        let metadata = metadata_from_body(&body, Some("1.1.0")).unwrap();
        assert_eq!(
            metadata.latest_version_date,
            Some("2020-02-01T00:00:00Z".to_string())
        );
        assert_eq!(metadata.current_publisher, Some("bob".to_string()));
        assert_eq!(metadata.previous_publisher, Some("alice".to_string()));
    }
}
