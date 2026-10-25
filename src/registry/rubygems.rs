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

fn gem_versions_url(package_name: &str) -> String {
    format!("https://rubygems.org/api/v1/versions/{}.json", package_name)
}

/// The earliest `created_at` in a `/api/v1/versions/<gem>.json` listing. A listing without
/// one is an error: an unknown first publish date must not read as an old gem.
fn first_published(versions: &serde_json::Value, package_name: &str) -> Result<String> {
    let entries = versions.as_array().ok_or_else(|| {
        anyhow::anyhow!("RubyGems version list for '{package_name}' is not an array")
    })?;
    let mut earliest: Option<(i64, &str)> = None;
    for entry in entries {
        let created = entry["created_at"].as_str();
        let epoch = created.and_then(crate::cache::iso_to_epoch).ok_or_else(|| {
            anyhow::anyhow!(
                "RubyGems version list for '{package_name}' has a version without a valid created_at"
            )
        })?;
        if earliest.is_none_or(|(seen, _)| epoch < seen) {
            earliest = created.map(|created| (epoch, created));
        }
    }
    earliest
        .map(|(_, created)| created.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "RubyGems lists no versions for '{package_name}'; its first publish date is unknown"
            )
        })
}

super::registry_struct!(RubyGemsRegistry);

#[async_trait]
impl super::RegistryExistence for RubyGemsRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let url = gem_url(package_name);
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "RubyGems", package_name)
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
        let gem_fut = super::retry_get(&self.client, &url);
        let version_fut = async {
            if let Some(ver) = version {
                Some(super::retry_get(&self.client, &gem_version_url(package_name, ver)).await)
            } else {
                None
            }
        };
        let (gem_resp, version_resp_opt) = tokio::join!(gem_fut, version_fut);

        let resp = gem_resp?;
        if super::check_metadata_status(resp.status(), "RubyGems", package_name)?.is_none() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await?;

        // The gem endpoint has no creation date; the oldest version's is the gem's.
        let versions_resp = super::retry_get(&self.client, &gem_versions_url(package_name)).await?;
        if !versions_resp.status().is_success() {
            anyhow::bail!(
                "RubyGems version list for '{}' returned HTTP {}",
                package_name,
                versions_resp.status()
            );
        }
        let created = Some(first_published(&versions_resp.json().await?, package_name)?);
        let downloads = body["downloads"].as_u64();

        let latest_version_date = if let Some(ver_resp_result) = version_resp_opt {
            let version_resp = ver_resp_result?;
            if version_resp.status() == reqwest::StatusCode::NOT_FOUND {
                None
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

        let repository_url = body["source_code_uri"]
            .as_str()
            .or_else(|| {
                body["homepage_uri"]
                    .as_str()
                    .filter(|u| u.contains("github.com") || u.contains("gitlab.com"))
            })
            .map(|s| s.to_string());

        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            downloads,
            repository_url,
            ..Default::default()
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

    #[test]
    fn first_publish_date_is_the_oldest_version() {
        let versions = serde_json::json!([
            {"number": "2.0.0", "created_at": "2024-05-01T00:00:00.000Z"},
            {"number": "0.1.0", "created_at": "2009-07-25T18:02:13.000Z"},
            {"number": "1.0.0", "created_at": "2015-01-01T00:00:00.000Z"}
        ]);
        assert_eq!(
            first_published(&versions, "rack").unwrap(),
            "2009-07-25T18:02:13.000Z"
        );
        assert_eq!(
            gem_versions_url("rack"),
            "https://rubygems.org/api/v1/versions/rack.json"
        );
    }

    #[test]
    fn unknown_first_publish_date_fails_closed() {
        for versions in [
            serde_json::json!([]),
            serde_json::json!({"error": "nope"}),
            serde_json::json!([{"number": "1.0.0"}]),
            serde_json::json!([{"number": "1.0.0", "created_at": "yesterday"}]),
        ] {
            assert!(first_published(&versions, "gem").is_err(), "{versions}");
        }
    }
}
