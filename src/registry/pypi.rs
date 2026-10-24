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
        if super::check_metadata_status(resp.status(), "PyPI", package_name)?.is_none() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(Some(metadata_from_body(&body, version)))
    }
}

fn first_upload(body: &serde_json::Value) -> Option<String> {
    body["releases"]
        .as_object()
        .and_then(|releases| {
            releases
                .values()
                .filter_map(|files| files.as_array()?.first()?.get("upload_time")?.as_str())
                .min()
                .map(|s| s.to_string())
        })
        .or_else(|| body["info"]["upload_time"].as_str().map(|s| s.to_string()))
}

fn repository_url(body: &serde_json::Value) -> Option<String> {
    body["info"]["project_urls"]["Repository"]
        .as_str()
        .or_else(|| body["info"]["project_urls"]["Source"].as_str())
        .or_else(|| body["info"]["project_urls"]["Source Code"].as_str())
        .or_else(|| {
            body["info"]["home_page"].as_str().filter(|u| {
                u.contains("github.com") || u.contains("gitlab.com") || u.contains("bitbucket.org")
            })
        })
        .map(|s| s.to_string())
}

/// Metadata for `version` (or the registry's current version) from a PyPI
/// JSON API body. A requested version PyPI lists no files for yields only
/// package-level facts, never the latest version's.
pub(crate) fn metadata_from_body(
    body: &serde_json::Value,
    version: Option<&str>,
) -> super::PackageMetadata {
    let created = first_upload(body);
    let repository_url = repository_url(body);

    let selected = match version {
        Some(ver) => super::strip_version_prefix(ver),
        None => body["info"]["version"].as_str().unwrap_or_default().to_string(),
    };
    let pypi_release = super::pypi_release::release_from_body(body, &selected);
    if version.is_some() && pypi_release.is_none() {
        return super::PackageMetadata {
            created,
            repository_url,
            ..Default::default()
        };
    }

    let latest_version_date = if version.is_some() {
        body["releases"][selected.as_str()]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|v| v["upload_time"].as_str())
            .map(|s| s.to_string())
    } else {
        body["info"]["upload_time"].as_str().map(|s| s.to_string())
    };

    // PyPI main API doesn't expose download counts
    super::PackageMetadata {
        created,
        latest_version_date,
        repository_url,
        release_cadence: super::pypi_release::cadence_from_body(body, &selected),
        pypi_release,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body() -> serde_json::Value {
        json!({
            "info": {"version": "2.0", "upload_time": "2024-06-01T00:00:00"},
            "releases": {
                "1.0": [{"filename": "p-1.0.tar.gz", "url": "https://x/p-1.0.tar.gz",
                         "packagetype": "sdist", "upload_time": "2023-01-01T00:00:00",
                         "upload_time_iso_8601": "2023-01-01T00:00:00Z",
                         "digests": {"sha256": "aa"}}],
                "2.0": [{"filename": "p-2.0.tar.gz", "url": "https://x/p-2.0.tar.gz",
                         "packagetype": "sdist", "upload_time": "2024-06-01T00:00:00",
                         "upload_time_iso_8601": "2024-06-01T00:00:00Z",
                         "digests": {"sha256": "bb"}}],
            }
        })
    }

    #[test]
    fn requested_version_gets_its_own_files_and_cadence() {
        let meta = metadata_from_body(&body(), Some("1.0"));
        let release = meta.pypi_release.unwrap();
        assert_eq!(release.version, "1.0");
        assert_eq!(release.files[0].sha256.as_deref(), Some("aa"));
        assert_eq!(meta.latest_version_date.as_deref(), Some("2023-01-01T00:00:00"));
        assert!(meta.release_cadence.unwrap().previous_release_epoch.is_none());
    }

    #[test]
    fn current_version_is_used_without_a_request() {
        let meta = metadata_from_body(&body(), None);
        assert_eq!(meta.pypi_release.unwrap().version, "2.0");
        assert!(meta.release_cadence.unwrap().previous_release_epoch.is_some());
    }

    #[test]
    fn unlisted_requested_version_never_borrows_the_latest() {
        let meta = metadata_from_body(&body(), Some("3.0"));
        assert!(meta.pypi_release.is_none());
        assert!(meta.release_cadence.is_none());
        assert!(meta.latest_version_date.is_none());
        assert_eq!(meta.created.as_deref(), Some("2023-01-01T00:00:00"));
    }
}
