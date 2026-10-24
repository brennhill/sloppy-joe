//! Dependencies of a Gradle build that lists `google()` next to
//! `mavenCentral()`. Gradle takes an artifact from the first repository that
//! has it, so a dependency exists if either repository serves it. Google's
//! repository uses the Maven layout:
//!
//! - `<base>/<group as path>/<artifact>/maven-metadata.xml` lists versions
//! - `<base>/<group as path>/<artifact>/<v>/<artifact>-<v>.pom`
//!
//! Neither exposes publish dates in the metadata, so the POM's `Last-Modified`
//! header is the publication date, as for Gradle plugin markers.

use super::gradle_plugins::{http_date_to_iso8601, maven_timestamp_to_iso8601};
use super::{Registry, RegistryExistence, RegistryMetadata};
use anyhow::{Result, bail};
use async_trait::async_trait;

/// Base URL of Google's Maven repository.
pub(crate) const GOOGLE_MAVEN_URL: &str = "https://dl.google.com/dl/android/maven2/";

const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

pub struct MavenWithGoogleRegistry {
    central: Box<dyn Registry>,
    client: reqwest::Client,
    base: String,
}

impl MavenWithGoogleRegistry {
    pub fn with_client(client: reqwest::Client) -> Self {
        Self::with_central(
            Box::new(super::maven::MavenRegistry::with_client(client.clone())),
            client,
            GOOGLE_MAVEN_URL.to_string(),
        )
    }

    pub(crate) fn with_central(
        central: Box<dyn Registry>,
        client: reqwest::Client,
        base: String,
    ) -> Self {
        Self {
            central,
            client,
            base,
        }
    }

    /// `<base><group path>/<artifact>` for a `group:artifact` name, refusing
    /// anything that is not a plain Maven coordinate.
    fn artifact_dir(&self, package_name: &str) -> Result<Option<String>> {
        let Some((group, artifact)) = package_name.split_once(':') else {
            return Ok(None);
        };
        let plain = |part: &str| {
            !part.is_empty()
                && !part.contains("..")
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        };
        if !plain(group) || !plain(artifact) {
            bail!("invalid Maven coordinate '{package_name}'");
        }
        Ok(Some(format!(
            "{}{}/{}",
            self.base,
            group.replace('.', "/"),
            artifact
        )))
    }

    async fn fetch_versions(
        &self,
        dir: &str,
        package_name: &str,
    ) -> Result<Option<(Vec<String>, Option<String>)>> {
        let url = format!("{dir}/maven-metadata.xml");
        let mut resp = super::retry_get(&self.client, &url).await?;
        if super::check_metadata_status(resp.status(), "Google Maven", package_name)?.is_none() {
            return Ok(None);
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_METADATA_BYTES {
                bail!(
                    "Google Maven metadata for '{package_name}' exceeds {MAX_METADATA_BYTES} bytes"
                );
            }
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8_lossy(&body);
        let versions = body
            .split_once("<versions>")
            .and_then(|(_, rest)| rest.split_once("</versions>"))
            .map(|(versions, _)| {
                versions
                    .split("<version>")
                    .skip(1)
                    .filter_map(|entry| entry.split_once("</version>"))
                    .map(|(version, _)| version.trim().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let last_updated = crate::fsutil::extract_xml_value(&body, "lastUpdated")
            .and_then(|value| maven_timestamp_to_iso8601(value.trim()));
        Ok(Some((versions, last_updated)))
    }

    /// `Last-Modified` of one version's POM. `Ok(None)`: no such POM.
    async fn pom_date(
        &self,
        dir: &str,
        artifact: &str,
        version: &str,
        package_name: &str,
    ) -> Result<Option<Option<String>>> {
        if !safe_version(version) {
            bail!("invalid Maven version '{version}' for '{package_name}'");
        }
        let url = format!("{dir}/{version}/{artifact}-{version}.pom");
        let resp = super::retry_get(&self.client, &url).await?;
        if super::check_metadata_status(resp.status(), "Google Maven", package_name)?.is_none() {
            return Ok(None);
        }
        Ok(Some(
            resp.headers()
                .get(reqwest::header::LAST_MODIFIED)
                .and_then(|value| value.to_str().ok())
                .and_then(http_date_to_iso8601),
        ))
    }
}

fn safe_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.contains("..")
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

#[async_trait]
impl RegistryExistence for MavenWithGoogleRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        if self.central.exists(package_name).await? {
            return Ok(true);
        }
        let Some(dir) = self.artifact_dir(package_name)? else {
            return Ok(false);
        };
        let resp = super::retry_get(&self.client, &format!("{dir}/maven-metadata.xml")).await?;
        super::check_existence_status(resp.status(), "Google Maven", package_name)
    }

    fn ecosystem(&self) -> &str {
        "jvm"
    }
}

#[async_trait]
impl RegistryMetadata for MavenWithGoogleRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        if let Some(found) = self.central.metadata(package_name, version).await? {
            return Ok(Some(found));
        }
        let Some(dir) = self.artifact_dir(package_name)? else {
            return Ok(None);
        };
        let Some((versions, last_updated)) = self.fetch_versions(&dir, package_name).await? else {
            return Ok(None);
        };
        let artifact = package_name.rsplit(':').next().unwrap_or_default();
        let published = match version {
            Some(version) => self
                .pom_date(&dir, artifact, version, package_name)
                .await?
                .flatten(),
            None => None,
        };
        // The oldest listed version gives the package's creation date.
        let created = match versions.first() {
            Some(first) if Some(first.as_str()) == version => published.clone(),
            Some(first) => self
                .pom_date(&dir, artifact, first, package_name)
                .await?
                .flatten(),
            None => None,
        };
        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date: published.or(last_updated),
            ..Default::default()
        }))
    }
}
