//! Gradle plugin marker lookups.
//!
//! A `plugins { id 'x' version 'v' }` request resolves the marker artifact
//! `x:x.gradle.plugin:v` from the build's plugin repositories, in declaration
//! order (default: the Gradle Plugin Portal). Both supported repositories use
//! the Maven layout:
//!
//! - `<base>/<id as path>/<id>.gradle.plugin/maven-metadata.xml` lists versions
//! - `<base>/<id as path>/<id>.gradle.plugin/<v>/<id>.gradle.plugin-<v>.pom`
//!   is the marker POM Gradle downloads for a pinned version.
//!
//! Neither repository exposes per-version publish dates in its metadata, so
//! the POM's `Last-Modified` header is the publication date; when it is
//! missing, `lastUpdated` (the newest publish of any version, so never older
//! than the requested version) is used, which can only under-estimate age.

use crate::Dependency;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;

pub(crate) use crate::config::{GRADLE_PLUGIN_PORTAL_URL, MAVEN_CENTRAL_URL, PluginRepository};

/// Upper bound for a `maven-metadata.xml` body.
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

/// Registry for one Gradle build's plugin markers. Names that are not plugin
/// markers (`<id>:<id>.gradle.plugin`) never resolve as plugins.
pub struct GradlePluginRegistry {
    client: reqwest::Client,
    /// Repository base URLs (with trailing `/`) in Gradle's lookup order.
    base_urls: Vec<String>,
    /// Pinned version per requested marker: existence means that version is
    /// published, not just the plugin id.
    requested: HashMap<String, String>,
}

impl GradlePluginRegistry {
    /// Only public, known repositories can be queried; a custom repository's
    /// contents are never vetted against a public one.
    pub fn new(
        client: reqwest::Client,
        repositories: &[PluginRepository],
        requested: &[Dependency],
    ) -> Result<Self> {
        let mut base_urls = Vec::new();
        for repository in repositories {
            base_urls.push(match repository {
                PluginRepository::GradlePluginPortal => GRADLE_PLUGIN_PORTAL_URL.to_string(),
                PluginRepository::MavenCentral => MAVEN_CENTRAL_URL.to_string(),
                PluginRepository::Custom(url) => bail!(
                    "custom Gradle plugin repository '{}' cannot be checked as a public registry",
                    crate::config::redact_url_for_display(url)
                ),
            });
        }
        Ok(Self::with_base_urls(client, base_urls, requested))
    }

    pub(crate) fn with_base_urls(
        client: reqwest::Client,
        base_urls: Vec<String>,
        requested: &[Dependency],
    ) -> Self {
        Self {
            client,
            base_urls,
            requested: requested
                .iter()
                .filter_map(|dep| Some((dep.name.clone(), dep.version.clone()?)))
                .collect(),
        }
    }

    /// Directory of the marker artifact relative to a repository base.
    fn marker_dir(base: &str, id: &str) -> String {
        format!("{base}{}/{id}.gradle.plugin", id.replace('.', "/"))
    }

    fn pom_url(base: &str, id: &str, version: &str) -> String {
        format!(
            "{}/{version}/{id}.gradle.plugin-{version}.pom",
            Self::marker_dir(base, id)
        )
    }

    /// GET the marker POM for `version`. `Ok(None)`: not in this repository.
    async fn fetch_pom(
        &self,
        base: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Option<String>>> {
        let url = Self::pom_url(base, id, version);
        let resp = super::retry_get(&self.client, &url).await?;
        if !super::check_existence_status(resp.status(), "Gradle plugin repository", id)? {
            return Ok(None);
        }
        let published = resp
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .and_then(http_date_to_iso8601);
        Ok(Some(published))
    }

    /// The implementation artifacts the marker POM for `version` depends on, as
    /// `(group, artifact, version)`. `Ok(None)`: no repository serves the
    /// marker. A dependency whose version is missing, a property, or a range
    /// cannot be pinned for an advisory lookup, so it is an error (fail closed).
    pub(crate) async fn implementation_artifacts(
        &self,
        package_name: &str,
        version: &str,
    ) -> Result<Option<Vec<(String, String, String)>>> {
        use super::RegistryExistence as _;
        self.validate_name(package_name)?;
        let Some(id) = plugin_marker_id(package_name) else {
            return Ok(None);
        };
        if !safe_version_segment(version) {
            bail!("invalid Gradle plugin version '{version}' for '{id}'");
        }
        for base in &self.base_urls {
            let url = Self::pom_url(base, id, version);
            let resp = super::retry_get(&self.client, &url).await?;
            if !super::check_existence_status(resp.status(), "Gradle plugin repository", id)? {
                continue;
            }
            let body = resp.text().await?;
            return parse_pom_dependencies(&body, id).map(Some);
        }
        Ok(None)
    }

    /// Versions and `lastUpdated` from `maven-metadata.xml`. `Ok(None)`: no
    /// such plugin in this repository.
    async fn fetch_versions(
        &self,
        base: &str,
        id: &str,
    ) -> Result<Option<(Vec<String>, Option<String>)>> {
        let url = format!("{}/maven-metadata.xml", Self::marker_dir(base, id));
        let mut resp = super::retry_get(&self.client, &url).await?;
        if super::check_metadata_status(resp.status(), "Gradle plugin repository", id)?.is_none() {
            return Ok(None);
        }
        if resp
            .content_length()
            .is_some_and(|length| length > MAX_METADATA_BYTES as u64)
        {
            bail!("Gradle plugin metadata for '{id}' exceeds {MAX_METADATA_BYTES} bytes");
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_METADATA_BYTES {
                bail!("Gradle plugin metadata for '{id}' exceeds {MAX_METADATA_BYTES} bytes");
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
}

/// The plugin id of a marker coordinate `<id>:<id>.gradle.plugin`.
fn xml_child<'a>(block: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&format!("</{tag}>"))? + start;
    Some(block[start..end].trim())
}

fn parse_pom_dependencies(pom: &str, id: &str) -> Result<Vec<(String, String, String)>> {
    let mut artifacts = Vec::new();
    let mut rest = pom;
    while let Some(start) = rest.find("<dependency>") {
        let after = &rest[start + "<dependency>".len()..];
        let Some(end) = after.find("</dependency>") else {
            bail!("marker POM for '{id}' has an unterminated <dependency>");
        };
        let block = &after[..end];
        rest = &after[end..];
        let (Some(group), Some(artifact), Some(version)) = (
            xml_child(block, "groupId"),
            xml_child(block, "artifactId"),
            xml_child(block, "version"),
        ) else {
            bail!("marker POM for '{id}' has a dependency without a group, artifact, and version");
        };
        let plain = |value: &str| {
            !value.is_empty()
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
        };
        if !plain(group) || !plain(artifact) || !safe_version_segment(version) {
            bail!("marker POM for '{id}' has a dependency that cannot be pinned exactly");
        }
        artifacts.push((group.to_string(), artifact.to_string(), version.to_string()));
    }
    Ok(artifacts)
}

pub(crate) fn plugin_marker_id(name: &str) -> Option<&str> {
    let (group, artifact) = name.split_once(':')?;
    (artifact.strip_suffix(".gradle.plugin") == Some(group)
        && !group.is_empty()
        && !group.starts_with('.')
        && !group.ends_with('.')
        && !group.contains("..")
        && group
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')))
    .then_some(group)
}

/// A version that is safe as one URL path segment.
fn safe_version_segment(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.contains("..")
        && version
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '+'))
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn iso8601(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> Option<String> {
    crate::cache::checked_date_to_epoch(year, month, day, hour, min, sec)?;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z"
    ))
}

/// `Wed, 21 Oct 2026 09:43:01 GMT` (RFC 9110 IMF-fixdate) to ISO 8601.
pub(crate) fn http_date_to_iso8601(value: &str) -> Option<String> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    let month = MONTHS.iter().position(|name| name == month)? as i64 + 1;
    let mut clock = time.split(':').map(|part| part.parse::<i64>().ok());
    let (hour, min, sec) = (clock.next()??, clock.next()??, clock.next()??);
    if clock.next().is_some() {
        return None;
    }
    iso8601(year.parse().ok()?, month, day.parse().ok()?, hour, min, sec)
}

/// Maven `lastUpdated` (`yyyyMMddHHmmss`, UTC) to ISO 8601.
pub(crate) fn maven_timestamp_to_iso8601(value: &str) -> Option<String> {
    if value.len() != 14 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let field = |range: std::ops::Range<usize>| value[range].parse::<i64>().ok();
    iso8601(
        field(0..4)?,
        field(4..6)?,
        field(6..8)?,
        field(8..10)?,
        field(10..12)?,
        field(12..14)?,
    )
}

#[async_trait]
impl super::RegistryExistence for GradlePluginRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let Some(id) = plugin_marker_id(package_name) else {
            return Ok(false);
        };
        if let Some(version) = self.requested.get(package_name) {
            if !safe_version_segment(version) {
                bail!("invalid Gradle plugin version '{version}' for '{id}'");
            }
            for base in &self.base_urls {
                if self.fetch_pom(base, id, version).await?.is_some() {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        for base in &self.base_urls {
            if let Some((versions, _)) = self.fetch_versions(base, id).await?
                && !versions.is_empty()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn ecosystem(&self) -> &str {
        "jvm"
    }
}

#[async_trait]
impl super::RegistryMetadata for GradlePluginRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        use super::RegistryExistence;
        self.validate_name(package_name)?;
        let Some(id) = plugin_marker_id(package_name) else {
            return Ok(None);
        };
        let Some(version) = version.or(self.requested.get(package_name).map(String::as_str)) else {
            return Ok(None);
        };
        if !safe_version_segment(version) {
            bail!("invalid Gradle plugin version '{version}' for '{id}'");
        }
        for base in &self.base_urls {
            // Gradle takes the first repository that serves this version.
            let Some(published) = self.fetch_pom(base, id, version).await? else {
                continue;
            };
            let (versions, last_updated) = self.fetch_versions(base, id).await?.unwrap_or_default();
            // The first listed version is the oldest the repository reports;
            // any later one only makes the package look newer (conservative).
            let created = match versions.first() {
                Some(first) if first == version => published.clone(),
                Some(first) if safe_version_segment(first) => {
                    self.fetch_pom(base, id, first).await?.flatten()
                }
                _ => None,
            };
            return Ok(Some(super::PackageMetadata {
                created,
                latest_version_date: published.or(last_updated),
                ..Default::default()
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
#[path = "gradle_plugins_tests.rs"]
mod tests;
