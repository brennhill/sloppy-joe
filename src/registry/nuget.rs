use super::RegistryExistence;
use anyhow::Result;
use async_trait::async_trait;

/// SemVer 2.0.0 registration hive (gzip bodies). The `registration5-semver1`
/// hive omits SemVer 2.0.0-only packages and versions.
pub(crate) const NUGET_REGISTRATION_BASE: &str =
    "https://api.nuget.org/v3/registration5-gz-semver2";
const NUGET_FLAT_CONTAINER_BASE: &str = "https://api.nuget.org/v3-flatcontainer";

/// Hard limits on registration documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegistrationLimits {
    pub max_compressed_bytes: u64,
    pub max_decompressed_bytes: u64,
    pub max_pages: usize,
}

impl Default for RegistrationLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: 16 * 1024 * 1024,
            max_decompressed_bytes: 64 * 1024 * 1024,
            max_pages: 128,
        }
    }
}

pub struct NugetRegistry {
    client: reqwest::Client,
    registration_client: reqwest::Client,
    registration_base: String,
    flat_container_base: String,
    limits: RegistrationLimits,
}

impl NugetRegistry {
    pub fn new() -> Self {
        Self::with_client(super::http_client())
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            registration_client: registration_http_client(),
            registration_base: NUGET_REGISTRATION_BASE.to_string(),
            flat_container_base: NUGET_FLAT_CONTAINER_BASE.to_string(),
            limits: RegistrationLimits::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(origin: &str, limits: RegistrationLimits) -> Self {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self {
            client: client.clone(),
            registration_client: client,
            registration_base: format!("{origin}/v3/registration5-gz-semver2"),
            flat_container_base: format!("{origin}/v3-flatcontainer"),
            limits,
        }
    }

    pub(crate) fn registration_index_url(&self, package_name: &str) -> String {
        format!(
            "{}/{}/index.json",
            self.registration_base,
            package_name.to_lowercase()
        )
    }
}

impl Default for NugetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::RegistryExistence for NugetRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let lower = package_name.to_lowercase();
        let url = format!("{}/{}/index.json", self.flat_container_base, lower);
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "NuGet", package_name)
    }

    fn ecosystem(&self) -> &str {
        "dotnet"
    }
}

/// NuGet's `published` value for unlisted versions; not a real publish date.
const UNLISTED_PUBLISHED_PREFIX: &str = "1900-01-01";

/// Registration client: never follows redirects (a redirect could leave the
/// NuGet host), HTTPS only.
fn registration_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("sloppy-joe (https://github.com/brennhill/sloppy-joe)")
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .expect("failed to build HTTP client")
}

/// One version entry from a registration page.
struct RegistrationEntry {
    version: String,
    published: Option<String>,
}

impl NugetRegistry {
    /// Fetch one registration document. `Ok(None)` only for 404/410; every
    /// other failure (redirect, HTTP error, size limit, bad gzip, bad JSON)
    /// is an error so the caller fails closed.
    async fn fetch_document(
        &self,
        url: &str,
        package_name: &str,
    ) -> Result<Option<serde_json::Value>> {
        let mut resp = super::retry_get(&self.registration_client, url).await?;
        let status = resp.status();
        if status.is_redirection() {
            anyhow::bail!(
                "NuGet registration request for '{package_name}' was redirected (HTTP {}); redirects are not followed",
                status.as_u16()
            );
        }
        if super::check_metadata_status(status, "NuGet", package_name)?.is_none() {
            return Ok(None);
        }
        let gzip_encoded = resp
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("gzip"));
        let max = self.limits.max_compressed_bytes;
        if resp.content_length().is_some_and(|len| len > max) {
            anyhow::bail!(
                "NuGet registration document for '{package_name}' is larger than {max} bytes"
            );
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() as u64 + chunk.len() as u64 > max {
                anyhow::bail!(
                    "NuGet registration document for '{package_name}' is larger than {max} bytes"
                );
            }
            body.extend_from_slice(&chunk);
        }
        let json =
            decode_body(&body, gzip_encoded, self.limits.max_decompressed_bytes).map_err(|e| {
                anyhow::anyhow!("NuGet registration document for '{package_name}': {e}")
            })?;
        let value: serde_json::Value = serde_json::from_slice(&json).map_err(|e| {
            anyhow::anyhow!(
                "NuGet registration document for '{package_name}' is not valid JSON: {e}"
            )
        })?;
        Ok(Some(value))
    }

    /// Accept a registration page URL only if it stays on the registration
    /// host (same scheme, host and port), has no credentials, query or
    /// fragment, and lies under this package's registration directory.
    fn validate_page_url(&self, raw: &str, package_name: &str) -> Result<reqwest::Url> {
        let base = reqwest::Url::parse(&self.registration_base)?;
        let url = reqwest::Url::parse(raw)
            .map_err(|e| anyhow::anyhow!("NuGet registration page URL is not a valid URL: {e}"))?;
        if url.scheme() != base.scheme()
            || url.host_str() != base.host_str()
            || url.port_or_known_default() != base.port_or_known_default()
        {
            anyhow::bail!(
                "NuGet registration page for '{package_name}' is not on the registry host {}",
                base.host_str().unwrap_or("")
            );
        }
        if !url.username().is_empty() || url.password().is_some() {
            anyhow::bail!("NuGet registration page URL for '{package_name}' embeds credentials");
        }
        if url.query().is_some() || url.fragment().is_some() {
            anyhow::bail!(
                "NuGet registration page URL for '{package_name}' has a query or fragment"
            );
        }
        let prefix = format!(
            "{}/{}/",
            base.path().trim_end_matches('/'),
            package_name.to_lowercase()
        );
        if !url.path().starts_with(&prefix) || url.path().contains("/../") {
            anyhow::bail!(
                "NuGet registration page URL for '{package_name}' is outside the package's registration directory"
            );
        }
        Ok(url)
    }

    /// All version entries of a package, following paged indexes.
    async fn registration_entries(
        &self,
        package_name: &str,
    ) -> Result<Option<Vec<RegistrationEntry>>> {
        let url = self.registration_index_url(package_name);
        let Some(index) = self.fetch_document(&url, package_name).await? else {
            return Ok(None);
        };
        let pages = index
            .get("items")
            .and_then(|items| items.as_array())
            .ok_or_else(|| malformed(package_name, "the index has no items array"))?;

        // Pages without inline items are fetched; validate them all first so
        // nothing is requested when any page URL is unacceptable.
        let mut remote = Vec::new();
        for (index, page) in pages.iter().enumerate() {
            if page.get("items").is_some() {
                continue;
            }
            let raw = page
                .get("@id")
                .and_then(|id| id.as_str())
                .ok_or_else(|| malformed(package_name, "a page has neither items nor an @id"))?;
            remote.push((index, self.validate_page_url(raw, package_name)?));
        }
        if remote.len() > self.limits.max_pages {
            anyhow::bail!(
                "NuGet registration index for '{package_name}' references {} pages (limit {})",
                remote.len(),
                self.limits.max_pages
            );
        }

        let mut fetched: std::collections::HashMap<usize, serde_json::Value> =
            std::collections::HashMap::new();
        for (index, url) in remote {
            let page = self
                .fetch_document(url.as_str(), package_name)
                .await?
                .ok_or_else(|| malformed(package_name, "a registration page is missing"))?;
            fetched.insert(index, page);
        }

        let mut entries = Vec::new();
        for (index, page) in pages.iter().enumerate() {
            let page = fetched.get(&index).unwrap_or(page);
            let items = page
                .get("items")
                .and_then(|items| items.as_array())
                .ok_or_else(|| malformed(package_name, "a page has no items array"))?;
            for item in items {
                let catalog = item
                    .get("catalogEntry")
                    .filter(|catalog| catalog.is_object())
                    .ok_or_else(|| malformed(package_name, "an entry has no catalogEntry"))?;
                let version = catalog
                    .get("version")
                    .and_then(|version| version.as_str())
                    .filter(|version| !version.trim().is_empty())
                    .ok_or_else(|| malformed(package_name, "an entry has no version"))?;
                let published = catalog
                    .get("published")
                    .and_then(|published| published.as_str())
                    .filter(|published| !published.starts_with(UNLISTED_PUBLISHED_PREFIX))
                    .map(str::to_string);
                entries.push(RegistrationEntry {
                    version: version.trim().to_string(),
                    published,
                });
            }
        }
        Ok(Some(entries))
    }
}

fn malformed(package_name: &str, detail: &str) -> anyhow::Error {
    anyhow::anyhow!("NuGet registration data for '{package_name}' is malformed: {detail}")
}

/// Decompress a gzip body (by header or magic bytes) under a hard cap;
/// plain bodies pass through. A gzip header on a non-gzip body is an error.
fn decode_body(body: &[u8], gzip_encoded: bool, max_decompressed: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let has_magic = body.starts_with(&[0x1f, 0x8b]);
    if !has_magic {
        if gzip_encoded {
            anyhow::bail!("Content-Encoding is gzip but the body is not gzip data");
        }
        return Ok(body.to_vec());
    }
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(body)
        .take(max_decompressed + 1)
        .read_to_end(&mut out)
        .map_err(|e| anyhow::anyhow!("gzip data is invalid: {e}"))?;
    if out.len() as u64 > max_decompressed {
        anyhow::bail!("decompresses to more than {max_decompressed} bytes");
    }
    Ok(out)
}

/// NuGet versions compare case-insensitively and ignore build metadata.
fn same_version(a: &str, b: &str) -> bool {
    let strip = |v: &str| v.split('+').next().unwrap_or(v).trim().to_ascii_lowercase();
    strip(a) == strip(b)
}

#[async_trait]
impl super::RegistryMetadata for NugetRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        self.validate_name(package_name)?;
        let Some(entries) = self.registration_entries(package_name).await? else {
            return Ok(None);
        };

        let created = entries
            .iter()
            .filter_map(|entry| entry.published.as_deref())
            .min()
            .map(str::to_string);
        let latest_version_date = match version.map(super::strip_version_prefix) {
            Some(target) => entries
                .iter()
                .rev()
                .find(|entry| same_version(&entry.version, &target))
                .and_then(|entry| entry.published.clone()),
            // Pages and entries are in ascending version order.
            None => entries.last().and_then(|entry| entry.published.clone()),
        };

        Ok(Some(super::PackageMetadata {
            created,
            latest_version_date,
            ..Default::default()
        }))
    }
}

#[cfg(test)]
#[path = "nuget_tests.rs"]
mod tests;
