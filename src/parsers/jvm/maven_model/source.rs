use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Coordinate {
    pub group: String,
    pub artifact: String,
    pub version: String,
}

/// Where parent and imported POMs come from.
#[async_trait]
pub(crate) trait PomSource: Send + Sync {
    async fn fetch(&self, coordinate: &Coordinate) -> Result<String>;
}

/// Maven Central's repository layout.
pub(crate) struct CentralPomSource {
    pub(crate) client: reqwest::Client,
    pub(crate) base: String,
}

impl CentralPomSource {
    pub(crate) fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base: crate::config::MAVEN_CENTRAL_URL.to_string(),
        }
    }
}

pub(crate) fn plain_segment(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

#[async_trait]
impl PomSource for CentralPomSource {
    async fn fetch(&self, coordinate: &Coordinate) -> Result<String> {
        let Coordinate {
            group,
            artifact,
            version,
        } = coordinate;
        if !plain_segment(group) || !plain_segment(artifact) || !plain_segment(version) {
            bail!("invalid Maven coordinate {group}:{artifact}:{version}");
        }
        let url = format!(
            "{}{}/{artifact}/{version}/{artifact}-{version}.pom",
            self.base,
            group.replace('.', "/")
        );
        let mut resp = crate::http::retry_get(&self.client, &url).await?;
        if !resp.status().is_success() {
            bail!(
                "POM {group}:{artifact}:{version} could not be fetched from Maven Central (HTTP {}); its managed versions cannot be verified",
                resp.status()
            );
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_POM_BYTES {
                bail!("POM {group}:{artifact}:{version} exceeds {MAX_POM_BYTES} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}
