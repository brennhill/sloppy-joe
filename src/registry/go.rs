use anyhow::Result;
use async_trait::async_trait;

/// Encode a Go module path for use with proxy.golang.org.
/// Upper-case letters are encoded as `!` followed by the lower-case letter,
/// per the Go module proxy protocol.
fn encode_module_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for ch in path.chars() {
        if ch.is_ascii_uppercase() {
            encoded.push('!');
            encoded.push(ch.to_ascii_lowercase());
        } else {
            encoded.push(ch);
        }
    }
    encoded
}

pub struct GoRegistry {
    client: reqwest::Client,
}

impl GoRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }
}

impl Default for GoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::Registry for GoRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let encoded = encode_module_path(package_name);
        let url = format!("https://proxy.golang.org/{}/@latest", encoded);
        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
            return Ok(false);
        }
        if !status.is_success() {
            anyhow::bail!(
                "Go package lookup for '{}' returned HTTP {}",
                package_name,
                status
            );
        }
        Ok(true)
    }

    fn ecosystem(&self) -> &str {
        "go"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_module_path_lowercase() {
        assert_eq!(
            encode_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
    }

    #[test]
    fn encode_module_path_uppercase() {
        assert_eq!(
            encode_module_path("github.com/Azure/azure-sdk-for-go"),
            "github.com/!azure/azure-sdk-for-go"
        );
    }

    #[test]
    fn encode_module_path_mixed() {
        assert_eq!(
            encode_module_path("github.com/Shopify/sarama"),
            "github.com/!shopify/sarama"
        );
    }

    #[test]
    fn go_registry_url_uses_proxy() {
        // Verify the URL format is correct by constructing it the same way the exists() method does
        let encoded = encode_module_path("github.com/gin-gonic/gin");
        let url = format!("https://proxy.golang.org/{}/@latest", encoded);
        assert_eq!(url, "https://proxy.golang.org/github.com/gin-gonic/gin/@latest");
    }
}
