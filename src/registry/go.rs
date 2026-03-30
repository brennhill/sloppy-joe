use super::RegistryExistence;
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

super::registry_struct!(GoRegistry);

#[async_trait]
impl super::RegistryExistence for GoRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let encoded = encode_module_path(package_name);
        let url = format!("https://proxy.golang.org/{}/@latest", encoded);
        let resp = super::retry_get(&self.client, &url).await?;
        super::check_existence_status(resp.status(), "Go proxy", package_name)
    }

    fn ecosystem(&self) -> &str {
        "go"
    }
}

#[async_trait]
impl super::RegistryMetadata for GoRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        self.validate_name(package_name)?;
        let encoded = encode_module_path(package_name);

        // Fetch version-specific .info (has Time field) or @latest
        let url = if let Some(ver) = version {
            let ver = super::strip_version_prefix(ver);
            format!("https://proxy.golang.org/{}/@v/{}.info", encoded, ver)
        } else {
            format!("https://proxy.golang.org/{}/@latest", encoded)
        };

        let resp = super::retry_get(&self.client, &url).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND
            || resp.status() == reqwest::StatusCode::GONE
        {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "Go proxy metadata for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }

        let body: serde_json::Value = resp.json().await?;

        // .info returns: {"Version":"v1.9.1","Time":"2023-06-07T07:40:19Z"}
        let version_date = body["Time"].as_str().map(|s| s.to_string());

        Ok(Some(super::PackageMetadata {
            created: version_date.clone(), // Go proxy doesn't expose first-publish separately
            latest_version_date: version_date,
            downloads: None,
            has_install_scripts: false,
            dependency_count: None,
            previous_dependency_count: None,
            current_publisher: None,
            previous_publisher: None,
            repository_url: Some(format!("https://{}", package_name)),
            version_history: Vec::new(),
        }))
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
        let encoded = encode_module_path("github.com/gin-gonic/gin");
        let url = format!("https://proxy.golang.org/{}/@latest", encoded);
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/gin-gonic/gin/@latest"
        );
    }
}
