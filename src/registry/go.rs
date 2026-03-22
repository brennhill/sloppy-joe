use anyhow::Result;
use async_trait::async_trait;

/// Encode uppercase letters for the Go module proxy (uppercase → `!` + lowercase).
fn encode_module_path(path: &str) -> String {
    path.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                format!("!{}", c.to_ascii_lowercase())
            } else {
                c.to_string()
            }
        })
        .collect()
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
        let encoded = encode_module_path(package_name);
        let url = format!("https://pkg.go.dev/{}", encoded);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "Go package lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
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
    fn encode_module_path_lowercases_with_bang() {
        assert_eq!(
            encode_module_path("GitHub.com/Foo"),
            "!git!hub.com/!foo"
        );
    }

    #[test]
    fn encode_module_path_no_uppercase() {
        assert_eq!(
            encode_module_path("github.com/foo"),
            "github.com/foo"
        );
    }

    #[test]
    fn encode_module_path_all_uppercase() {
        assert_eq!(encode_module_path("ABC"), "!a!b!c");
    }
}
