use anyhow::Result;
use async_trait::async_trait;

pub struct MavenRegistry {
    client: reqwest::Client,
}

impl MavenRegistry {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("sloppy-joe (https://github.com/brennhill/sloppy-joe)")
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

#[async_trait]
impl super::Registry for MavenRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        let parts: Vec<&str> = package_name.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Ok(false);
        }
        let (group, artifact) = (parts[0], parts[1]);
        // Use quoted values in the Solr query for exact matching
        let url = format!(
            "https://search.maven.org/solrsearch/select?q=g:%22{}%22+AND+a:%22{}%22&rows=1&wt=json",
            group, artifact
        );
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(false);
        }
        let body: serde_json::Value = resp.json().await?;
        let found = body["response"]["numFound"].as_i64().unwrap_or(0);
        Ok(found > 0)
    }

    fn ecosystem(&self) -> &str {
        "jvm"
    }
}
