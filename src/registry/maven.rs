use anyhow::Result;
use async_trait::async_trait;

pub struct MavenRegistry {
    client: reqwest::Client,
}

impl MavenRegistry {
    pub fn new() -> Self {
        Self {
            client: super::http_client(),
        }
    }
}

impl Default for MavenRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn search_url(group: &str, artifact: &str, version: Option<&str>) -> String {
    match version {
        Some(version) => format!(
            "https://search.maven.org/solrsearch/select?q=g:%22{}%22+AND+a:%22{}%22+AND+v:%22{}%22&rows=1&wt=json",
            group, artifact, version
        ),
        None => format!(
            "https://search.maven.org/solrsearch/select?q=g:%22{}%22+AND+a:%22{}%22&rows=1&wt=json",
            group, artifact
        ),
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
        let url = search_url(group, artifact, None);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "Maven lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        let body: serde_json::Value = resp.json().await?;
        let found = body["response"]["numFound"].as_i64().unwrap_or(0);
        Ok(found > 0)
    }

    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<super::PackageMetadata>> {
        let parts: Vec<&str> = package_name.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Ok(None);
        }
        let (group, artifact) = (parts[0], parts[1]);
        let url = search_url(group, artifact, version);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "Maven metadata lookup for '{}' returned HTTP {}",
                package_name,
                resp.status()
            );
        }
        let body: serde_json::Value = resp.json().await?;
        let doc = &body["response"]["docs"][0];
        if doc.is_null() {
            return Ok(None);
        }

        // timestamp is epoch millis
        let latest_version_date = doc["timestamp"].as_i64().map(|ts| {
            let secs = ts / 1000;
            // Convert epoch seconds to rough ISO 8601
            let days = secs / 86400;
            let remaining = secs % 86400;
            let hour = remaining / 3600;
            let min = (remaining % 3600) / 60;
            // Rough date from epoch days
            let mut year = 1970i64;
            let mut rem_days = days;
            loop {
                let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                    366
                } else {
                    365
                };
                if rem_days < days_in_year {
                    break;
                }
                rem_days -= days_in_year;
                year += 1;
            }
            let days_per_month = [
                31,
                if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                    29
                } else {
                    28
                },
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ];
            let mut month = 1i64;
            for &dm in &days_per_month {
                if rem_days < dm {
                    break;
                }
                rem_days -= dm;
                month += 1;
            }
            let day = rem_days + 1;
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:00Z",
                year, month, day, hour, min
            )
        });

        Ok(Some(super::PackageMetadata {
            created: None, // Maven search API doesn't easily expose first publish date
            latest_version_date,
            downloads: None,
            has_install_scripts: false,
            dependency_count: None,
            previous_dependency_count: None,
            current_publisher: None,
            previous_publisher: None,
        }))
    }

    fn ecosystem(&self) -> &str {
        "jvm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_url_includes_exact_version_when_requested() {
        let url = search_url("com.example", "demo", Some("1.2.3"));
        assert!(url.contains("g:%22com.example%22"));
        assert!(url.contains("a:%22demo%22"));
        assert!(url.contains("v:%221.2.3%22"));
    }
}
