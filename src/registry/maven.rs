use anyhow::Result;
use async_trait::async_trait;

super::registry_struct!(MavenRegistry);

fn search_url(group: &str, artifact: &str, version: Option<&str>) -> String {
    let mut url = reqwest::Url::parse("https://search.maven.org/solrsearch/select")
        .expect("static Maven URL should parse");
    url.query_pairs_mut()
        .append_pair("q", &search_query(group, artifact, version))
        .append_pair("rows", "1")
        .append_pair("wt", "json");
    url.into()
}

fn search_query(group: &str, artifact: &str, version: Option<&str>) -> String {
    let group = escape_solr_term(group);
    let artifact = escape_solr_term(artifact);
    match version {
        Some(version) => format!(
            r#"g:"{}"+AND+a:"{}"+AND+v:"{}""#,
            group,
            artifact,
            escape_solr_term(version)
        ),
        None => format!(r#"g:"{}"+AND+a:"{}""#, group, artifact),
    }
}

fn escape_solr_term(term: &str) -> String {
    term.chars()
        .flat_map(|ch| match ch {
            '\\' | '"' => ['\\', ch].into_iter().collect::<Vec<_>>(),
            _ => [ch].into_iter().collect::<Vec<_>>(),
        })
        .collect()
}

#[async_trait]
impl super::RegistryExistence for MavenRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.validate_name(package_name)?;
        let parts: Vec<&str> = package_name.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Ok(false);
        }
        let (group, artifact) = (parts[0], parts[1]);
        // Use quoted values in the Solr query for exact matching
        let url = search_url(group, artifact, None);
        let resp = super::retry_get(&self.client, &url).await?;
        if !super::check_existence_status(resp.status(), "Maven", package_name)? {
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

#[async_trait]
impl super::RegistryMetadata for MavenRegistry {
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
        let resp = super::retry_get(&self.client, &url).await?;
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

        // timestamp is epoch millis — use shared converter (handles negative values)
        let latest_version_date = doc["timestamp"]
            .as_i64()
            .and_then(crate::cache::epoch_millis_to_iso8601);

        Ok(Some(super::PackageMetadata {
            created: None, // Maven search API doesn't easily expose first publish date
            latest_version_date,
            downloads: None,
            has_install_scripts: false,
            dependency_count: None,
            previous_dependency_count: None,
            current_publisher: None,
            previous_publisher: None,
            repository_url: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_url_includes_exact_version_when_requested() {
        let url = search_url("com.example", "demo", Some("1.2.3"));
        let parsed = reqwest::Url::parse(&url).unwrap();
        let query = parsed
            .query_pairs()
            .find(|(key, _)| key == "q")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        assert_eq!(query, r#"g:"com.example"+AND+a:"demo"+AND+v:"1.2.3""#);
    }

    #[test]
    fn search_query_escapes_embedded_quotes_and_backslashes() {
        let query = search_query(
            r#"com.example\"group"#,
            r#"demo"artifact"#,
            Some(r#"1.2\"3"#),
        );
        assert_eq!(
            query,
            r#"g:"com.example\\\"group"+AND+a:"demo\"artifact"+AND+v:"1.2\\\"3""#
        );
    }
}
