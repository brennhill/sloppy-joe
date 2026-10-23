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

const CENTRAL_BASE: &str = "https://repo1.maven.org/maven2";

/// Statuses that mean the search API cannot answer (as opposed to answering "not found").
fn search_unavailable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn central_segment_ok(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

fn central_artifact_url(base: &str, group: &str, artifact: &str) -> Result<String> {
    let group_path = group.replace('.', "/");
    if !group.split('.').all(central_segment_ok) || !central_segment_ok(artifact) {
        anyhow::bail!("invalid Maven coordinates for a Central lookup: '{group}:{artifact}'");
    }
    Ok(format!("{base}/{group_path}/{artifact}"))
}

/// Existence straight from Maven Central's repository layout.
async fn central_exists(
    client: &reqwest::Client,
    base: &str,
    group: &str,
    artifact: &str,
) -> Result<bool> {
    let url = format!(
        "{}/maven-metadata.xml",
        central_artifact_url(base, group, artifact)?
    );
    let resp = super::retry_get(client, &url).await?;
    super::check_existence_status(
        resp.status(),
        "Maven Central",
        &format!("{group}:{artifact}"),
    )
}

/// Publication date of a version from the `Last-Modified` header of its POM on Central.
async fn central_metadata(
    client: &reqwest::Client,
    base: &str,
    group: &str,
    artifact: &str,
    version: Option<&str>,
) -> Result<Option<super::PackageMetadata>> {
    let name = format!("{group}:{artifact}");
    let artifact_url = central_artifact_url(base, group, artifact)?;
    let version = match version {
        Some(version) => version.to_string(),
        None => {
            let resp =
                super::retry_get(client, &format!("{artifact_url}/maven-metadata.xml")).await?;
            if super::check_metadata_status(resp.status(), "Maven Central", &name)?.is_none() {
                return Ok(None);
            }
            let body = resp.text().await?;
            let Some(version) = xml_tag(&body, "release").or_else(|| xml_tag(&body, "latest"))
            else {
                return Ok(None);
            };
            version
        }
    };
    if !central_segment_ok(&version) {
        anyhow::bail!("invalid Maven version for a Central lookup: '{version}'");
    }
    let pom_url = format!("{artifact_url}/{version}/{artifact}-{version}.pom");
    let resp = client.head(&pom_url).send().await?;
    if super::check_metadata_status(resp.status(), "Maven Central", &name)?.is_none() {
        return Ok(None);
    }
    let latest_version_date = resp
        .headers()
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .and_then(http_date_to_epoch_millis)
        .and_then(crate::cache::epoch_millis_to_iso8601);
    Ok(Some(super::PackageMetadata {
        latest_version_date,
        ..Default::default()
    }))
}

fn xml_tag(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = body.find(&open)? + open.len();
    let end = start + body[start..].find(&format!("</{tag}>"))?;
    let value = body[start..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// `Sat, 13 Feb 2021 16:31:54 GMT` to epoch milliseconds.
fn http_date_to_epoch_millis(value: &str) -> Option<i64> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    let day: i64 = day.parse().ok()?;
    let year: i64 = year.parse().ok()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|name| name == month)? as i64
        + 1;
    let mut clock = time.split(':').map(|part| part.parse::<i64>().ok());
    let (hour, minute, second) = (clock.next()??, clock.next()??, clock.next()??);
    // Days since 1970-01-01 (Howard Hinnant's civil-from-days inverse).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + hour) * 3600 + minute * 60 + second) * 1000)
}

fn search_query(group: &str, artifact: &str, version: Option<&str>) -> String {
    let group = escape_solr_term(group);
    let artifact = escape_solr_term(artifact);
    match version {
        Some(version) => format!(
            r#"g:"{}" AND a:"{}" AND v:"{}""#,
            group,
            artifact,
            escape_solr_term(version)
        ),
        None => format!(r#"g:"{}" AND a:"{}""#, group, artifact),
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
        let resp = match super::retry_get(&self.client, &url).await {
            Ok(resp) if !search_unavailable(resp.status()) => resp,
            // The search API is down or refusing us: ask Central itself.
            _ => return central_exists(&self.client, CENTRAL_BASE, group, artifact).await,
        };
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
        let resp = match super::retry_get(&self.client, &url).await {
            Ok(resp) if !search_unavailable(resp.status()) => resp,
            _ => {
                return central_metadata(&self.client, CENTRAL_BASE, group, artifact, version)
                    .await;
            }
        };
        if super::check_metadata_status(resp.status(), "Maven", package_name)?.is_none() {
            return Ok(None);
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
            latest_version_date,
            ..Default::default()
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
        assert_eq!(query, r#"g:"com.example" AND a:"demo" AND v:"1.2.3""#);
    }

    #[test]
    fn search_url_never_encodes_solr_operators_as_literal_plus() {
        // Regression: a literal '+' in the query is serialized as %2B, which
        // Solr rejects with HTTP 400 for every lookup.
        let url = search_url("com.example", "demo", None);
        assert!(
            !url.contains("%2B"),
            "query must not contain encoded '+': {url}"
        );
        let parsed = reqwest::Url::parse(&url).unwrap();
        let query = parsed
            .query_pairs()
            .find(|(key, _)| key == "q")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        assert_eq!(query, r#"g:"com.example" AND a:"demo""#);
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
            r#"g:"com.example\\\"group" AND a:"demo\"artifact" AND v:"1.2\\\"3""#
        );
    }

    #[test]
    fn http_dates_convert_to_iso8601() {
        let millis = http_date_to_epoch_millis("Sat, 13 Feb 2021 16:31:54 GMT").unwrap();
        assert_eq!(
            crate::cache::epoch_millis_to_iso8601(millis).as_deref(),
            Some("2021-02-13T16:31:00Z")
        );
        assert!(http_date_to_epoch_millis("not a date").is_none());
    }

    #[test]
    fn central_urls_reject_traversal_and_odd_characters() {
        assert_eq!(
            central_artifact_url("https://c", "org.apache.maven.plugins", "maven-jar-plugin")
                .unwrap(),
            "https://c/org/apache/maven/plugins/maven-jar-plugin"
        );
        for (group, artifact) in [("a..b", "x"), ("a.b", ".."), ("a/b", "x"), ("a.b", "x?y")] {
            assert!(central_artifact_url("https://c", group, artifact).is_err());
        }
    }

    async fn serve_central(routes: Vec<(&'static str, &'static str)>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let line = request.lines().next().unwrap_or_default().to_string();
                let reply = routes
                    .iter()
                    .find(|(path, _)| line.contains(path))
                    .map(|(_, reply)| reply.to_string())
                    .unwrap_or_else(|| {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .into()
                    });
                let _ = stream.write_all(reply.as_bytes()).await;
            }
        });
        origin
    }

    #[tokio::test]
    async fn central_fallback_answers_existence_and_publication_date() {
        let origin = serve_central(vec![
            (
                "/org/example/demo/maven-metadata.xml",
                "HTTP/1.1 200 OK\r\nContent-Length: 70\r\nConnection: close\r\n\r\n<metadata><versioning><release>1.2.3</release></versioning></metadata>",
            ),
            (
                "/org/example/demo/1.2.3/demo-1.2.3.pom",
                "HTTP/1.1 200 OK\r\nLast-Modified: Sat, 13 Feb 2021 16:31:54 GMT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        ])
        .await;
        let client = crate::registry::http_client();
        assert!(
            central_exists(&client, &origin, "org.example", "demo")
                .await
                .unwrap()
        );
        assert!(
            !central_exists(&client, &origin, "org.example", "ghost")
                .await
                .unwrap()
        );
        let metadata = central_metadata(&client, &origin, "org.example", "demo", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            metadata.latest_version_date.as_deref(),
            Some("2021-02-13T16:31:00Z")
        );
    }
}
