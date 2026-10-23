//! Plugin marker lookups against Maven-layout plugin repositories, served by
//! a local 127.0.0.1 mock. No test talks to the real Plugin Portal.

use super::*;
use crate::Dependency;
use crate::registry::{RegistryExistence, RegistryMetadata};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Route {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
}

fn ok(body: &str, headers: Vec<(&'static str, &'static str)>) -> Route {
    Route {
        status: 200,
        headers,
        body: body.to_string(),
    }
}

struct MockServer {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockServer {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

async fn mock_server(routes: HashMap<String, Route>) -> MockServer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                seen.lock().unwrap().push(path.clone());
                let route = routes.get(&path).cloned().unwrap_or(Route {
                    status: 404,
                    headers: vec![],
                    body: String::new(),
                });
                let mut head = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    route.status,
                    route.body.len()
                );
                for (k, v) in &route.headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(route.body.as_bytes()).await;
            });
        }
    });
    MockServer { origin, requests }
}

const MARKER: &str = "com.example.demo:com.example.demo.gradle.plugin";
const BASE: &str = "/m2/com/example/demo/com.example.demo.gradle.plugin";

fn requested(version: &str) -> Vec<Dependency> {
    vec![Dependency {
        name: MARKER.to_string(),
        version: Some(version.to_string()),
        ecosystem: crate::Ecosystem::Jvm,
        actual_name: None,
    }]
}

fn metadata_xml(versions: &[&str], last_updated: &str) -> String {
    let versions: String = versions
        .iter()
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    format!(
        "<?xml version='1.0' encoding='US-ASCII'?>\n<metadata><groupId>com.example.demo</groupId><artifactId>com.example.demo.gradle.plugin</artifactId><versioning><versions>{versions}</versions><lastUpdated>{last_updated}</lastUpdated></versioning></metadata>"
    )
}

fn published_routes() -> HashMap<String, Route> {
    HashMap::from([
        (
            format!("{BASE}/maven-metadata.xml"),
            ok(&metadata_xml(&["0.9.0", "1.0.0"], "20240101000000"), vec![]),
        ),
        (
            format!("{BASE}/1.0.0/com.example.demo.gradle.plugin-1.0.0.pom"),
            ok(
                "<project/>",
                vec![("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")],
            ),
        ),
        (
            format!("{BASE}/0.9.0/com.example.demo.gradle.plugin-0.9.0.pom"),
            ok(
                "<project/>",
                vec![("Last-Modified", "Fri, 01 Dec 2023 12:30:00 GMT")],
            ),
        ),
    ])
}

fn registry(repos: &[&MockServer], version: &str) -> GradlePluginRegistry {
    GradlePluginRegistry::with_base_urls(
        reqwest::Client::new(),
        repos
            .iter()
            .map(|server| format!("{}/m2/", server.origin))
            .collect(),
        &requested(version),
    )
}

#[tokio::test]
async fn published_plugin_version_exists_with_publication_dates() {
    let server = mock_server(published_routes()).await;
    let registry = registry(&[&server], "1.0.0");
    assert!(registry.exists(MARKER).await.unwrap());
    let metadata = registry
        .metadata(MARKER, Some("1.0.0"))
        .await
        .unwrap()
        .expect("published version has metadata");
    assert_eq!(
        metadata.latest_version_date.as_deref(),
        Some("2024-01-01T00:00:00Z")
    );
    assert_eq!(metadata.created.as_deref(), Some("2023-12-01T12:30:00Z"));
}

#[tokio::test]
async fn nonexistent_plugin_does_not_exist() {
    let server = mock_server(HashMap::new()).await;
    let registry = registry(&[&server], "1.0.0");
    assert!(!registry.exists(MARKER).await.unwrap());
    assert!(
        registry
            .metadata(MARKER, Some("1.0.0"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unpublished_version_of_an_existing_plugin_does_not_exist() {
    let server = mock_server(published_routes()).await;
    let registry = registry(&[&server], "9.9.9");
    assert!(
        !registry.exists(MARKER).await.unwrap(),
        "the pinned version must be published, not just the plugin id"
    );
    assert!(
        registry
            .metadata(MARKER, Some("9.9.9"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn repositories_are_consulted_in_declared_order() {
    let empty = mock_server(HashMap::new()).await;
    let portal = mock_server(published_routes()).await;
    let registry = registry(&[&empty, &portal], "1.0.0");
    assert!(registry.exists(MARKER).await.unwrap());
    let metadata = registry.metadata(MARKER, Some("1.0.0")).await.unwrap();
    assert!(metadata.is_some());
    assert!(
        !empty.requests().is_empty(),
        "first repository is tried first"
    );

    // When the first repository serves the version, later ones are not used.
    let first = mock_server(published_routes()).await;
    let second = mock_server(published_routes()).await;
    let registry = registry_for(&first, &second);
    assert!(registry.exists(MARKER).await.unwrap());
    assert!(second.requests().is_empty(), "{:?}", second.requests());
}

fn registry_for(first: &MockServer, second: &MockServer) -> GradlePluginRegistry {
    registry(&[first, second], "1.0.0")
}

#[tokio::test]
async fn repository_errors_fail_closed() {
    let routes = HashMap::from([(
        format!("{BASE}/1.0.0/com.example.demo.gradle.plugin-1.0.0.pom"),
        Route {
            status: 500,
            headers: vec![],
            body: String::new(),
        },
    )]);
    let server = mock_server(routes).await;
    let registry = registry(&[&server], "1.0.0");
    assert!(registry.exists(MARKER).await.is_err());
    assert!(registry.metadata(MARKER, Some("1.0.0")).await.is_err());
}

#[tokio::test]
async fn missing_last_modified_falls_back_to_the_newer_last_updated_date() {
    let mut routes = published_routes();
    routes.insert(
        format!("{BASE}/1.0.0/com.example.demo.gradle.plugin-1.0.0.pom"),
        ok("<project/>", vec![]),
    );
    let server = mock_server(routes).await;
    let registry = registry(&[&server], "1.0.0");
    let metadata = registry
        .metadata(MARKER, Some("1.0.0"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        metadata.latest_version_date.as_deref(),
        Some("2024-01-01T00:00:00Z")
    );
}

#[tokio::test]
async fn non_marker_names_are_never_plugins() {
    let server = mock_server(published_routes()).await;
    let registry = registry(&[&server], "1.0.0");
    for name in [
        "com.google.guava:guava",
        "com.example.demo:com.example.other.gradle.plugin",
    ] {
        assert!(!registry.exists(name).await.unwrap(), "{name}");
        assert!(
            registry
                .metadata(name, Some("1.0.0"))
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(server.requests().is_empty(), "{:?}", server.requests());
}

#[tokio::test]
async fn unsafe_names_are_rejected_before_url_construction() {
    let server = mock_server(published_routes()).await;
    let registry = registry(&[&server], "1.0.0");
    for name in [
        "../evil:../evil.gradle.plugin",
        "a%2f:a%2f.gradle.plugin",
        "a?b:a?b.gradle.plugin",
    ] {
        assert!(registry.exists(name).await.is_err(), "{name}");
    }
    assert!(server.requests().is_empty(), "{:?}", server.requests());
}

#[tokio::test]
async fn unsafe_remote_versions_are_never_fetched() {
    let mut routes = published_routes();
    routes.insert(
        format!("{BASE}/maven-metadata.xml"),
        ok(
            &metadata_xml(&["../../x", "1.0.0"], "20240101000000"),
            vec![],
        ),
    );
    let server = mock_server(routes).await;
    let registry = registry(&[&server], "1.0.0");
    let metadata = registry
        .metadata(MARKER, Some("1.0.0"))
        .await
        .unwrap()
        .unwrap();
    assert!(metadata.created.is_none());
    assert!(
        server.requests().iter().all(|path| !path.contains("..")),
        "{:?}",
        server.requests()
    );
}

#[test]
fn only_known_public_plugin_repositories_get_a_client() {
    let deps = requested("1.0.0");
    assert!(
        GradlePluginRegistry::new(
            reqwest::Client::new(),
            &[
                PluginRepository::GradlePluginPortal,
                PluginRepository::MavenCentral
            ],
            &deps,
        )
        .is_ok()
    );
    assert!(
        GradlePluginRegistry::new(
            reqwest::Client::new(),
            &[PluginRepository::Custom(
                "https://plugins.corp.example/m2".into()
            )],
            &deps,
        )
        .is_err(),
        "custom repositories are never queried as if they were public"
    );
}

#[test]
fn http_dates_and_maven_timestamps_convert_to_iso8601() {
    assert_eq!(
        http_date_to_iso8601("Wed, 21 Oct 2026 09:43:01 GMT").as_deref(),
        Some("2026-10-21T09:43:01Z")
    );
    assert_eq!(http_date_to_iso8601("Wed, 31 Feb 2026 09:43:01 GMT"), None);
    assert_eq!(http_date_to_iso8601("garbage"), None);
    assert_eq!(
        maven_timestamp_to_iso8601("20261021094301").as_deref(),
        Some("2026-10-21T09:43:01Z")
    );
    assert_eq!(maven_timestamp_to_iso8601("2026102109430"), None);
}

fn marker_pom(dependencies: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example.demo</groupId><artifactId>com.example.demo.gradle.plugin</artifactId><version>1.0.0</version><packaging>pom</packaging><dependencies>{dependencies}</dependencies></project>"
    )
}

fn routes_with_pom(pom: &str) -> HashMap<String, Route> {
    HashMap::from([(
        format!("{BASE}/1.0.0/com.example.demo.gradle.plugin-1.0.0.pom"),
        ok(pom, vec![]),
    )])
}

#[tokio::test]
async fn marker_pom_names_the_implementation_artifacts() {
    let pom = marker_pom(
        "<dependency><groupId>com.example</groupId><artifactId>demo-gradle-plugin</artifactId><version>1.0.0</version></dependency><dependency><groupId>org.x</groupId><artifactId>helper</artifactId><version>2.1</version><scope>runtime</scope></dependency>",
    );
    let server = mock_server(routes_with_pom(&pom)).await;
    let artifacts = registry(&[&server], "1.0.0")
        .implementation_artifacts(MARKER, "1.0.0")
        .await
        .unwrap()
        .expect("marker is published");
    assert_eq!(
        artifacts,
        vec![
            (
                "com.example".to_string(),
                "demo-gradle-plugin".to_string(),
                "1.0.0".to_string()
            ),
            ("org.x".to_string(), "helper".to_string(), "2.1".to_string()),
        ]
    );
}

#[tokio::test]
async fn unresolvable_marker_dependency_versions_fail_closed() {
    for dependency in [
        "<dependency><groupId>com.example</groupId><artifactId>impl</artifactId><version>${impl.version}</version></dependency>",
        "<dependency><groupId>com.example</groupId><artifactId>impl</artifactId></dependency>",
        "<dependency><groupId>com.example</groupId><artifactId>impl</artifactId><version>[1.0,2.0)</version></dependency>",
    ] {
        let server = mock_server(routes_with_pom(&marker_pom(dependency))).await;
        let result = registry(&[&server], "1.0.0")
            .implementation_artifacts(MARKER, "1.0.0")
            .await;
        assert!(result.is_err(), "{dependency}");
    }
}

#[tokio::test]
async fn marker_missing_from_every_repository_has_no_artifacts() {
    let server = mock_server(HashMap::new()).await;
    let artifacts = registry(&[&server], "1.0.0")
        .implementation_artifacts(MARKER, "1.0.0")
        .await
        .unwrap();
    assert!(artifacts.is_none());
}

struct FakeOsv(Vec<&'static str>);

#[async_trait::async_trait]
impl crate::checks::malicious::OsvClient for FakeOsv {
    async fn query(
        &self,
        name: &str,
        ecosystem: &str,
        _version: Option<&str>,
    ) -> anyhow::Result<Vec<String>> {
        assert_eq!(ecosystem, "jvm");
        Ok(self
            .0
            .iter()
            .filter(|vulnerable| **vulnerable == name)
            .map(|_| "GHSA-test".to_string())
            .collect())
    }
}

#[tokio::test]
async fn vulnerable_implementation_artifact_is_reported() {
    let pom = marker_pom(
        "<dependency><groupId>com.example</groupId><artifactId>demo-gradle-plugin</artifactId><version>1.0.0</version></dependency>",
    );
    let server = mock_server(routes_with_pom(&pom)).await;
    let registry = registry(&[&server], "1.0.0");
    let issues = crate::gradle_plugin_scan::implementation_advisory_issues(
        &registry,
        &requested("1.0.0"),
        &FakeOsv(vec!["com.example:demo-gradle-plugin"]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(issues[0].package, "com.example:demo-gradle-plugin");
    assert_eq!(issues[0].check, "malicious/known-vulnerability");
}

#[tokio::test]
async fn clean_implementation_artifact_has_no_issues() {
    let pom = marker_pom(
        "<dependency><groupId>com.example</groupId><artifactId>demo-gradle-plugin</artifactId><version>1.0.0</version></dependency>",
    );
    let server = mock_server(routes_with_pom(&pom)).await;
    let registry = registry(&[&server], "1.0.0");
    let issues = crate::gradle_plugin_scan::implementation_advisory_issues(
        &registry,
        &requested("1.0.0"),
        &FakeOsv(vec![]),
        None,
    )
    .await
    .unwrap();
    assert!(issues.is_empty(), "{issues:?}");
}

#[tokio::test]
async fn unreadable_marker_blocks() {
    let server = mock_server(HashMap::new()).await;
    let registry = registry(&[&server], "1.0.0");
    let issues = crate::gradle_plugin_scan::implementation_advisory_issues(
        &registry,
        &requested("1.0.0"),
        &FakeOsv(vec![]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(issues.len(), 1);
}
