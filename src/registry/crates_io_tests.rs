use super::*;
use crate::registry::{RegistryExistence, RegistryMetadata};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Each path answers with its responses in order; the last one repeats. Unknown paths 404.
type Routes = HashMap<String, Vec<(u16, String)>>;

struct MockServer {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    max_in_flight: Arc<AtomicUsize>,
}

impl MockServer {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn registry(&self) -> CratesIoRegistry {
        CratesIoRegistry::with_endpoints(
            crate::registry::http_client(),
            format!("{}/api/v1/crates", self.origin),
            format!("{}/index", self.origin),
        )
    }
}

async fn mock_server(routes: Routes, delay: Duration) -> MockServer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let routes = Arc::new(Mutex::new(routes));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let (seen, max) = (requests.clone(), max_in_flight.clone());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (seen, routes, in_flight, max) =
                (seen.clone(), routes.clone(), in_flight.clone(), max.clone());
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
                seen.lock().unwrap().push(path.clone());
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                let (status, body) = {
                    let mut routes = routes.lock().unwrap();
                    match routes.get_mut(&path) {
                        Some(answers) if answers.len() > 1 => answers.remove(0),
                        Some(answers) => answers[0].clone(),
                        None => (404, String::new()),
                    }
                };
                in_flight.fetch_sub(1, Ordering::SeqCst);
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    MockServer {
        origin,
        requests,
        max_in_flight,
    }
}

fn routes(entries: &[(&str, u16, &str)]) -> Routes {
    entries
        .iter()
        .map(|(path, status, body)| (path.to_string(), vec![(*status, body.to_string())]))
        .collect()
}

fn crate_body(name: &str) -> String {
    serde_json::json!({
        "crate": {
            "name": name,
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2020-03-01T00:00:00Z",
            "downloads": 1234,
            "repository": "https://example.com/repo"
        },
        "versions": [
            { "num": "0.59.0", "created_at": "2020-03-01T00:00:00Z", "published_by": { "login": "carol" } },
            { "num": "0.52.0", "created_at": "2020-02-01T00:00:00Z", "published_by": { "login": "bob" } },
            { "num": "0.48.0", "created_at": "2020-01-02T00:00:00Z", "published_by": { "login": "alice" } }
        ]
    })
    .to_string()
}

#[test]
fn metadata_uses_requested_version_for_publisher_history() {
    let body: serde_json::Value = serde_json::from_str(&crate_body("x")).unwrap();
    let metadata = metadata_from_body(&body, Some("0.52.0")).unwrap();
    assert_eq!(
        metadata.latest_version_date,
        Some("2020-02-01T00:00:00Z".to_string())
    );
    assert_eq!(metadata.current_publisher, Some("bob".to_string()));
    assert_eq!(metadata.previous_publisher, Some("alice".to_string()));
    assert_eq!(metadata.created, Some("2020-01-01T00:00:00Z".to_string()));
    assert_eq!(
        metadata.repository_url,
        Some("https://example.com/repo".to_string())
    );
    assert!(metadata_from_body(&body, Some("9.9.9")).is_none());
}

#[test]
fn a_crate_with_no_versions_has_no_metadata() {
    let body = serde_json::json!({ "crate": {}, "versions": [] });
    assert!(metadata_from_body(&body, None).is_none());
    assert!(metadata_from_body(&serde_json::json!({ "crate": {} }), None).is_none());
}

#[test]
fn sparse_index_paths_follow_the_cargo_layout() {
    assert_eq!(sparse_index_path("a"), "1/a");
    assert_eq!(sparse_index_path("ab"), "2/ab");
    assert_eq!(sparse_index_path("abc"), "3/a/abc");
    assert_eq!(sparse_index_path("Serde"), "se/rd/serde");
    assert_eq!(
        sparse_index_path("windows_i686_gnu"),
        "wi/nd/windows_i686_gnu"
    );
}

#[test]
fn separator_spellings_cover_every_assignment_of_dash_and_underscore() {
    assert_eq!(separator_spellings("tokio"), Some(vec![]));
    assert_eq!(
        separator_spellings("serde-json"),
        Some(vec!["serde_json".to_string()])
    );
    let mut two = separator_spellings("a-b_c").unwrap();
    two.sort();
    assert_eq!(two, vec!["a-b-c", "a_b-c", "a_b_c"]);
    assert_eq!(separator_spellings("a-b-c-d-e"), None);
}

#[tokio::test]
async fn existence_reads_the_sparse_index_not_the_web_api() {
    let server = mock_server(
        routes(&[("/index/wi/nd/windows_i686_gnu", 200, "{}")]),
        Duration::ZERO,
    )
    .await;
    assert!(server.registry().exists("windows_i686_gnu").await.unwrap());
    assert_eq!(server.requests(), vec!["/index/wi/nd/windows_i686_gnu"]);
}

#[tokio::test]
async fn a_name_without_separators_is_absent_after_one_index_miss() {
    let server = mock_server(Routes::new(), Duration::ZERO).await;
    assert!(!server.registry().exists("tokioo").await.unwrap());
    assert_eq!(server.requests(), vec!["/index/to/ki/tokioo"]);
}

#[tokio::test]
async fn a_crate_published_with_the_other_separator_is_found_on_the_index() {
    // crates.io treats `-` and `_` as the same name, as its web API did.
    let server = mock_server(
        routes(&[("/index/se/rd/serde_jsno", 200, "{}")]),
        Duration::ZERO,
    )
    .await;
    assert!(server.registry().exists("serde-jsno").await.unwrap());
    assert!(
        server
            .requests()
            .iter()
            .all(|path| path.starts_with("/index/"))
    );
}

#[tokio::test]
async fn a_name_absent_under_every_spelling_is_absent() {
    let server = mock_server(Routes::new(), Duration::ZERO).await;
    assert!(!server.registry().exists("serde-jsno").await.unwrap());
    let mut requests = server.requests();
    requests.sort();
    assert_eq!(
        requests,
        vec!["/index/se/rd/serde-jsno", "/index/se/rd/serde_jsno"]
    );
}

#[tokio::test]
async fn a_name_with_many_separators_falls_back_to_the_web_api() {
    let server = mock_server(
        routes(&[("/api/v1/crates/a-b-c-d-e", 200, "{}")]),
        Duration::ZERO,
    )
    .await;
    assert!(server.registry().exists("a-b-c-d-e").await.unwrap());
    assert_eq!(
        server.requests(),
        vec!["/index/a-/b-/a-b-c-d-e", "/api/v1/crates/a-b-c-d-e"]
    );
}

#[tokio::test]
async fn an_index_failure_blocks_instead_of_reading_as_absent() {
    let server = mock_server(routes(&[("/index/to/ki/tokio", 500, "")]), Duration::ZERO).await;
    let err = server.registry().exists("tokio").await.unwrap_err();
    assert!(err.to_string().contains("HTTP 500"), "{err}");
}

#[tokio::test]
async fn a_failed_spelling_blocks_when_no_spelling_is_found() {
    let server = mock_server(
        routes(&[("/index/se/rd/serde_jsno", 500, "")]),
        Duration::ZERO,
    )
    .await;
    assert!(server.registry().exists("serde-jsno").await.is_err());
}

#[tokio::test]
async fn versions_of_one_crate_share_a_single_web_api_request() {
    let body = crate_body("windows-sys");
    let server = mock_server(
        routes(&[("/api/v1/crates/windows-sys", 200, &body)]),
        Duration::from_millis(50),
    )
    .await;
    let registry = server.registry();
    let (newer, older) = tokio::join!(
        registry.metadata("windows-sys", Some("0.59.0")),
        registry.metadata("windows-sys", Some("0.52.0")),
    );
    let (newer, older) = (newer.unwrap().unwrap(), older.unwrap().unwrap());
    assert_eq!(newer.current_publisher.as_deref(), Some("carol"));
    assert_eq!(newer.previous_publisher.as_deref(), Some("bob"));
    assert_eq!(older.current_publisher.as_deref(), Some("bob"));
    assert_eq!(older.previous_publisher.as_deref(), Some("alice"));
    assert_eq!(older.downloads, Some(1234));
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn a_missing_crate_has_no_metadata_and_is_asked_about_once() {
    let server = mock_server(Routes::new(), Duration::ZERO).await;
    let registry = server.registry();
    assert!(registry.metadata("nope", None).await.unwrap().is_none());
    assert!(
        registry
            .metadata("nope", Some("1.0.0"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(server.requests(), vec!["/api/v1/crates/nope"]);
}

#[tokio::test]
async fn a_failed_metadata_lookup_is_not_remembered() {
    let body = crate_body("flaky");
    let mut routes = Routes::new();
    routes.insert(
        "/api/v1/crates/flaky".to_string(),
        vec![
            (503, String::new()),
            (503, String::new()),
            (503, String::new()),
            (200, body),
        ],
    );
    let server = mock_server(routes, Duration::ZERO).await;
    let registry = server.registry();
    let err = registry.metadata("flaky", None).await.unwrap_err();
    assert!(err.to_string().contains("HTTP 503"), "{err}");
    assert!(registry.metadata("flaky", None).await.unwrap().is_some());
}

#[tokio::test]
async fn web_api_requests_are_bounded_per_process() {
    let names: Vec<String> = (0..12).map(|i| format!("crate{i}")).collect();
    let entries: Vec<(String, u16, String)> = names
        .iter()
        .map(|name| (format!("/api/v1/crates/{name}"), 200, crate_body(name)))
        .collect();
    let routes = entries
        .iter()
        .map(|(path, status, body)| (path.clone(), vec![(*status, body.clone())]))
        .collect();
    let server = mock_server(routes, Duration::from_millis(100)).await;
    let registry = server.registry();
    let lookups = names.iter().map(|name| registry.metadata(name, None));
    for result in futures::future::join_all(lookups).await {
        assert!(result.unwrap().is_some());
    }
    let max = server.max_in_flight.load(Ordering::SeqCst);
    assert!(
        max <= API_CONCURRENCY,
        "{max} concurrent crates.io API requests"
    );
}
