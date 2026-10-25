//! NuGet registration metadata against a local mock server: the SemVer 2.0.0
//! hive, gzip bodies under a decompression cap, paged indexes, host pinning
//! and fail-closed parsing.

use super::*;
use crate::registry::RegistryMetadata;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Route {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn gz(json: &serde_json::Value) -> Route {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(json.to_string().as_bytes()).unwrap();
    Route {
        status: 200,
        headers: vec![("Content-Encoding".into(), "gzip".into())],
        body: encoder.finish().unwrap(),
    }
}

fn plain(json: &serde_json::Value) -> Route {
    Route {
        status: 200,
        headers: vec![],
        body: json.to_string().into_bytes(),
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

async fn mock_server(build: impl FnOnce(&str) -> HashMap<String, Route>) -> MockServer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let routes = build(&origin);
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
                    body: b"{}".to_vec(),
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
                let _ = stream.write_all(&route.body).await;
            });
        }
    });
    MockServer { origin, requests }
}

const INDEX: &str = "/v3/registration5-gz-semver2/acme.lib/index.json";

fn registry(origin: &str) -> NugetRegistry {
    NugetRegistry::for_test(origin, RegistrationLimits::default())
}

fn entry(version: &str, published: &str) -> serde_json::Value {
    serde_json::json!({
        "@id": format!("https://example.invalid/{version}.json"),
        "catalogEntry": {"id": "Acme.Lib", "version": version, "published": published, "listed": true}
    })
}

fn inline_index(entries: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "count": 1,
        "items": [{"@id": "x#page/a/b", "count": entries.len(), "items": entries}]
    })
}

#[tokio::test]
async fn semver2_only_version_is_found_in_the_gz_semver2_hive() {
    let server = mock_server(|_| {
        [(
            INDEX.to_string(),
            gz(&inline_index(vec![
                entry("1.0.0", "2020-01-01T00:00:00+00:00"),
                entry("2.0.0-beta.1", "2024-05-05T00:00:00+00:00"),
            ])),
        )]
        .into()
    })
    .await;
    let meta = registry(&server.origin)
        .metadata("Acme.Lib", Some("2.0.0-beta.1"))
        .await
        .unwrap()
        .expect("SemVer 2.0.0 packages have metadata");
    assert_eq!(meta.created.as_deref(), Some("2020-01-01T00:00:00+00:00"));
    assert_eq!(
        meta.latest_version_date.as_deref(),
        Some("2024-05-05T00:00:00+00:00")
    );
    assert_eq!(server.requests(), vec![INDEX.to_string()]);
}

#[tokio::test]
async fn version_match_ignores_case_and_build_metadata() {
    let server = mock_server(|_| {
        [(
            INDEX.to_string(),
            gz(&inline_index(vec![entry(
                "3.0.0-RC.1+sha.abc",
                "2023-03-03T00:00:00+00:00",
            )])),
        )]
        .into()
    })
    .await;
    let meta = registry(&server.origin)
        .metadata("Acme.Lib", Some("3.0.0-rc.1"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        meta.latest_version_date.as_deref(),
        Some("2023-03-03T00:00:00+00:00")
    );
}

#[tokio::test]
async fn uncompressed_json_is_accepted() {
    let server = mock_server(|_| {
        [(
            INDEX.to_string(),
            plain(&inline_index(vec![entry(
                "1.0.0",
                "2020-01-01T00:00:00+00:00",
            )])),
        )]
        .into()
    })
    .await;
    let meta = registry(&server.origin)
        .metadata("Acme.Lib", Some("1.0.0"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        meta.latest_version_date.as_deref(),
        Some("2020-01-01T00:00:00+00:00")
    );
}

#[tokio::test]
async fn paged_index_fetches_each_page_on_the_registry_host() {
    let server = mock_server(|origin| {
        let page1 = format!("{origin}/v3/registration5-gz-semver2/acme.lib/page/1.0.0/1.9.0.json");
        let page2 = format!("{origin}/v3/registration5-gz-semver2/acme.lib/page/2.0.0/2.0.0.json");
        [
            (
                INDEX.to_string(),
                gz(&serde_json::json!({
                    "count": 2,
                    "items": [
                        {"@id": page1, "count": 1, "lower": "1.0.0", "upper": "1.9.0"},
                        {"@id": page2, "count": 1, "lower": "2.0.0", "upper": "2.0.0"}
                    ]
                })),
            ),
            (
                "/v3/registration5-gz-semver2/acme.lib/page/1.0.0/1.9.0.json".to_string(),
                gz(&serde_json::json!({"items": [entry("1.0.0", "2019-01-01T00:00:00+00:00")]})),
            ),
            (
                "/v3/registration5-gz-semver2/acme.lib/page/2.0.0/2.0.0.json".to_string(),
                gz(&serde_json::json!({"items": [entry("2.0.0", "2025-02-02T00:00:00+00:00")]})),
            ),
        ]
        .into()
    })
    .await;
    let reg = registry(&server.origin);
    let meta = reg
        .metadata("Acme.Lib", Some("2.0.0"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(meta.created.as_deref(), Some("2019-01-01T00:00:00+00:00"));
    assert_eq!(
        meta.latest_version_date.as_deref(),
        Some("2025-02-02T00:00:00+00:00")
    );
    // Without a version, the newest entry of the last page is used.
    let latest = reg.metadata("Acme.Lib", None).await.unwrap().unwrap();
    assert_eq!(
        latest.latest_version_date.as_deref(),
        Some("2025-02-02T00:00:00+00:00")
    );
}

#[tokio::test]
async fn off_host_page_url_fails_without_contacting_that_host() {
    let elsewhere = mock_server(|_| HashMap::new()).await;
    let page = format!(
        "{}/v3/registration5-gz-semver2/acme.lib/page/1.0.0/2.0.0.json",
        elsewhere.origin
    );
    let server = mock_server(move |_| {
        [(
            INDEX.to_string(),
            gz(&serde_json::json!({"items": [{"@id": page, "count": 1}]})),
        )]
        .into()
    })
    .await;
    let err = registry(&server.origin)
        .metadata("Acme.Lib", Some("2.0.0"))
        .await
        .expect_err("an off-host page must fail closed");
    assert!(err.to_string().contains("host"), "{err:#}");
    assert!(
        elsewhere.requests().is_empty(),
        "{:?}",
        elsewhere.requests()
    );
}

#[tokio::test]
async fn page_url_for_another_package_is_rejected() {
    let server = mock_server(|origin| {
        let page = format!("{origin}/v3/registration5-gz-semver2/evil.lib/page/1.0.0/2.0.0.json");
        [(
            INDEX.to_string(),
            gz(&serde_json::json!({"items": [{"@id": page, "count": 1}]})),
        )]
        .into()
    })
    .await;
    assert!(
        registry(&server.origin)
            .metadata("Acme.Lib", Some("2.0.0"))
            .await
            .is_err()
    );
    assert_eq!(server.requests(), vec![INDEX.to_string()]);
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let elsewhere = mock_server(|_| HashMap::new()).await;
    let location = format!("{}{INDEX}", elsewhere.origin);
    let server = mock_server(move |_| {
        [(
            INDEX.to_string(),
            Route {
                status: 302,
                headers: vec![("Location".into(), location)],
                body: vec![],
            },
        )]
        .into()
    })
    .await;
    let err = registry(&server.origin)
        .metadata("Acme.Lib", Some("1.0.0"))
        .await
        .expect_err("a redirect must fail closed");
    assert!(err.to_string().contains("redirect"), "{err:#}");
    assert!(elsewhere.requests().is_empty());
}

#[tokio::test]
async fn too_many_pages_fail_closed() {
    let server = mock_server(|origin| {
        let pages: Vec<_> = (0..3)
            .map(|i| {
                serde_json::json!({
                    "@id": format!("{origin}/v3/registration5-gz-semver2/acme.lib/page/{i}.json"),
                    "count": 1
                })
            })
            .collect();
        [(INDEX.to_string(), gz(&serde_json::json!({"items": pages})))].into()
    })
    .await;
    let reg = NugetRegistry::for_test(
        &server.origin,
        RegistrationLimits {
            max_pages: 2,
            ..RegistrationLimits::default()
        },
    );
    let err = reg.metadata("Acme.Lib", Some("1.0.0")).await.unwrap_err();
    assert!(err.to_string().contains("pages"), "{err:#}");
    assert_eq!(server.requests(), vec![INDEX.to_string()]);
}

#[tokio::test]
async fn gzip_bomb_is_capped() {
    let padding = "x".repeat(64 * 1024);
    let server = mock_server(move |_| {
        [(
            INDEX.to_string(),
            gz(&serde_json::json!({"items": [], "padding": padding})),
        )]
        .into()
    })
    .await;
    let reg = NugetRegistry::for_test(
        &server.origin,
        RegistrationLimits {
            max_decompressed_bytes: 16 * 1024,
            ..RegistrationLimits::default()
        },
    );
    let err = reg.metadata("Acme.Lib", Some("1.0.0")).await.unwrap_err();
    assert!(err.to_string().contains("bytes"), "{err:#}");
}

#[tokio::test]
async fn oversized_compressed_body_is_capped() {
    let server = mock_server(|_| {
        [(
            INDEX.to_string(),
            plain(&serde_json::json!({"items": [], "padding": "y".repeat(4096)})),
        )]
        .into()
    })
    .await;
    let reg = NugetRegistry::for_test(
        &server.origin,
        RegistrationLimits {
            max_compressed_bytes: 1024,
            ..RegistrationLimits::default()
        },
    );
    assert!(reg.metadata("Acme.Lib", Some("1.0.0")).await.is_err());
}

#[tokio::test]
async fn gzip_header_with_non_gzip_body_fails_closed() {
    let server = mock_server(|_| {
        [(
            INDEX.to_string(),
            Route {
                status: 200,
                headers: vec![("Content-Encoding".into(), "gzip".into())],
                body: b"{\"items\":[]}".to_vec(),
            },
        )]
        .into()
    })
    .await;
    assert!(
        registry(&server.origin)
            .metadata("Acme.Lib", Some("1.0.0"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn malformed_registration_data_fails_closed() {
    for body in [
        serde_json::json!({"no_items": true}),
        serde_json::json!({"items": [{"count": 1}]}),
        serde_json::json!({"items": [{"items": [{"catalogEntry": {"id": "Acme.Lib", "published": "2020-01-01T00:00:00Z"}}]}]}),
        serde_json::json!({"items": [{"items": [{"no_catalog": {}}]}]}),
        serde_json::json!(["not", "an", "object"]),
    ] {
        let route = gz(&body);
        let server = mock_server(move |_| [(INDEX.to_string(), route)].into()).await;
        let result = registry(&server.origin)
            .metadata("Acme.Lib", Some("1.0.0"))
            .await;
        assert!(result.is_err(), "{body}: {result:?}");
    }
}

#[tokio::test]
async fn not_found_is_no_metadata() {
    let server = mock_server(|_| HashMap::new()).await;
    assert!(
        registry(&server.origin)
            .metadata("Acme.Lib", Some("1.0.0"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unlisted_sentinel_date_is_not_a_publish_date() {
    let server = mock_server(|_| {
        [(
            INDEX.to_string(),
            gz(&inline_index(vec![
                entry("0.9.0", "1900-01-01T00:00:00+00:00"),
                entry("1.0.0", "2020-01-01T00:00:00+00:00"),
            ])),
        )]
        .into()
    })
    .await;
    let reg = registry(&server.origin);
    let meta = reg
        .metadata("Acme.Lib", Some("0.9.0"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(meta.latest_version_date, None);
    assert_eq!(meta.created.as_deref(), Some("2020-01-01T00:00:00+00:00"));
}

#[tokio::test]
async fn metadata_reports_each_published_id_spelling() {
    let mut legacy = entry("0.9.0", "2019-01-01T00:00:00+00:00");
    legacy["catalogEntry"]["id"] = "acme.lib".into();
    let server = mock_server(move |_| {
        [(
            INDEX.to_string(),
            gz(&inline_index(vec![
                legacy,
                entry("1.0.0", "2020-01-01T00:00:00+00:00"),
                entry("1.1.0", "2020-02-01T00:00:00+00:00"),
            ])),
        )]
        .into()
    })
    .await;
    let meta = registry(&server.origin)
        .metadata("ACME.LIB", Some("1.0.0"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(meta.registry_ids, vec!["Acme.Lib", "acme.lib"]);
}

#[tokio::test]
async fn catalog_entry_for_another_id_fails_closed() {
    for id in [serde_json::Value::Null, "Other.Lib".into(), "".into()] {
        let mut wrong = entry("1.0.0", "2020-01-01T00:00:00+00:00");
        wrong["catalogEntry"]["id"] = id.clone();
        let route = gz(&inline_index(vec![wrong]));
        let server = mock_server(move |_| [(INDEX.to_string(), route)].into()).await;
        let result = registry(&server.origin)
            .metadata("Acme.Lib", Some("1.0.0"))
            .await;
        assert!(result.is_err(), "{id}: {result:?}");
    }
}

#[test]
fn production_registration_base_is_the_semver2_hive() {
    assert_eq!(
        NUGET_REGISTRATION_BASE,
        "https://api.nuget.org/v3/registration5-gz-semver2"
    );
    let reg = NugetRegistry::new();
    assert_eq!(
        reg.registration_index_url("Acme.Lib"),
        "https://api.nuget.org/v3/registration5-gz-semver2/acme.lib/index.json"
    );
}
