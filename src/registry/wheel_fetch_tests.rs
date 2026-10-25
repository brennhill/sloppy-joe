//! Wheel download: host pinning, hash check, redirects.

use super::tests::zip;
use super::*;
use crate::registry::RegistryMetadata;
use crate::registry::pypi::PypiRegistry;
use crate::registry::pypi_release::{PypiFile, PypiFileKind};
use sha2::Digest;

async fn serve(status: u16, location: Option<&'static str>, body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let mut head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                if let Some(location) = location {
                    head.push_str(&format!("Location: {location}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    origin
}

fn file(origin: &str, sha256: Option<String>) -> PypiFile {
    PypiFile {
        filename: "p-1.0-py3-none-any.whl".into(),
        url: format!("{origin}/packages/p-1.0-py3-none-any.whl"),
        sha256,
        kind: PypiFileKind::Wheel,
        size: None,
        yanked: false,
    }
}

fn sha(bytes: &[u8]) -> String {
    hex(&sha2::Sha256::digest(bytes))
}

#[tokio::test]
async fn verified_wheel_reports_its_startup_hook() {
    let wheel = zip(&[("p-1.0-setup.pth", b"import os\n", false)]);
    let origin = serve(200, None, wheel.clone()).await;
    let registry = PypiRegistry::for_test(&origin);
    let facts = registry
        .inspect_pypi_wheel("p", &file(&origin, Some(sha(&wheel))))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(facts.startup_hooks.len(), 1);
}

#[tokio::test]
async fn digest_mismatch_is_an_integrity_error_and_nothing_is_parsed() {
    let wheel = zip(&[("a.pth", b"import os\n", false)]);
    let origin = serve(200, None, wheel).await;
    let registry = PypiRegistry::for_test(&origin);
    let error = registry
        .inspect_pypi_wheel("p", &file(&origin, Some("00".repeat(32))))
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<IntegrityMismatch>().is_some());
}

#[tokio::test]
async fn missing_digest_refuses_to_read_the_wheel() {
    let wheel = zip(&[("a.pth", b"import os\n", false)]);
    let origin = serve(200, None, wheel).await;
    let registry = PypiRegistry::for_test(&origin);
    let error = registry
        .inspect_pypi_wheel("p", &file(&origin, None))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no sha256"));
}

#[tokio::test]
async fn url_on_another_host_is_refused() {
    let origin = serve(200, None, Vec::new()).await;
    let registry = PypiRegistry::for_test(&origin);
    let mut wheel_file = file(&origin, Some("00".repeat(32)));
    wheel_file.url = "http://127.0.0.1:1/p-1.0-py3-none-any.whl".into();
    let error = registry
        .inspect_pypi_wheel("p", &wheel_file)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not on the PyPI file host"));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let origin = serve(302, Some("http://evil.example/x.whl"), Vec::new()).await;
    let registry = PypiRegistry::for_test(&origin);
    let error = registry
        .inspect_pypi_wheel("p", &file(&origin, Some("00".repeat(32))))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("redirect"));
}

#[test]
fn url_validation_rejects_credentials_queries_and_non_wheels() {
    let origin = reqwest::Url::parse("https://files.pythonhosted.org").unwrap();
    assert!(validate_wheel_url("https://files.pythonhosted.org/p/a.whl", &origin).is_ok());
    for bad in [
        "http://files.pythonhosted.org/p/a.whl",
        "https://user@files.pythonhosted.org/p/a.whl",
        "https://files.pythonhosted.org/p/a.whl?x=1",
        "https://files.pythonhosted.org/p/a.tar.gz",
        "https://files.pythonhosted.org.evil.example/p/a.whl",
        "https://files.pythonhosted.org:8443/p/a.whl",
    ] {
        assert!(validate_wheel_url(bad, &origin).is_err(), "{bad}");
    }
}

/// Like [`serve`], answering 200 with `body` only for a path ending in `suffix` (404 otherwise).
async fn serve_path(suffix: &'static str, body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]).to_string();
                let path = request.split(' ').nth(1).unwrap_or("");
                let (status, body) = if path.ends_with(suffix) {
                    (200, body)
                } else {
                    (404, Vec::new())
                };
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    origin
}

fn core_metadata(origin: &str, sha256: String) -> crate::registry::pypi_release::PypiCoreMetadata {
    crate::registry::pypi_release::PypiCoreMetadata {
        filename: "p-1.0-py3-none-any.whl".into(),
        wheel_url: format!("{origin}/packages/p-1.0-py3-none-any.whl"),
        sha256,
    }
}

const METADATA: &[u8] = b"Metadata-Version: 2.1\nName: p\nRequires-Dist: urllib3>=1\n\nbody\n";

#[tokio::test]
async fn wheel_core_metadata_is_read_from_the_metadata_file_beside_the_wheel() {
    let origin = serve_path(
        "/packages/p-1.0-py3-none-any.whl.metadata",
        METADATA.to_vec(),
    )
    .await;
    let registry = PypiRegistry::for_test(&origin);
    let requires = registry
        .pypi_wheel_requires_dist("p", &core_metadata(&origin, sha(METADATA)))
        .await
        .unwrap();
    assert_eq!(requires, vec!["urllib3>=1".to_string()]);
}

#[tokio::test]
async fn wheel_core_metadata_with_another_digest_is_an_integrity_error() {
    let origin = serve_path(".metadata", METADATA.to_vec()).await;
    let registry = PypiRegistry::for_test(&origin);
    let error = registry
        .pypi_wheel_requires_dist("p", &core_metadata(&origin, "00".repeat(32)))
        .await
        .unwrap_err();
    assert!(
        error.downcast_ref::<IntegrityMismatch>().is_some(),
        "{error}"
    );
}

#[tokio::test]
async fn wheel_core_metadata_that_cannot_be_fetched_is_an_error() {
    // PyPI said the file exists; a 404 is a failed lookup, not "no dependencies".
    let origin = serve_path("/never", Vec::new()).await;
    let registry = PypiRegistry::for_test(&origin);
    let error = registry
        .pypi_wheel_requires_dist("p", &core_metadata(&origin, sha(METADATA)))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("404"), "{error}");
}

#[tokio::test]
async fn wheel_core_metadata_is_only_fetched_from_the_file_host() {
    let origin = serve_path(".metadata", METADATA.to_vec()).await;
    let registry = PypiRegistry::for_test(&origin);
    for url in [
        "http://127.0.0.1:1/p-1.0-py3-none-any.whl",
        &format!("{origin}/p-1.0.tar.gz"),
        &format!("{origin}/p-1.0-py3-none-any.whl?x=.metadata"),
    ] {
        let mut metadata = core_metadata(&origin, sha(METADATA));
        metadata.wheel_url = url.to_string();
        assert!(
            registry
                .pypi_wheel_requires_dist("p", &metadata)
                .await
                .is_err(),
            "{url}"
        );
    }
    assert!(
        registry
            .pypi_wheel_requires_dist("../x", &core_metadata(&origin, sha(METADATA)))
            .await
            .is_err()
    );
}
