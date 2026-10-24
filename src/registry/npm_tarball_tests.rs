//! Tarball verification against the packument (manifest confusion). All
//! fixtures are built in memory; network tests use a local 127.0.0.1 server.

use super::*;

use crate::registry::RegistryMetadata;

use crate::registry::npm_tarball::*;

use serde_json::json;

use std::collections::HashMap;

use std::io::Write;

use std::sync::{Arc, Mutex};

// ── fixtures ──

enum Entry<'a> {
    File(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
    /// A single 512-byte zero block (node-tar keeps reading after one).
    ZeroBlock,
}

fn tar_bytes(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        match entry {
            Entry::File(path, data) => {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                out.extend_from_slice(header.as_bytes());
                out.extend_from_slice(data);
                out.resize(out.len().div_ceil(512) * 512, 0);
            }
            Entry::Symlink(path, target) => {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_link_name(target).unwrap();
                header.set_cksum();
                out.extend_from_slice(header.as_bytes());
            }
            Entry::ZeroBlock => out.extend_from_slice(&[0u8; 512]),
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn tgz(entries: &[Entry]) -> Vec<u8> {
    gzip(&tar_bytes(entries))
}

fn package_tgz(package_json: &serde_json::Value) -> Vec<u8> {
    let manifest = package_json.to_string();
    tgz(&[
        Entry::File("package/package.json", manifest.as_bytes()),
        Entry::File("package/index.js", b"module.exports = 1;\n"),
    ])
}

fn sri_sha512(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha512-{}", base64_encode(&sha2::Sha512::digest(bytes)))
}

fn clean_manifest() -> serde_json::Value {
    json!({
        "name": "left-pad", "version": "1.0.0",
        "scripts": {"test": "jest"},
        "dependencies": {"a": "^1.0.0"}
    })
}

fn facts(json: serde_json::Value) -> NpmManifestFacts {
    read_tarball_manifest(&package_tgz(&json), &TarballLimits::default()).unwrap()
}

// ── pure helpers ──

#[derive(Clone)]
struct Route {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn ok(body: Vec<u8>) -> Route {
    Route {
        status: 200,
        headers: vec![],
        body,
    }
}

struct MockServer {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
}

async fn mock_server(routes: HashMap<String, Route>) -> MockServer {
    mock_server_with(|_| routes).await
}

/// Mock server whose routes may embed its own origin (e.g. a packument's
/// `dist.tarball`).
async fn mock_server_with(build: impl FnOnce(&str) -> HashMap<String, Route>) -> MockServer {
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

fn test_registry(origin: &str, limits: TarballLimits) -> NpmRegistry {
    NpmRegistry::for_test(origin, limits)
}

fn tarball_ref(
    origin: &str,
    integrity: Option<String>,
    declared: serde_json::Value,
) -> NpmTarballRef {
    NpmTarballRef {
        version: "1.0.0".into(),
        tarball: Some(format!("{origin}/left-pad/-/left-pad-1.0.0.tgz")),
        integrity,
        shasum: None,
        declared: declared_facts(&declared),
    }
}

const TARBALL_PATH: &str = "/left-pad/-/left-pad-1.0.0.tgz";

/// A brand-new, low-download package whose packument is clean and
/// consistent (correct integrity) whatever the tarball contains.
fn forged_packument(origin: &str, integrity: &str) -> serde_json::Value {
    let now = crate::cache::now_iso8601();
    json!({
        "name": "left-pad",
        "time": {"created": now, "modified": now, "1.0.0": now},
        "dist-tags": {"latest": "1.0.0"},
        "repository": {"url": "https://github.com/acme/left-pad"},
        "versions": {"1.0.0": {
            "name": "left-pad", "version": "1.0.0",
            "scripts": {"test": "jest"},
            "dependencies": {"a": "^1.0.0"},
            "_npmUser": {"name": "mallory"},
            "dist": {"tarball": format!("{origin}{TARBALL_PATH}"), "integrity": integrity}
        }}
    })
}

async fn scan_npm(tarball_manifest: serde_json::Value) -> (Vec<crate::report::Issue>, Vec<String>) {
    let bytes = package_tgz(&tarball_manifest);
    let integrity = sri_sha512(&bytes);
    let server = mock_server_with(|origin| {
        [
            (
                "/left-pad".to_string(),
                ok(forged_packument(origin, &integrity)
                    .to_string()
                    .into_bytes()),
            ),
            (
                "/downloads/left-pad".to_string(),
                ok(br#"{"downloads": 5}"#.to_vec()),
            ),
            (TARBALL_PATH.to_string(), ok(bytes)),
        ]
        .into()
    })
    .await;
    let registry = test_registry(&server.origin, TarballLimits::default());
    let deps = vec![crate::test_helpers::dep_with(
        "left-pad",
        Some("1.0.0"),
        crate::Ecosystem::Npm,
    )];
    let issues = crate::checks::metadata::check_metadata(
        &registry,
        &deps,
        &crate::config::SloppyJoeConfig::default(),
        &std::collections::HashSet::new(),
        &crate::lockfiles::ResolutionResult::default(),
    )
    .await
    .unwrap();
    let requests = server.requests.lock().unwrap().clone();
    (issues, requests)
}

#[path = "npm_tarball_tests/part01_sha1_matches_fips.rs"]
mod part01_sha1_matches_fips;
