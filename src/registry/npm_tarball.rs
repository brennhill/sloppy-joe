//! npm tarball verification ("manifest confusion" defence).
//!
//! The registry packument is publisher-supplied and npm does not validate it
//! against the published tarball, while npm runs the lifecycle scripts found
//! in the tarball's own `package.json`. A forged-but-consistent packument can
//! therefore hide a `postinstall`. For versions selected for verification the
//! tarball is downloaded into memory (never to disk), checked against the
//! packument's `dist.integrity` / `dist.shasum`, and its `package.json` is read
//! under hard size and entry limits. Nothing is extracted.

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

/// Lifecycle scripts that run (or, for `prepare`, can run) on install.
pub(crate) const INSTALL_HOOKS: [&str; 4] = ["preinstall", "install", "postinstall", "prepare"];

/// The script npm synthesises for a package that ships a `*.gyp` file and
/// declares no `install`/`preinstall` script.
pub(crate) const NODE_GYP_REBUILD: &str = "node-gyp rebuild";

/// Hard limits applied while downloading and reading a tarball.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarballLimits {
    /// Maximum tarball size as transferred (gzip-compressed).
    pub max_compressed_bytes: u64,
    /// Maximum total bytes produced by gzip decompression (bomb defence).
    pub max_decompressed_bytes: u64,
    /// Maximum number of tar entries.
    pub max_entries: usize,
    /// Maximum size of the tarball's `package.json`.
    pub max_manifest_bytes: u64,
}

impl Default for TarballLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: 64 * 1024 * 1024,
            max_decompressed_bytes: 1024 * 1024 * 1024,
            max_entries: 200_000,
            max_manifest_bytes: 1024 * 1024,
        }
    }
}

/// Install and dependency facts for one npm package version, read either
/// from the packument (declared) or from the tarball's `package.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmManifestFacts {
    /// Effective install hooks (`preinstall`/`install`/`postinstall`/`prepare`)
    /// mapped to their command.
    pub install_scripts: BTreeMap<String, String>,
    /// Names from `dependencies` and `optionalDependencies`. npm's publish
    /// normalisation moves names between the two, so only the union is stable.
    pub dependencies: BTreeSet<String>,
    /// Packument: `gypfile: true`. Tarball: a root-level `*.gyp` file exists.
    pub gyp: bool,
}

impl NpmManifestFacts {
    pub fn has_install_scripts(&self) -> bool {
        !self.install_scripts.is_empty() || self.gyp
    }
}

/// Where the packument says a version's tarball lives, how to verify it, and
/// what the packument declares about that version.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct NpmTarballRef {
    pub version: String,
    pub tarball: Option<String>,
    pub integrity: Option<String>,
    pub shasum: Option<String>,
    pub declared: NpmManifestFacts,
}

impl NpmTarballRef {
    /// Stable cache identity: name, version and the expected content hash.
    /// `None` when the packument gives no hash (verification cannot succeed).
    pub fn cache_key(&self, package: &str) -> Option<String> {
        let digest = match (&self.integrity, &self.shasum) {
            (Some(integrity), _) if !integrity.trim().is_empty() => integrity.trim().to_string(),
            (_, Some(shasum)) if !shasum.trim().is_empty() => format!("shasum:{}", shasum.trim()),
            _ => return None,
        };
        Some(format!("{package}@{}#{digest}", self.version))
    }
}

/// The downloaded tarball does not match the hash the packument declares.
#[derive(Debug)]
pub struct IntegrityMismatch(pub String);

impl std::fmt::Display for IntegrityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IntegrityMismatch {}

/// Build a packument `NpmTarballRef` for one version object.
pub(crate) fn tarball_ref_from_version(
    version: &str,
    version_obj: &serde_json::Value,
) -> NpmTarballRef {
    let dist = &version_obj["dist"];
    let text = |value: &serde_json::Value| value.as_str().map(str::to_string);
    NpmTarballRef {
        version: version.to_string(),
        tarball: text(&dist["tarball"]),
        integrity: text(&dist["integrity"]),
        shasum: text(&dist["shasum"]),
        declared: declared_facts(version_obj),
    }
}

/// Facts the packument declares for a version (already publish-normalised).
pub(crate) fn declared_facts(version_obj: &serde_json::Value) -> NpmManifestFacts {
    NpmManifestFacts {
        install_scripts: install_hooks(&version_obj["scripts"]),
        dependencies: dependency_names(version_obj),
        gyp: version_obj["gypfile"].as_bool() == Some(true),
    }
}

/// Facts from a tarball's raw `package.json`, normalised the way npm does at
/// publish and install time (implicit `node-gyp rebuild`, script path prefix).
pub(crate) fn tarball_facts(
    package_json: &serde_json::Value,
    has_root_gyp: bool,
) -> NpmManifestFacts {
    let mut install_scripts = install_hooks(&package_json["scripts"]);
    if has_root_gyp
        && package_json["gypfile"].as_bool() != Some(false)
        && !install_scripts.contains_key("install")
        && !install_scripts.contains_key("preinstall")
    {
        install_scripts.insert("install".to_string(), NODE_GYP_REBUILD.to_string());
    }
    NpmManifestFacts {
        install_scripts,
        dependencies: dependency_names(package_json),
        gyp: has_root_gyp,
    }
}

fn install_hooks(scripts: &serde_json::Value) -> BTreeMap<String, String> {
    INSTALL_HOOKS
        .iter()
        .filter_map(|hook| {
            let command = scripts[*hook].as_str()?;
            Some((hook.to_string(), normalize_script(command)))
        })
        .collect()
}

/// npm strips a leading `node_modules/.bin/` (optionally `./`) from scripts
/// when it normalises a manifest for publishing.
fn normalize_script(command: &str) -> String {
    for prefix in [
        "./node_modules/.bin/",
        ".\\node_modules\\.bin\\",
        "node_modules/.bin/",
        "node_modules\\.bin\\",
    ] {
        if let Some(rest) = command.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    command.to_string()
}

fn dependency_names(manifest: &serde_json::Value) -> BTreeSet<String> {
    ["dependencies", "optionalDependencies"]
        .iter()
        .filter_map(|section| manifest[*section].as_object())
        .flat_map(|deps| deps.keys().cloned())
        .collect()
}

/// Human-readable differences between what the packument declares and what
/// the tarball contains. Empty when they agree.
pub(crate) fn compare_facts(declared: &NpmManifestFacts, actual: &NpmManifestFacts) -> Vec<String> {
    let mut differences = Vec::new();
    for hook in INSTALL_HOOKS {
        let declared_cmd = declared.install_scripts.get(hook).map(|c| shorten(c));
        let actual_cmd = actual.install_scripts.get(hook).map(|c| shorten(c));
        match (declared_cmd, actual_cmd) {
            (None, Some(command)) => differences.push(format!(
                "the tarball's package.json has a {hook} script ({command:?}) that the registry metadata does not declare"
            )),
            (Some(command), None) => differences.push(format!(
                "the registry metadata declares a {hook} script ({command:?}) that the tarball's package.json does not contain"
            )),
            (Some(declared_cmd), Some(actual_cmd))
                if declared.install_scripts.get(hook) != actual.install_scripts.get(hook) =>
            {
                differences.push(format!(
                    "the {hook} script differs: registry metadata has {declared_cmd:?}, the tarball has {actual_cmd:?}"
                ))
            }
            _ => {}
        }
    }
    if declared.gyp && !actual.gyp {
        differences.push(
            "the registry metadata declares a native build (gypfile) but the tarball has no .gyp file"
                .to_string(),
        );
    }
    let hidden: Vec<_> = actual
        .dependencies
        .difference(&declared.dependencies)
        .collect();
    if !hidden.is_empty() {
        differences.push(format!(
            "the tarball's package.json depends on {} not listed in the registry metadata",
            quote_list(&hidden)
        ));
    }
    let phantom: Vec<_> = declared
        .dependencies
        .difference(&actual.dependencies)
        .collect();
    if !phantom.is_empty() {
        differences.push(format!(
            "the registry metadata lists {} as dependencies but the tarball's package.json does not",
            quote_list(&phantom)
        ));
    }
    differences
}

/// Bound publisher-controlled text quoted in issue messages.
fn shorten(text: &str) -> String {
    const MAX_CHARS: usize = 120;
    if text.chars().count() <= MAX_CHARS {
        return text.to_string();
    }
    let head: String = text.chars().take(MAX_CHARS).collect();
    format!("{head}...")
}

fn quote_list(names: &[&String]) -> String {
    const SHOWN: usize = 10;
    let mut text = names
        .iter()
        .take(SHOWN)
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        text.push_str(&format!(" and {} more", names.len() - SHOWN));
    }
    text
}

/// Accept a packument `dist.tarball` URL only if it is on the registry's own
/// origin (same scheme, host and port; the registry origin is HTTPS), carries
/// no credentials, and points into this package's tarball directory.
pub(crate) fn validate_tarball_url(
    raw: &str,
    registry_origin: &reqwest::Url,
    package_name: &str,
) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw)
        .map_err(|e| anyhow!("tarball URL {raw:?} is not a valid URL: {e}"))?;
    if url.scheme() != "https" && registry_origin.scheme() == "https" {
        bail!("tarball URL {raw:?} does not use HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("tarball URL for '{package_name}' embeds credentials");
    }
    if url.scheme() != registry_origin.scheme()
        || url.host_str() != registry_origin.host_str()
        || url.port_or_known_default() != registry_origin.port_or_known_default()
    {
        bail!(
            "tarball URL {raw:?} is not on the registry host {}",
            registry_origin.host_str().unwrap_or("")
        );
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("tarball URL {raw:?} has a query or fragment");
    }
    let expected_prefix = format!("/{package_name}/-/");
    let path = url.path();
    if !path.starts_with(&expected_prefix)
        || !path.ends_with(".tgz")
        || path[expected_prefix.len()..].contains('/')
    {
        bail!("tarball URL {raw:?} is not in the tarball directory of '{package_name}'");
    }
    Ok(url)
}

/// Verify downloaded bytes against the packument hashes, the way npm does:
/// the strongest supported algorithm in `dist.integrity`, else `dist.shasum`.
/// A mismatch is an [`IntegrityMismatch`]; no usable hash is a plain error.
pub(crate) fn verify_integrity(
    bytes: &[u8],
    integrity: Option<&str>,
    shasum: Option<&str>,
) -> Result<()> {
    const ALGORITHMS: [&str; 4] = ["sha512", "sha384", "sha256", "sha1"];
    if let Some(integrity) = integrity {
        let entries: Vec<(&str, &str)> = integrity
            .split_whitespace()
            .filter_map(|entry| {
                let entry = entry.split('?').next().unwrap_or(entry);
                entry.split_once('-')
            })
            .collect();
        for algorithm in ALGORITHMS {
            let expected: Vec<&str> = entries
                .iter()
                .filter(|(alg, _)| *alg == algorithm)
                .map(|(_, digest)| *digest)
                .collect();
            if expected.is_empty() {
                continue;
            }
            let actual = base64_encode(&digest(algorithm, bytes));
            if expected.contains(&actual.as_str()) {
                return Ok(());
            }
            return Err(IntegrityMismatch(format!(
                "tarball {algorithm} digest {actual} does not match the registry integrity {}",
                expected.join(" ")
            ))
            .into());
        }
    }
    if let Some(shasum) = shasum {
        let shasum = shasum.trim().to_ascii_lowercase();
        if shasum.len() != 40 || !shasum.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("registry shasum {shasum:?} is not a SHA-1 hex digest");
        }
        let actual = hex(&sha1(bytes));
        if actual == shasum {
            return Ok(());
        }
        return Err(IntegrityMismatch(format!(
            "tarball sha1 {actual} does not match the registry shasum {shasum}"
        ))
        .into());
    }
    bail!("registry metadata provides no supported integrity hash for the tarball")
}

fn digest(algorithm: &str, bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match algorithm {
        "sha512" => sha2::Sha512::digest(bytes).to_vec(),
        "sha384" => sha2::Sha384::digest(bytes).to_vec(),
        "sha256" => sha2::Sha256::digest(bytes).to_vec(),
        _ => sha1(bytes).to_vec(),
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Standard base64 with padding (the encoding used by SRI strings).
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// SHA-1, only used to compare against legacy npm `shasum` values; packages
/// published since 2017 carry a sha512 integrity instead.
pub(crate) fn sha1(bytes: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    Sha1::digest(bytes).into()
}

/// Caps the bytes a reader may produce; exceeding the cap is an error, so a
/// gzip bomb fails instead of running to completion.
struct LimitedReader<R> {
    inner: R,
    produced: u64,
    limit: u64,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.produced += n as u64;
        if self.produced > self.limit {
            return Err(std::io::Error::other(format!(
                "tarball decompresses to more than {} bytes",
                self.limit
            )));
        }
        Ok(n)
    }
}

/// Path of an entry after npm's extraction rule (`strip: 1`): drop the first
/// component. `None` for entries that would be dropped or escape the package.
fn stripped_entry_path(raw: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(raw);
    let components: Vec<&str> = raw
        .split(['/', '\\'])
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    if components.len() < 2 || components.contains(&"..") {
        return None;
    }
    Some(components[1..].join("/"))
}

/// Read the tarball's `package.json` (and whether it ships a root `*.gyp`)
/// from gzip-compressed tar bytes, entirely in memory and under `limits`.
///
/// Every entry is visited because a later entry with the same path would
/// overwrite an earlier one on extraction: more than one `package.json`
/// (compared case-insensitively, as on macOS/Windows file systems) is an
/// error, as is a `package.json` that is not a regular file.
pub(crate) fn read_tarball_manifest(
    bytes: &[u8],
    limits: &TarballLimits,
) -> Result<NpmManifestFacts> {
    let decoder = LimitedReader {
        inner: flate2::read::MultiGzDecoder::new(bytes),
        produced: 0,
        limit: limits.max_decompressed_bytes,
    };
    let mut archive = tar::Archive::new(decoder);
    // node-tar only stops at two consecutive zero blocks; tar-rs would stop at
    // the first one and miss entries npm still extracts.
    archive.set_ignore_zeros(true);

    let mut manifest: Option<Vec<u8>> = None;
    let mut has_root_gyp = false;
    let mut entries = 0usize;
    let entry_iter = archive
        .entries()
        .map_err(|e| anyhow!("could not read the tarball: {e}"))?;
    for entry in entry_iter {
        let mut entry = entry.map_err(|e| anyhow!("could not read the tarball: {e}"))?;
        entries += 1;
        if entries > limits.max_entries {
            bail!("tarball has more than {} entries", limits.max_entries);
        }
        let Some(path) = stripped_entry_path(&entry.path_bytes()) else {
            continue;
        };
        let lower = path.to_ascii_lowercase();
        if lower == "package.json" {
            if manifest.is_some() {
                bail!("tarball contains more than one package.json");
            }
            if !entry.header().entry_type().is_file() {
                bail!("the tarball's package.json is not a regular file");
            }
            if entry.size() > limits.max_manifest_bytes {
                bail!(
                    "the tarball's package.json is larger than {} bytes",
                    limits.max_manifest_bytes
                );
            }
            let mut buf = Vec::new();
            (&mut entry)
                .take(limits.max_manifest_bytes + 1)
                .read_to_end(&mut buf)
                .map_err(|e| anyhow!("could not read the tarball's package.json: {e}"))?;
            if buf.len() as u64 > limits.max_manifest_bytes {
                bail!(
                    "the tarball's package.json is larger than {} bytes",
                    limits.max_manifest_bytes
                );
            }
            manifest = Some(buf);
        } else if !lower.contains('/') && lower.ends_with(".gyp") {
            has_root_gyp = true;
        }
    }

    let manifest = manifest.ok_or_else(|| anyhow!("the tarball has no package/package.json"))?;
    let text = manifest.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&manifest);
    let json: serde_json::Value = serde_json::from_slice(text)
        .map_err(|e| anyhow!("the tarball's package.json is not valid JSON: {e}"))?;
    if !json.is_object() {
        bail!("the tarball's package.json is not a JSON object");
    }
    Ok(tarball_facts(&json, has_root_gyp))
}

/// Download a tarball into memory. Redirects are never followed (the client
/// is built without a redirect policy) and the body is capped.
pub(crate) async fn download_tarball(
    client: &reqwest::Client,
    url: &reqwest::Url,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let mut resp = super::retry_get(client, url.as_str())
        .await
        .map_err(|e| anyhow!("tarball download failed: {e}"))?;
    let status = resp.status();
    if status.is_redirection() {
        bail!(
            "tarball download was redirected (HTTP {}); redirects are not followed",
            status.as_u16()
        );
    }
    if !status.is_success() {
        bail!("tarball download returned HTTP {}", status.as_u16());
    }
    if resp.content_length().is_some_and(|len| len > max_bytes) {
        bail!("tarball is larger than {max_bytes} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| anyhow!("tarball download failed: {e}"))?
    {
        if body.len() as u64 + chunk.len() as u64 > max_bytes {
            bail!("tarball is larger than {max_bytes} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Download, verify and read a tarball. Hashing and parsing run on a
/// blocking thread; the bytes are hashed before they are parsed.
pub(crate) async fn fetch_and_verify(
    client: &reqwest::Client,
    registry_origin: &reqwest::Url,
    package_name: &str,
    tarball: &NpmTarballRef,
    limits: TarballLimits,
) -> Result<NpmManifestFacts> {
    let raw = tarball.tarball.as_deref().ok_or_else(|| {
        anyhow!(
            "registry metadata for '{package_name}@{}' has no dist.tarball URL",
            tarball.version
        )
    })?;
    let url = validate_tarball_url(raw, registry_origin, package_name)?;
    let bytes = download_tarball(client, &url, limits.max_compressed_bytes).await?;
    let integrity = tarball.integrity.clone();
    let shasum = tarball.shasum.clone();
    tokio::task::spawn_blocking(move || {
        verify_integrity(&bytes, integrity.as_deref(), shasum.as_deref())?;
        read_tarball_manifest(&bytes, &limits)
    })
    .await
    .map_err(|e| anyhow!("tarball verification task failed: {e}"))?
}
