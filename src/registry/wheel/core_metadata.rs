//! A wheel's core metadata, read from the file PyPI serves beside the wheel (PEP 658/714:
//! `<wheel url>.metadata`, the wheel's `.dist-info/METADATA`), without downloading the wheel.
//!
//! The JSON API's `info.requires_dist` comes from the first file uploaded for a release, which
//! may be an sdist that declares nothing; the wheel's own metadata is what pip installs from.
//! The file is fetched only from PyPI's file host, never through a redirect, and its bytes are
//! hashed against the sha256 PyPI published for it before they are parsed.

use super::super::npm_tarball::{IntegrityMismatch, download_tarball, hex};
use super::super::pypi_release::PypiCoreMetadata;
use anyhow::{Result, anyhow, bail};

/// Largest core metadata file read. Older wheels fold the whole README into a header.
pub(crate) const MAX_CORE_METADATA_BYTES: u64 = 16 * 1024 * 1024;

/// The `Requires-Dist` values of a core metadata file. Only the header block counts (the body
/// after the first blank line is the description). A file that is not UTF-8, has no
/// `Metadata-Version` or has a line that is neither a field nor a continuation is malformed.
pub(crate) fn requires_dist_from_core_metadata(bytes: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow!("the wheel's core metadata is not UTF-8"))?;
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            let (_, value) = fields
                .last_mut()
                .ok_or_else(|| anyhow!("the wheel's core metadata starts with a continuation"))?;
            value.push(' ');
            value.push_str(line.trim());
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("the wheel's core metadata has a line that is not a field"))?;
        fields.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    if !fields.iter().any(|(name, _)| name == "metadata-version") {
        bail!("the wheel's core metadata has no Metadata-Version");
    }
    Ok(fields
        .into_iter()
        .filter(|(name, _)| name == "requires-dist")
        .map(|(_, value)| value)
        .collect())
}

/// Fetch `<wheel url>.metadata` from PyPI's file host, check its sha256 against the digest PyPI
/// published and read its `Requires-Dist`. Any failure is an error; a mismatch is an
/// [`IntegrityMismatch`].
pub(crate) async fn fetch_requires_dist(
    client: &reqwest::Client,
    files_origin: &reqwest::Url,
    metadata: &PypiCoreMetadata,
) -> Result<Vec<String>> {
    let mut url = super::validate_wheel_url(&metadata.wheel_url, files_origin)?;
    url.set_path(&format!("{}.metadata", url.path()));
    let bytes = download_tarball(client, &url, MAX_CORE_METADATA_BYTES)
        .await
        .map_err(|e| anyhow!("core metadata of {}: {e}", metadata.filename))?;
    use sha2::Digest;
    let actual = hex(&sha2::Sha256::digest(&bytes));
    if actual != metadata.sha256 {
        return Err(IntegrityMismatch(format!(
            "core metadata sha256 {actual} of {} does not match the digest PyPI published ({})",
            metadata.filename, metadata.sha256
        ))
        .into());
    }
    requires_dist_from_core_metadata(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_dist_is_read_from_the_header_block_only() {
        let metadata = b"Metadata-Version: 2.1\r\nName: requests\r\nrequires-dist: idna (<4,>=2.5)\r\nRequires-Dist: PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'\r\n\r\nRequires-Dist: not-a-header\r\n";
        assert_eq!(
            requires_dist_from_core_metadata(metadata).unwrap(),
            vec![
                "idna (<4,>=2.5)".to_string(),
                "PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'".to_string()
            ]
        );
    }

    #[test]
    fn folded_fields_are_joined() {
        let metadata = b"Metadata-Version: 1.2\nDescription: long\n  text\nRequires-Dist: a;\n\tpython_version < \"3\"\n";
        assert_eq!(
            requires_dist_from_core_metadata(metadata).unwrap(),
            vec!["a; python_version < \"3\"".to_string()]
        );
    }

    #[test]
    fn metadata_without_requires_dist_declares_none() {
        let metadata = b"Metadata-Version: 2.1\nName: p\n";
        assert!(
            requires_dist_from_core_metadata(metadata)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn malformed_metadata_is_an_error() {
        for bad in [
            &b"<html>error</html>\n"[..],
            b"Name: p\nRequires-Dist: a\n",
            b"  continuation first\n",
            b"Metadata-Version: 2.1\n\xff\xfe\n",
        ] {
            assert!(
                requires_dist_from_core_metadata(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
