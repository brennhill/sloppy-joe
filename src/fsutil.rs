//! Small input helpers shared by parsers, registries and config: bounded file reads and
//! single-line XML value extraction.
use anyhow::Result;

/// Read a file with a size limit to prevent memory exhaustion on huge files.
pub(crate) fn read_file_limited(path: &std::path::Path, max_bytes: u64) -> Result<String> {
    let bytes = read_bytes_limited(path, max_bytes)?;
    String::from_utf8(bytes)
        .map_err(|e| anyhow::anyhow!("Failed to decode {} as UTF-8: {}", path.display(), e))
}

/// Read raw bytes from a regular file with a hard size limit.
#[cfg(unix)]
pub(crate) fn read_bytes_limited(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            anyhow::bail!("Refusing to read symlinked file: {}", path.display())
        }
        Err(err) => return Err(err.into()),
    };

    let meta = file.metadata()?;
    if !meta.is_file() {
        anyhow::bail!("Refusing to read non-regular file: {}", path.display());
    }
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("File too large: {} bytes (max {})", bytes.len(), max_bytes);
    }
    Ok(bytes)
}

/// Read raw bytes from a regular file with a hard size limit.
#[cfg(not(unix))]
pub(crate) fn read_bytes_limited(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>> {
    use std::io::Read;

    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("Refusing to read symlinked file: {}", path.display());
    }
    if !meta.file_type().is_file() {
        anyhow::bail!("Refusing to read non-regular file: {}", path.display());
    }

    let file = std::fs::File::open(path)?;
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("File too large: {} bytes (max {})", bytes.len(), max_bytes);
    }
    Ok(bytes)
}

/// Maximum file size for manifest/lockfile parsing (100 MB).
pub(crate) const MAX_MANIFEST_BYTES: u64 = 100 * 1024 * 1024;

/// Shared XML value extractor: `<tag>value</tag>` on a single line.
/// Searches for the close tag starting AFTER the open tag to avoid
/// matching a close tag that appears before the open tag.
pub(crate) fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = line.find(&open)? + open.len();
    let end = line[start..].find(&close).map(|i| i + start)?;
    Some(line[start..end].to_string())
}
