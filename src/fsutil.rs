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

/// Fail closed on line terminators Rust's `str::lines()` does not split on but the tools that
/// read these files do (pip, npm's ini parser, `configparser` and Python's tokenizer split on a
/// lone `\r`; Python's `splitlines()` also on `\x0b \x0c \x1c-\x1e \x85 U+2028 U+2029`). Text
/// after one would be visible to the tool and invisible to the scan.
pub(crate) fn reject_unmodeled_line_breaks(content: &str, path: &std::path::Path) -> Result<()> {
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        let lone_cr = c == '\r' && chars.peek() != Some(&'\n');
        if lone_cr
            || matches!(
                c,
                '\x0b' | '\x0c' | '\x1c'..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
            )
        {
            anyhow::bail!(
                "Unsupported line terminator (U+{:04X}) in {}: the tool that reads it splits lines differently than sloppy-joe, so the file cannot be scanned reliably. Fix: use \\n or \\r\\n line endings.",
                c as u32,
                path.display()
            );
        }
    }
    Ok(())
}

/// The key/value pairs of a `java.util.Properties` file. Decoded as ISO-8859-1, split on `\n`,
/// `\r` or `\r\n`, with comments, `\` continuations, the `=`, `:` or whitespace separators and
/// backslash escapes handled as Java does.
pub(crate) fn parse_java_properties(bytes: &[u8]) -> Vec<(String, String)> {
    let text: String = bytes.iter().map(|&b| b as char).collect();
    let mut logical: Vec<String> = Vec::new();
    let mut physical = text.split(['\n', '\r']).peekable();
    while let Some(line) = physical.next() {
        let line = line.trim_start_matches([' ', '\t', '\x0c']);
        if line.is_empty() || line.starts_with(['#', '!']) {
            continue;
        }
        let mut joined = line.to_string();
        // An odd number of trailing backslashes continues the logical line.
        while joined.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1 {
            joined.pop();
            match physical.next() {
                Some(next) => joined.push_str(next.trim_start_matches([' ', '\t', '\x0c'])),
                None => break,
            }
        }
        logical.push(joined);
    }
    logical
        .iter()
        .map(|line| {
            let mut key = String::new();
            let mut chars = line.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => key.push(unescape(&mut chars)),
                    '=' | ':' | ' ' | '\t' | '\x0c' => break,
                    _ => key.push(c),
                }
            }
            let rest: String = chars.collect();
            let rest = rest.trim_start_matches([' ', '\t', '\x0c']);
            let rest = rest
                .strip_prefix(['=', ':'])
                .map_or(rest, |r| r.trim_start_matches([' ', '\t', '\x0c']));
            let mut value = String::new();
            let mut chars = rest.chars().peekable();
            while let Some(c) = chars.next() {
                value.push(if c == '\\' { unescape(&mut chars) } else { c });
            }
            (key, value)
        })
        .collect()
}

fn unescape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> char {
    match chars.next() {
        Some('u') => {
            let hex: String = chars.by_ref().take(4).collect();
            u32::from_str_radix(&hex, 16)
                .ok()
                .and_then(char::from_u32)
                .unwrap_or('\u{fffd}')
        }
        Some('t') => '\t',
        Some('n') => '\n',
        Some('r') => '\r',
        Some('f') => '\x0c',
        Some(other) => other,
        None => '\\',
    }
}

#[cfg(test)]
mod line_tests {
    use super::*;

    #[test]
    fn lone_carriage_returns_and_exotic_breaks_are_rejected() {
        let path = std::path::Path::new("f");
        assert!(reject_unmodeled_line_breaks("a\nb\r\nc", path).is_ok());
        for bad in ["a\rb", "a\x0cb", "a\u{2028}b", "# c\revil", "a\x0bb"] {
            assert!(reject_unmodeled_line_breaks(bad, path).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn java_properties_follow_javas_separators_and_escapes() {
        let props = parse_java_properties(
            b"# c \xe9\ndistributionUrl:https\\://evil.example/g.zip\nb   two\rc=3\nd=a\\\n   b\n\\u0065=x\n",
        );
        let get = |k: &str| {
            props
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("distributionUrl"), Some("https://evil.example/g.zip"));
        assert_eq!(get("b"), Some("two"));
        assert_eq!(get("c"), Some("3"));
        assert_eq!(get("d"), Some("ab"));
        assert_eq!(get("e"), Some("x"));
    }
}
