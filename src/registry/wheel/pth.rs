//! The lines `site` acts on in `*.pth` and `*.start` files.
//!
//! Python versions read these files differently: 3.10-3.11 split on
//! universal newlines (`\n`, `\r`, `\r\n`) in the locale encoding; 3.12+
//! decode UTF-8 after an optional BOM (falling back to the locale encoding)
//! and split with `str.splitlines` (also `\x0b \x0c \x1c-\x1e \x85 U+2028
//! U+2029`); 3.15 strips every line with `str.strip` before testing for
//! `import`. Each file is read every way at once: decoded as UTF-8 and as
//! Latin-1 (where byte 0x85 is NEL), BOM removed, split on every Python line
//! break, and a line is an import line if it starts `import ` or `import\t`
//! before or after stripping. Every line any version executes is therefore
//! found; a line no version executes may be reported too (fail closed).

pub(super) const MAX_SHOWN_LINE_CHARS: usize = 160;

/// What a `.pth` file does at startup.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PthLines {
    /// Lines `site` executes (`import ` or `import<TAB>` first).
    pub imports: Vec<String>,
    /// Lines `site` appends to `sys.path`.
    pub paths: Vec<String>,
}

fn shown(line: &str) -> String {
    line.chars().take(MAX_SHOWN_LINE_CHARS).collect()
}

fn is_import(line: &str) -> bool {
    line.starts_with("import ") || line.starts_with("import\t")
}

/// `str.isspace`: Unicode whitespace plus the separators `\x1c`-`\x1f`.
fn is_python_whitespace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.splitlines` boundaries (`\r\n` splits as `\r` then an empty line,
/// which is skipped as blank).
fn is_python_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\x0b' | '\x0c' | '\x1c'..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

fn python_strip(line: &str) -> &str {
    line.trim_matches(is_python_whitespace)
}

/// Every line of `content` under each decoding Python may use, in order,
/// without duplicates.
fn logical_lines(content: &[u8]) -> Vec<String> {
    let body = content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(content);
    let utf8 = String::from_utf8_lossy(body).into_owned();
    let latin1: String = body.iter().map(|&b| char::from(b)).collect();
    let mut seen = std::collections::HashSet::new();
    let mut lines: Vec<String> = Vec::new();
    for text in [utf8, latin1] {
        for line in text.split(is_python_line_break) {
            if seen.insert(line.to_string()) {
                lines.push(line.to_string());
            }
        }
    }
    lines
}

pub(super) fn pth_lines(content: &[u8]) -> PthLines {
    let mut found = PthLines::default();
    for raw in logical_lines(content) {
        let line = python_strip(&raw);
        if line.is_empty() {
            continue;
        }
        if is_import(&raw) || is_import(line) {
            found.imports.push(shown(line));
        } else if !raw.starts_with('#') {
            // Before 3.15 only a `#` in the first column starts a comment.
            found.paths.push(shown(line));
        }
    }
    found.imports.dedup();
    found.paths.dedup();
    found
}

/// Entry points of a `.start` file: every non-blank line not starting `#`.
pub(super) fn start_entries(content: &[u8]) -> Vec<String> {
    let mut entries: Vec<String> = logical_lines(content)
        .iter()
        .map(|line| python_strip(line))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(shown)
        .collect();
    entries.dedup();
    entries
}
