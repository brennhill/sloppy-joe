//! The lines `site` acts on in `*.pth` and `*.start` files.

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

fn logical_lines(content: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(content)
        .lines()
        .map(str::to_string)
        .collect()
}

pub(super) fn pth_lines(content: &[u8]) -> PthLines {
    let mut found = PthLines::default();
    for raw in logical_lines(content) {
        let line = raw.trim_end();
        if line.trim_start().is_empty() || line.starts_with('#') {
            continue;
        }
        if is_import(line) {
            found.imports.push(shown(line));
        } else {
            found.paths.push(shown(line));
        }
    }
    found
}

/// Entry points of a `.start` file: every non-blank line not starting `#`.
pub(super) fn start_entries(content: &[u8]) -> Vec<String> {
    logical_lines(content)
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(shown)
        .collect()
}
