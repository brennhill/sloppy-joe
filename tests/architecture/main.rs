//! Architecture guardrails (docs/specs/architecture-guardrails.md).
//!
//! Pure source scanning: layer direction, file size, per-function cyclomatic complexity and
//! ecosystem placement (never baselined). Existing violations live in `tests/architecture_baseline.txt` and may only
//! shrink. Rewrite the baseline with smaller values via
//! `UPDATE_ARCH_BASELINE=1 cargo test --test architecture`.

mod baseline;
mod bypass_rules;
mod gap_tests;
mod isolation;
mod items;
mod roots;
mod scanner_tests;
mod test_files;

use baseline::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_FILE_LINES: usize = 800;
const MAX_COMPLEXITY: usize = 15;
const PLACEMENT_KEY_PREFIX: &str = "project-input-kind ";

// ---------------------------------------------------------------- layers

const FOUNDATION: &[&str] = &[
    "ecosystem",
    "cache",
    "version",
    "report",
    "names",
    "http",
    "fsutil",
];
const CONFIG: &[&str] = &["config", "npm_config"];
const ORCHESTRATION: &[&str] = &["bootstrap", "engine", "lib", "main"];

fn layer_of(module: &str) -> Option<&'static str> {
    if FOUNDATION.contains(&module) {
        return Some("foundation");
    }
    if CONFIG.contains(&module) {
        return Some("config");
    }
    if ORCHESTRATION.contains(&module) {
        return Some("orchestration");
    }
    match module {
        "parsers" => Some("parsers"),
        "registry" => Some("registry"),
        "lockfiles" => Some("lockfiles"),
        "checks" => Some("checks"),
        "project" => Some("project"),
        "ecosystems" => Some("ecosystems"),
        _ => None,
    }
}

fn layer_may_depend_on(from: &str, to: &str) -> bool {
    let allowed: &[&str] = match from {
        "foundation" => &["foundation"],
        "config" => &["foundation", "config"],
        "parsers" => &["foundation", "config", "parsers"],
        "registry" => &["foundation", "config", "registry"],
        "lockfiles" => &["foundation", "config", "parsers", "lockfiles"],
        "checks" => &[
            "foundation",
            "config",
            "parsers",
            "lockfiles",
            "registry",
            "checks",
        ],
        "project" => &["foundation", "config", "parsers", "lockfiles", "project"],
        "ecosystems" => &[
            "foundation",
            "config",
            "parsers",
            "registry",
            "lockfiles",
            "checks",
            "project",
            "ecosystems",
        ],
        "orchestration" => return true,
        _ => &[],
    };
    allowed.contains(&to)
}

// ---------------------------------------------------------------- files

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

struct SourceFile {
    /// `src/parsers/jvm.rs`
    rel: String,
    /// Top-level module: `parsers`, `lib`, `config`, ...
    module: String,
    raw_lines: usize,
    is_test: bool,
    /// Comments and literals removed, inline test module cut off.
    code: String,
}

/// Physical lines as rustc sees them: `\n`, `\r\n`, a lone `\r` and the Unicode line separators
/// are all whitespace to the compiler, so none may hide lines from the size cap.
fn count_lines(content: &str) -> usize {
    let mut lines = 0;
    let mut pending = false;
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(
            c,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        ) {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            lines += 1;
            pending = false;
        } else {
            pending = true;
        }
    }
    lines + usize::from(pending)
}

fn load_sources() -> Vec<SourceFile> {
    let root = repo_root();
    let mut paths = Vec::new();
    collect_rs(&root.join("src"), &mut paths);
    let raw: Vec<(String, String)> = paths
        .iter()
        .map(|path| {
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, std::fs::read_to_string(path).unwrap())
        })
        .collect();
    let test_files = test_files::test_only_files(&raw);
    raw.into_iter()
        .map(|(rel, content)| {
            let inside = rel.trim_start_matches("src/");
            let module = match inside.split_once('/') {
                Some((dir, _)) => dir.to_string(),
                None => inside.trim_end_matches(".rs").to_string(),
            };
            SourceFile {
                raw_lines: count_lines(&content),
                is_test: test_files.contains(&rel),
                code: cut_inline_tests(&strip(&content)),
                rel,
                module,
            }
        })
        .collect()
}

// ---------------------------------------------------------------- stripping

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Remove comments and the contents of string / char literals, keeping newlines and quotes.
fn strip(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if b[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            continue;
        }
        if (c == 'r' || (c == 'b' && next == Some('r')))
            && !out.chars().last().is_some_and(is_ident)
        {
            let mut j = i + if c == 'b' { 2 } else { 1 };
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                j += 1;
                out.push_str("\"\"");
                while j < b.len() {
                    if b[j] == '"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&'#')) {
                        j += 1 + hashes;
                        break;
                    }
                    if b[j] == '\n' {
                        out.push('\n');
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        if c == '"' {
            out.push_str("\"\"");
            i += 1;
            while i < b.len() {
                if b[i] == '\\' {
                    if b.get(i + 1) == Some(&'\n') {
                        out.push('\n');
                    }
                    i += 2;
                    continue;
                }
                if b[i] == '"' {
                    i += 1;
                    break;
                }
                if b[i] == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        if c == '\'' {
            if next == Some('\\') {
                let mut j = i + 2;
                while j < b.len() && b[j] != '\'' && j < i + 14 {
                    j += 1;
                }
                if b.get(j) == Some(&'\'') {
                    out.push_str("' '");
                    i = j + 1;
                    continue;
                }
            } else if b.get(i + 2) == Some(&'\'') && next != Some('\'') {
                out.push_str("' '");
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Drop every `#[cfg(test)]` item (module, function, `use`, constant, ...) and only those: it is
/// not production code, and code after it still is. An item ends at its closing brace or at a
/// `;` outside any bracket.
fn cut_inline_tests(code: &str) -> String {
    let marker = "#[cfg(test)]";
    let chars: Vec<(usize, char)> = code.char_indices().collect();
    let mut out = String::with_capacity(code.len());
    let mut at = 0;
    while let Some(found) = code[at..].find(marker) {
        let start = at + found;
        out.push_str(&code[at..start]);
        let (mut paren, mut brace) = (0i32, 0i32);
        let mut generic = false;
        let mut end = code.len();
        let begin = start + marker.len();
        for &(offset, c) in chars.iter().filter(|(offset, _)| *offset >= begin) {
            match c {
                '(' | '[' => paren += 1,
                ')' | ']' => paren -= 1,
                '<' if brace == 0 && paren == 0 => generic = true,
                '{' => brace += 1,
                '}' if brace == 0 && paren == 0 => {
                    // The parent's closing brace: the marked item was a field, variant or
                    // statement that ends here, not an item with a body.
                    end = offset;
                    break;
                }
                '}' => {
                    brace -= 1;
                    if brace == 0 && paren == 0 {
                        end = offset + 1;
                        break;
                    }
                }
                ';' if brace == 0 && paren == 0 => {
                    end = offset + 1;
                    break;
                }
                // A field or variant ends at its comma (generic arguments have commas too, so
                // those fall through to the parent's closing brace above).
                ',' if brace == 0 && paren == 0 && !generic => {
                    end = offset + 1;
                    break;
                }
                _ => {}
            }
        }
        at = end;
    }
    out.push_str(&code[at..]);
    out
}

// ---------------------------------------------------------------- measures

#[derive(Default, Debug)]
struct Measures {
    /// `src/parsers/x.rs -> registry`
    layer_edges: Vec<String>,
    /// file -> lines, only files above the cap
    file_lines: BTreeMap<String, usize>,
    /// `file::fn` -> complexity, only functions above the cap
    complexity: BTreeMap<String, usize>,
    /// placement counters
    placement: BTreeMap<String, usize>,
    /// Modules under src/ that the layer table does not know.
    unclassified: Vec<String>,
}

fn measure() -> Measures {
    let files = load_sources();
    let mut measures = Measures::default();
    let modules: Vec<String> = files
        .iter()
        .filter(|file| !file.is_test)
        .map(|file| file.module.clone())
        .collect();

    let root_exports = roots::root_export_modules(&files);

    for file in &files {
        if file.raw_lines > MAX_FILE_LINES {
            measures.file_lines.insert(file.rel.clone(), file.raw_lines);
        }
        if file.is_test {
            continue;
        }
        let Some(from_layer) = layer_of(&file.module) else {
            if !measures.unclassified.contains(&file.module) {
                measures.unclassified.push(file.module.clone());
            }
            continue;
        };
        for edge in roots::edges_of_file(file, from_layer, &modules, &root_exports) {
            if !measures.layer_edges.contains(&edge) {
                measures.layer_edges.push(edge);
            }
        }
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for (name, complexity) in function_complexities(&file.code) {
            let count = seen.entry(name.clone()).or_insert(0);
            *count += 1;
            if complexity > MAX_COMPLEXITY {
                let key = if *count == 1 {
                    format!("{}::{}", file.rel, name)
                } else {
                    format!("{}::{}#{}", file.rel, name, count)
                };
                measures.complexity.insert(key, complexity);
            }
        }
        // The kind table and the ecosystem plugins are where kinds are meant to be matched.
        let kind_uses = file.code.matches("ProjectInputKind::").count();
        if kind_uses > 0 && file.module != "ecosystems" && file.module != "project" {
            measures
                .placement
                .insert(format!("{PLACEMENT_KEY_PREFIX}{}", file.rel), kind_uses);
        }
    }
    measures.layer_edges.sort();
    measures
}

/// Modules named by `crate::<module>` (including `crate::{a, b::c}` groups).
fn crate_targets(code: &str) -> Vec<String> {
    let b: Vec<char> = code.chars().collect();
    let needle: Vec<char> = "crate::".chars().collect();
    let mut targets = Vec::new();
    let mut i = 0;
    while i + needle.len() <= b.len() {
        if b[i..i + needle.len()] == needle[..] && (i == 0 || !is_ident(b[i - 1])) {
            let mut j = i + needle.len();
            if b.get(j) == Some(&'{') {
                let mut depth = 0;
                let mut at_start = true;
                while j < b.len() {
                    match b[j] {
                        '{' => {
                            depth += 1;
                            at_start = depth == 1;
                        }
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        ',' if depth == 1 => at_start = true,
                        c if is_ident(c) && at_start && depth == 1 => {
                            let start = j;
                            while j < b.len() && is_ident(b[j]) {
                                j += 1;
                            }
                            targets.push(b[start..j].iter().collect());
                            at_start = false;
                            continue;
                        }
                        _ => {}
                    }
                    j += 1;
                }
            } else {
                let start = j;
                while j < b.len() && is_ident(b[j]) {
                    j += 1;
                }
                if j > start {
                    targets.push(b[start..j].iter().collect());
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    targets
}

/// `(function name, cyclomatic complexity)` for every function with a body, in source order.
fn function_complexities(code: &str) -> Vec<(String, usize)> {
    let b: Vec<char> = code.chars().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !is_ident(b[i]) || (i > 0 && is_ident(b[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_ident(b[i]) {
            i += 1;
        }
        if b[start..i].iter().collect::<String>() != "fn" {
            continue;
        }
        let mut j = i;
        while j < b.len() && b[j].is_whitespace() {
            j += 1;
        }
        let name_start = j;
        while j < b.len() && is_ident(b[j]) {
            j += 1;
        }
        if j == name_start || j == i {
            continue; // `fn(...)` pointer type or `fn` without a name
        }
        let name: String = b[name_start..j].iter().collect();
        // Find the body: first `{` (or `;`) outside parentheses and brackets.
        let mut depth = 0i32;
        let mut k = j;
        let mut body_start = None;
        while k < b.len() {
            match b[k] {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                ';' if depth == 0 => break,
                '{' if depth == 0 => {
                    body_start = Some(k);
                    break;
                }
                _ => {}
            }
            k += 1;
        }
        let Some(body_start) = body_start else {
            continue;
        };
        let mut braces = 0i32;
        let mut end = body_start;
        while end < b.len() {
            match b[end] {
                '{' => braces += 1,
                '}' => {
                    braces -= 1;
                    if braces == 0 {
                        break;
                    }
                }
                _ => {}
            }
            end += 1;
        }
        found.push((name, complexity(&b[body_start..end.min(b.len())])));
        // Keep scanning inside the body so nested functions are found too.
        i = j;
    }
    found.extend(items::initializer_complexities(&b));
    found
}

/// 1 + `if` / `while` / `for` / `loop` / `&&` / `||` + (match arms - 1) for each `match`.
fn complexity(b: &[char]) -> usize {
    let mut n = 1;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if is_ident(c) {
            let start = i;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            if start > 0 && is_ident(b[start - 1]) {
                continue;
            }
            let word: String = b[start..i].iter().collect();
            match word.as_str() {
                "if" | "while" | "for" | "loop" => n += 1,
                "match" => n += match_arms(b, i).saturating_sub(1),
                _ => {}
            }
            continue;
        }
        if (c == '&' || c == '|') && b.get(i + 1) == Some(&c) {
            if operand_before(b, i) {
                n += 1;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    n
}

/// Whether `&&` / `||` at `at` is a binary operator (and not a closure or a reference type).
fn operand_before(b: &[char], at: usize) -> bool {
    let mut p = at;
    while p > 0 && b[p - 1].is_whitespace() {
        p -= 1;
    }
    if p == 0 {
        return false;
    }
    let prev = b[p - 1];
    if !(is_ident(prev) || matches!(prev, ')' | ']' | '"' | '\'' | '?')) {
        return false;
    }
    let mut w = p;
    while w > 0 && is_ident(b[w - 1]) {
        w -= 1;
    }
    let word: String = b[w..p].iter().collect();
    !matches!(word.as_str(), "move" | "return" | "in")
}

/// Number of `=>` arms directly inside the block of the `match` whose keyword ends at `after`.
fn match_arms(b: &[char], after: usize) -> usize {
    let mut depth = 0i32;
    let mut k = after;
    while k < b.len() {
        match b[k] {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '{' if depth == 0 => break,
            _ => {}
        }
        k += 1;
    }
    let mut braces = 0i32;
    let mut parens = 0i32;
    let mut arms = 0;
    while k < b.len() {
        match b[k] {
            '{' => braces += 1,
            '}' => {
                braces -= 1;
                if braces == 0 {
                    break;
                }
            }
            '(' | '[' => parens += 1,
            ')' | ']' => parens -= 1,
            '=' if braces == 1 && parens == 0 && b.get(k + 1) == Some(&'>') => {
                arms += 1;
                k += 1;
            }
            _ => {}
        }
        k += 1;
    }
    arms
}

// ---------------------------------------------------------------- tests

#[test]
fn every_source_module_is_classified_into_a_layer() {
    let measures = measure();
    assert!(
        measures.unclassified.is_empty(),
        "classify these src/ modules in tests/architecture/ and docs/specs/architecture-guardrails.md: {:?}",
        measures.unclassified
    );
}

#[test]
fn layers_only_depend_downward() {
    if update_mode() {
        return;
    }
    let (worse, stale) = compare_layers(&measure().layer_edges, &load_baseline().layer);
    fail_if_any(worse, stale);
}

#[test]
fn files_stay_within_the_line_cap() {
    if update_mode() {
        return;
    }
    let (worse, stale) = compare_numbers(
        "file lines:",
        &measure().file_lines,
        &load_baseline().file_lines,
        Some(MAX_FILE_LINES),
    );
    fail_if_any(worse, stale);
}

#[test]
fn functions_stay_within_the_complexity_cap() {
    if update_mode() {
        return;
    }
    let (worse, stale) = compare_numbers(
        "complexity:",
        &measure().complexity,
        &load_baseline().complexity,
        Some(MAX_COMPLEXITY),
    );
    fail_if_any(worse, stale);
}

#[test]
fn ecosystem_matches_do_not_spread() {
    if update_mode() {
        return;
    }
    let worse: Vec<String> = measure()
        .placement
        .iter()
        .map(|(key, uses)| {
            format!(
                "placement: {key} matches on ProjectInputKind {uses} time(s); only src/project.rs and src/ecosystems/ may. Move the logic into the ecosystem plugin."
            )
        })
        .collect();
    fail_if_any(worse, Vec::new());
}

/// `UPDATE_ARCH_BASELINE=1 cargo test --test architecture` rewrites the baseline with smaller
/// values. It refuses to record anything that is worse than the existing baseline.
#[test]
fn update_baseline_when_requested() {
    if !update_mode() {
        return;
    }
    let measures = measure();
    let baseline = load_baseline();
    if baseline.exists {
        let (worse, _) = all_comparisons(&measures, &baseline);
        assert!(
            worse.is_empty(),
            "refusing to baseline new violations:\n  - {}",
            worse.join("\n  - ")
        );
    }
    write_baseline(&measures);
}

// ------------------------------------------- the scanner measures what it claims
