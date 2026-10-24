//! Architecture guardrails (docs/specs/architecture-guardrails.md).
//!
//! Pure source scanning: layer direction, file size, per-function cyclomatic complexity and
//! ecosystem placement (never baselined). Existing violations live in `tests/architecture_baseline.txt` and may only
//! shrink. Rewrite the baseline with smaller values via
//! `UPDATE_ARCH_BASELINE=1 cargo test --test architecture`.

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

fn is_test_file(rel: &str) -> bool {
    let mut parts = rel.rsplit('/');
    let name = parts.next().unwrap_or(rel);
    let in_test_dir = parts.any(|dir| dir == "tests" || dir.ends_with("_tests"));
    in_test_dir || name.ends_with("_tests.rs") || name == "tests.rs" || name.contains("test_utils")
}

fn load_sources() -> Vec<SourceFile> {
    let root = repo_root();
    let mut paths = Vec::new();
    collect_rs(&root.join("src"), &mut paths);
    paths
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let inside = rel.trim_start_matches("src/");
            let module = match inside.split_once('/') {
                Some((dir, _)) => dir.to_string(),
                None => inside.trim_end_matches(".rs").to_string(),
            };
            let content = std::fs::read_to_string(&path).unwrap();
            SourceFile {
                raw_lines: content.lines().count(),
                is_test: is_test_file(&rel),
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

/// Drop everything from the first inline `#[cfg(test)] mod name { ... }` onward.
fn cut_inline_tests(code: &str) -> String {
    let marker = "#[cfg(test)]";
    let mut search = 0;
    while let Some(found) = code[search..].find(marker) {
        let at = search + found;
        let rest = code[at + marker.len()..].trim_start();
        if let Some(after_mod) = rest.strip_prefix("mod ") {
            let name_len = after_mod.chars().take_while(|c| is_ident(*c)).count();
            if after_mod[name_len..].trim_start().starts_with('{') {
                return code[..at].to_string();
            }
        }
        search = at + marker.len();
    }
    code.to_string()
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
        for target in crate_targets(&file.code) {
            if !modules.contains(&target) {
                continue; // a root item such as `crate::Dependency`
            }
            let Some(to_layer) = layer_of(&target) else {
                continue;
            };
            if !layer_may_depend_on(from_layer, to_layer) {
                let edge = format!("{} -> {}", file.rel, target);
                if !measures.layer_edges.contains(&edge) {
                    measures.layer_edges.push(edge);
                }
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

// ---------------------------------------------------------------- baseline

#[derive(Default, Debug)]
struct Baseline {
    layer: Vec<String>,
    file_lines: BTreeMap<String, usize>,
    complexity: BTreeMap<String, usize>,
    exists: bool,
}

fn baseline_path() -> PathBuf {
    repo_root().join("tests").join("architecture_baseline.txt")
}

fn load_baseline() -> Baseline {
    let Ok(text) = std::fs::read_to_string(baseline_path()) else {
        return Baseline::default();
    };
    let mut baseline = Baseline {
        exists: true,
        ..Baseline::default()
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (kind, rest) = line.split_once(' ').expect("baseline line needs a kind");
        match kind {
            "layer" => baseline.layer.push(rest.to_string()),
            "file-lines" | "fn-complexity" => {
                let (key, value) = rest.rsplit_once(' ').expect("baseline line needs a value");
                let value: usize = value.parse().expect("baseline value must be a number");
                let map = match kind {
                    "file-lines" => &mut baseline.file_lines,
                    _ => &mut baseline.complexity,
                };
                map.insert(key.to_string(), value);
            }
            other => panic!("unknown baseline entry kind '{other}'"),
        }
    }
    baseline
}

fn write_baseline(measures: &Measures) {
    let mut out = String::from(
        "# Architecture baseline (docs/specs/architecture-guardrails.md).\n\
         # Existing violations only. Values may shrink, never grow.\n\
         # Tighten with: UPDATE_ARCH_BASELINE=1 cargo test --test architecture\n",
    );
    for edge in &measures.layer_edges {
        out.push_str(&format!("layer {edge}\n"));
    }
    for (file, lines) in &measures.file_lines {
        out.push_str(&format!("file-lines {file} {lines}\n"));
    }
    for (function, value) in &measures.complexity {
        out.push_str(&format!("fn-complexity {function} {value}\n"));
    }
    std::fs::write(baseline_path(), out).unwrap();
}

fn update_mode() -> bool {
    std::env::var_os("UPDATE_ARCH_BASELINE").is_some()
}

/// `(worse, stale)` for a numeric measure: worse = new or grown; stale = shrunk or resolved.
fn compare_numbers(
    what: &str,
    current: &BTreeMap<String, usize>,
    baseline: &BTreeMap<String, usize>,
    cap: Option<usize>,
) -> (Vec<String>, Vec<String>) {
    let mut worse = Vec::new();
    let mut stale = Vec::new();
    for (key, value) in current {
        match baseline.get(key) {
            None => worse.push(format!(
                "{what} {key} is {value}{} and is not in the baseline: fix it instead of baselining it",
                cap.map(|c| format!(" (cap {c})")).unwrap_or_default()
            )),
            Some(allowed) if value > allowed => {
                worse.push(format!("{what} {key} grew from {allowed} to {value}"))
            }
            Some(allowed) if value < allowed => stale.push(format!(
                "{what} {key} shrank from {allowed} to {value}: tighten the baseline"
            )),
            _ => {}
        }
    }
    for (key, allowed) in baseline {
        if !current.contains_key(key) {
            stale.push(format!(
                "{what} {key} (baseline {allowed}) is now within its limit: remove it from the baseline"
            ));
        }
    }
    (worse, stale)
}

fn compare_layers(current: &[String], baseline: &[String]) -> (Vec<String>, Vec<String>) {
    let worse = current
        .iter()
        .filter(|edge| !baseline.contains(edge))
        .map(|edge| format!("layer violation not in the baseline: {edge}"))
        .collect();
    let stale = baseline
        .iter()
        .filter(|edge| !current.contains(edge))
        .map(|edge| format!("layer violation resolved: remove '{edge}' from the baseline"))
        .collect();
    (worse, stale)
}

fn all_comparisons(measures: &Measures, baseline: &Baseline) -> (Vec<String>, Vec<String>) {
    let mut worse = Vec::new();
    let mut stale = Vec::new();
    let sets = [
        compare_layers(&measures.layer_edges, &baseline.layer),
        compare_numbers(
            "file lines:",
            &measures.file_lines,
            &baseline.file_lines,
            Some(MAX_FILE_LINES),
        ),
        compare_numbers(
            "complexity:",
            &measures.complexity,
            &baseline.complexity,
            Some(MAX_COMPLEXITY),
        ),
    ];
    for (w, s) in sets {
        worse.extend(w);
        stale.extend(s);
    }
    (worse, stale)
}

fn fail_if_any(worse: Vec<String>, stale: Vec<String>) {
    let mut message = String::new();
    if !worse.is_empty() {
        message.push_str("\nArchitecture guardrail violations:\n");
        for line in &worse {
            message.push_str(&format!("  - {line}\n"));
        }
    }
    if !stale.is_empty() {
        message.push_str(
            "\nBaseline is looser than the code (ratchet it down with UPDATE_ARCH_BASELINE=1 cargo test --test architecture):\n",
        );
        for line in &stale {
            message.push_str(&format!("  - {line}\n"));
        }
    }
    assert!(message.is_empty(), "{message}");
}

// ---------------------------------------------------------------- tests

#[test]
fn every_source_module_is_classified_into_a_layer() {
    let measures = measure();
    assert!(
        measures.unclassified.is_empty(),
        "classify these src/ modules in tests/architecture.rs and docs/specs/architecture-guardrails.md: {:?}",
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

/// The ecosystem plugin modules: every `src/ecosystems/<name>.rs` or `src/ecosystems/<name>/`
/// except the shared helpers.
fn plugin_names() -> Vec<String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(repo_root().join("src").join("ecosystems")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        if !["mod", "common", "tests"].contains(&name.as_str()) {
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Whether `code` contains `path` followed by a non-identifier character.
fn mentions_path(code: &str, path: &str) -> bool {
    code.match_indices(path).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + path.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Isolation violations among `(relative path, code)` pairs: code outside `src/ecosystems/`
/// naming a concrete plugin, and a plugin importing a sibling plugin.
fn isolation_violations(files: &[(String, String)], plugins: &[String]) -> Vec<String> {
    let mut violations = Vec::new();
    for (rel, code) in files {
        // `ecosystems/mod.rs` is the registry: it names every plugin by design.
        if rel == "src/ecosystems/mod.rs" {
            continue;
        }
        let owner = rel
            .strip_prefix("src/ecosystems/")
            .map(|rest| rest.split(['/', '.']).next().unwrap().to_string());
        for plugin in plugins {
            let reaches_in = mentions_path(code, &format!("ecosystems::{plugin}"));
            match owner.as_deref() {
                None if reaches_in => violations.push(format!(
                    "{rel} reaches into ecosystems::{plugin}; go through the EcosystemSupport trait"
                )),
                Some(own) if own != plugin => {
                    let sibling = reaches_in
                        || mentions_path(code, &format!("super::super::{plugin}"))
                        || (rel.matches('/').count() == 2
                            && mentions_path(code, &format!("super::{plugin}")));
                    if sibling {
                        violations.push(format!(
                            "{rel} (ecosystem {own}) imports ecosystem {plugin}; share code through ecosystems::common"
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    violations
}

#[test]
fn ecosystem_plugins_are_isolated() {
    let plugins = plugin_names();
    assert!(plugins.len() >= 8, "found plugins {plugins:?}");
    let files: Vec<(String, String)> = load_sources()
        .into_iter()
        .filter(|f| !f.is_test)
        .map(|f| (f.rel, f.code))
        .collect();
    let violations = isolation_violations(&files, &plugins);
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn isolation_rule_flags_engine_and_sibling_imports() {
    let plugins = vec!["cargo".to_string(), "go".to_string()];
    let files = vec![
        (
            "src/engine/scan.rs".to_string(),
            "use crate::ecosystems::cargo::Cargo;".to_string(),
        ),
        (
            "src/ecosystems/go.rs".to_string(),
            "use super::cargo::helper;".to_string(),
        ),
        (
            "src/ecosystems/go/inner.rs".to_string(),
            "use super::super::cargo::helper;".to_string(),
        ),
        (
            "src/ecosystems/cargo/mod.rs".to_string(),
            "use super::common::x; use crate::ecosystems::first_existing_lockfile;".to_string(),
        ),
        (
            "src/engine/ok.rs".to_string(),
            "use crate::ecosystems::bind;".to_string(),
        ),
    ];
    let violations = isolation_violations(&files, &plugins);
    assert_eq!(violations.len(), 3, "{violations:?}");
    assert!(violations[0].contains("src/engine/scan.rs"));
}

#[test]
fn scanner_finds_whole_path_mentions() {
    assert!(mentions_path("use a::js;", "a::js"));
    assert!(!mentions_path("use a::json;", "a::js"));
    assert!(!mentions_path("use xa::js;", "a::js"));
}

#[test]
fn scanner_ignores_comments_and_literals() {
    let code = strip("fn a() { // if if if\n let s = \"if && ||\"; let c = '{'; /* for */ }");
    let f = function_complexities(&code);
    assert_eq!(f, vec![("a".to_string(), 1)]);
}

#[test]
fn scanner_counts_branches_boolean_operators_and_match_arms() {
    let code = strip(
        "fn a(x: i32) -> i32 { if x > 0 && x < 9 || x == 20 { 1 } else if x < 0 { 2 } else { \
         match x { 1 => 1, 2 => 2, _ => 3 } } }",
    );
    // 1 + if + && + || + else-if + (3 arms - 1)
    assert_eq!(function_complexities(&code), vec![("a".to_string(), 7)]);
}

#[test]
fn scanner_does_not_count_closures_or_reference_types_as_operators() {
    let code = strip("fn a(v: &&str) { let f = || 1; let g = move || 2; let h = |&&x| x; }");
    assert_eq!(function_complexities(&code), vec![("a".to_string(), 1)]);
}

#[test]
fn scanner_finds_crate_targets_in_paths_and_groups() {
    let targets = crate_targets(
        "use crate::registry::Registry; use crate::{checks::x, cache}; crate::Dependency",
    );
    assert_eq!(targets, vec!["registry", "checks", "cache", "Dependency"]);
}

#[test]
fn inline_test_modules_are_cut() {
    let code = cut_inline_tests("fn a() {}\n#[cfg(test)]\nmod tests { fn b() {} }");
    assert!(code.contains("fn a") && !code.contains("fn b"));
    let kept = cut_inline_tests("#[cfg(test)]\n#[path = \"x\"]\nmod x;\nfn c() {}");
    assert!(kept.contains("fn c"));
}
