//! Baseline of existing violations: it may only shrink.

use super::*;

#[derive(Default, Debug)]
pub(super) struct Baseline {
    pub(super) layer: Vec<String>,
    pub(super) file_lines: BTreeMap<String, usize>,
    pub(super) complexity: BTreeMap<String, usize>,
    pub(super) exists: bool,
}

pub(super) fn baseline_path() -> PathBuf {
    repo_root().join("tests").join("architecture_baseline.txt")
}

pub(super) fn load_baseline() -> Baseline {
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

pub(super) fn write_baseline(measures: &Measures) {
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

pub(super) fn update_mode() -> bool {
    std::env::var_os("UPDATE_ARCH_BASELINE").is_some()
}

/// `(worse, stale)` for a numeric measure: worse = new or grown; stale = shrunk or resolved.
pub(super) fn compare_numbers(
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

pub(super) fn compare_layers(
    current: &[String],
    baseline: &[String],
) -> (Vec<String>, Vec<String>) {
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

pub(super) fn all_comparisons(
    measures: &Measures,
    baseline: &Baseline,
) -> (Vec<String>, Vec<String>) {
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

pub(super) fn fail_if_any(worse: Vec<String>, stale: Vec<String>) {
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
