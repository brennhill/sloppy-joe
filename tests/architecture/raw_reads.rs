//! Raw reads of repo-controlled files outside the untrusted-read gateway
//! (docs/specs/untrusted-input-hardening.md, criterion C).
//!
//! Non-test code in `parsers`, `lockfiles` and `ecosystems` reads manifests, lockfiles and tool
//! config through `crate::untrusted`, which refuses input the scan cannot model. A direct read,
//! or a hand-written split into lines, bypasses those refusals. Existing sites are baselined per
//! file and may only shrink; a new site is never baselined.

use super::*;

const RAW_READS: &[&str] = &[
    "read_to_string(",
    "fs::read(",
    "File::open(",
    "OpenOptions::new(",
    "read_file_limited(",
    "read_bytes_limited(",
    "read_line_oriented_limited(",
];

const LINE_SPLITS: &[&str] = &[".lines()", ".split_terminator(", ".split('\\n')"];

const SCOPED_MODULES: &[&str] = &["parsers", "lockfiles", "ecosystems"];

fn in_scope(file: &SourceFile) -> bool {
    !file.is_test && SCOPED_MODULES.contains(&file.module.as_str())
}

fn occurrences(code: &str, patterns: &[&str]) -> usize {
    patterns
        .iter()
        .map(|pattern| code.matches(pattern).count())
        .sum()
}

/// `(raw reads per file, line splits per file)`, files with none omitted.
pub(super) fn measure_raw_reads(
    files: &[SourceFile],
) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
    let mut reads = BTreeMap::new();
    let mut splits = BTreeMap::new();
    for file in files.iter().filter(|file| in_scope(file)) {
        let read_count = occurrences(&file.code, RAW_READS);
        if read_count > 0 {
            reads.insert(file.rel.clone(), read_count);
        }
        let split_count = occurrences(&file.code, LINE_SPLITS);
        if split_count > 0 {
            splits.insert(file.rel.clone(), split_count);
        }
    }
    (reads, splits)
}

fn with_injected(target: &str, code: &str) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
    let mut files = load_sources();
    let entry = files
        .iter_mut()
        .find(|f| f.rel == target)
        .unwrap_or_else(|| panic!("{target} is not a source file"));
    entry.code.push_str(code);
    measure_raw_reads(&files)
}

#[test]
fn new_raw_reads_in_scoped_modules_are_counted() {
    let (before, _) = measure_raw_reads(&load_sources());
    for (target, code) in [
        (
            "src/parsers/go_mod.rs",
            "\nfn leak(p: &std::path::Path) { let _ = std::fs::read_to_string(p); }\n",
        ),
        (
            "src/lockfiles/gradle.rs",
            "\nfn leak(p: &std::path::Path) { let _ = std::fs::read(p); }\n",
        ),
        (
            "src/ecosystems/go.rs",
            "\nfn leak(p: &std::path::Path) { let _ = std::fs::File::open(p); }\n",
        ),
        (
            "src/parsers/go_mod.rs",
            "\nfn leak(p: &std::path::Path) { let _ = crate::fsutil::read_file_limited(p, 1); }\n",
        ),
        (
            "src/lockfiles/gradle.rs",
            "\nfn leak(p: &std::path::Path) { let _ = crate::fsutil::read_bytes_limited(p, 1); }\n",
        ),
        (
            "src/parsers/go_mod.rs",
            "\nfn leak(p: &std::path::Path) { let _ = crate::fsutil::read_line_oriented_limited(p, 1); }\n",
        ),
    ] {
        let (after, _) = with_injected(target, code);
        assert!(
            after.get(target).copied().unwrap_or(0) > before.get(target).copied().unwrap_or(0),
            "{target}: {code}"
        );
    }
}

#[test]
fn new_line_splits_in_scoped_modules_are_counted() {
    let (_, before) = measure_raw_reads(&load_sources());
    for code in [
        "\nfn leak(s: &str) { for _ in s.lines() {} }\n",
        "\nfn leak(s: &str) { for _ in s.split('\\n') {} }\n",
        "\nfn leak(s: &str) { for _ in s.split_terminator('\\n') {} }\n",
    ] {
        let target = "src/parsers/go_mod.rs";
        let (_, after) = with_injected(target, code);
        assert!(
            after.get(target).copied().unwrap_or(0) > before.get(target).copied().unwrap_or(0),
            "{code}"
        );
    }
}

#[test]
fn the_gateway_itself_and_out_of_scope_modules_are_not_counted() {
    let files = load_sources();
    let (reads, splits) = measure_raw_reads(&files);
    for key in reads.keys().chain(splits.keys()) {
        assert!(
            SCOPED_MODULES
                .iter()
                .any(|module| key.starts_with(&format!("src/{module}/"))),
            "{key} is outside the scoped modules"
        );
    }
    let (reads, splits) = with_injected(
        "src/untrusted.rs",
        "\nfn ok(p: &std::path::Path) { let _ = std::fs::read_to_string(p); }\n",
    );
    assert!(!reads.contains_key("src/untrusted.rs") && !splits.contains_key("src/untrusted.rs"));
    let (reads, _) = with_injected(
        "src/config/mod.rs",
        "\nfn ok(p: &std::path::Path) { let _ = std::fs::read_to_string(p); }\n",
    );
    assert!(!reads.contains_key("src/config/mod.rs"));
}

#[test]
fn test_only_files_are_not_counted() {
    let files = load_sources();
    let counted = measure_raw_reads(&files).0;
    for file in files.iter().filter(|file| file.is_test) {
        assert!(!counted.contains_key(&file.rel), "{}", file.rel);
    }
}
