//! requirements.txt index options (`--index-url`, `-i`, `--extra-index-url`) choose where
//! pip downloads from. A non-allowlisted index in any requirements file must block, or the
//! scanner vets the public PyPI package while pip installs from the attacker's index.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-reqidx-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn preflight_with(dir: &std::path::Path, config: &config::SloppyJoeConfig) -> Result<Vec<Issue>> {
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), config)?;
    preflight_project_inputs(dir, &specs, config)
}

fn trusting(urls: &[&str]) -> config::SloppyJoeConfig {
    let mut config = config::SloppyJoeConfig::default();
    config.trusted_indexes.insert(
        "pypi".to_string(),
        urls.iter()
            .map(|url| config::normalize_python_index_url(url))
            .collect(),
    );
    config
}

fn assert_untrusted_index(err: &anyhow::Error, url: &str) {
    let text = format!("{err:#}");
    assert!(
        text.contains(checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE),
        "error must name the check: {text}"
    );
    assert!(text.contains(url), "error must name the index: {text}");
    assert!(text.contains("trusted_indexes.pypi"), "{text}");
}

#[test]
fn unhashed_requirements_with_untrusted_index_options_block() {
    for line in [
        "--index-url https://evil.example/simple",
        "--index-url=https://evil.example/simple",
        "-i https://evil.example/simple",
        "--extra-index-url https://evil.example/simple",
        "--extra-index-url=https://evil.example/simple",
    ] {
        let dir = unique_dir();
        std::fs::write(
            dir.join("requirements.txt"),
            format!("{line}\nrequests==2.32.3\n"),
        )
        .unwrap();
        let err = preflight_with(&dir, &config::SloppyJoeConfig::default())
            .expect_err(&format!("untrusted index must block: {line}"));
        assert_untrusted_index(&err, "https://evil.example/simple");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn untrusted_index_in_included_requirement_or_constraint_file_blocks() {
    for directive in ["-r base.txt", "-c constraints.txt"] {
        let dir = unique_dir();
        std::fs::write(
            dir.join("requirements.txt"),
            format!("{directive}\nrequests==2.32.3\n"),
        )
        .unwrap();
        let target = directive.split_whitespace().nth(1).unwrap();
        std::fs::write(
            dir.join(target),
            "--extra-index-url https://evil.example/simple\nurllib3==2.2.0\n",
        )
        .unwrap();
        let err = preflight_with(&dir, &config::SloppyJoeConfig::default())
            .expect_err(&format!("included untrusted index must block: {directive}"));
        assert_untrusted_index(&err, "https://evil.example/simple");
        assert!(format!("{err:#}").contains(target), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn untrusted_index_in_nested_requirements_directory_blocks() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("requirements")).unwrap();
    std::fs::write(
        dir.join("requirements/dev.txt"),
        "-i https://evil.example/simple/\nrequests==2.32.3\n",
    )
    .unwrap();
    let err = preflight_with(&dir, &config::SloppyJoeConfig::default())
        .expect_err("requirements/*.txt index options must be checked too");
    assert_untrusted_index(&err, "https://evil.example/simple");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn default_pypi_index_is_allowed_without_config() {
    for line in [
        "--index-url https://pypi.org/simple",
        "--index-url https://pypi.org/simple/",
        "--extra-index-url https://PyPI.org/simple",
    ] {
        let dir = unique_dir();
        std::fs::write(
            dir.join("requirements.txt"),
            format!("{line}\nrequests==2.32.3\n"),
        )
        .unwrap();
        preflight_with(&dir, &config::SloppyJoeConfig::default())
            .unwrap_or_else(|err| panic!("{line}: {err:#}"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn allowlisted_index_is_accepted_and_near_misses_are_not() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("requirements.txt"),
        "--extra-index-url https://download.pytorch.org/whl/cu124/\ntorch==2.4.0\n",
    )
    .unwrap();
    preflight_with(&dir, &trusting(&["https://download.pytorch.org/whl/cu124"]))
        .expect("exact allowlisted index must pass");
    let err = preflight_with(&dir, &trusting(&["https://download.pytorch.org/whl"]))
        .expect_err("path-prefix trust is not allowed");
    assert_untrusted_index(&err, "https://download.pytorch.org/whl/cu124");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hash_locked_requirements_name_the_check_too() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("requirements.txt"),
        "--index-url https://pypi.org/simple\n--extra-index-url https://evil.example/simple\nrequests==2.32.3 \\\n    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
    )
    .unwrap();
    let err = preflight_with(&dir, &config::SloppyJoeConfig::default())
        .expect_err("hash-locked requirements with an untrusted index must block");
    assert_untrusted_index(&err, "https://evil.example/simple");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn other_pip_source_options_still_fail_closed() {
    for line in [
        "--find-links https://evil.example/wheels",
        "--find-links=https://evil.example/wheels",
        "-f https://evil.example/wheels",
        "--no-index",
        "--trusted-host evil.example",
        "--index-url ftp://evil.example/simple",
        "requests==2.32.3 --index-url https://evil.example/simple",
        "requests==2.32.3 --extra-index-url=https://evil.example/simple",
    ] {
        let dir = unique_dir();
        std::fs::write(
            dir.join("requirements.txt"),
            format!("{line}\nurllib3==2.2.0\n"),
        )
        .unwrap();
        let preflight = preflight_with(&dir, &config::SloppyJoeConfig::default());
        let parsed = parsers::requirements::parse_file(&dir.join("requirements.txt"), &dir);
        assert!(
            preflight.is_err() || parsed.is_err(),
            "must fail closed: {line}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
