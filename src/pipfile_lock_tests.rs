//! Pipfile.lock is reconciled with the Pipfile in both directions: every
//! Pipfile package (default, develop, and custom categories) must be locked in
//! the matching section with an exact `==` pin and hashes; lock-only entries
//! are transitives and are scanned; entries with git/path/file/editable or
//! non-PyPI index provenance block, as do lock sources outside the Python
//! index policy.
use super::*;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const HASH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-pipfile-lock-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const PIPFILE: &str = r#"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[packages]
requests = "==2.32.3"
flask = ">=3.0"

[dev-packages]
pytest = "*"

[docs]
mkdocs = "==1.6.0"
"#;

fn entry(version: &str) -> serde_json::Value {
    serde_json::json!({"hashes": [HASH], "index": "pypi", "version": version})
}

fn base_lock() -> serde_json::Value {
    serde_json::json!({
        "_meta": {
            "hash": {"sha256": "x"},
            "pipfile-spec": 6,
            "requires": {},
            "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]
        },
        "default": {
            "requests": entry("==2.32.3"),
            "flask": entry("==3.0.3"),
            "idna": entry("==3.10")
        },
        "develop": {
            "pytest": entry("==8.3.3"),
            "pluggy": entry("==1.5.0")
        },
        "docs": {
            "mkdocs": entry("==1.6.0")
        }
    })
}

fn write_project(pipfile: &str, lock: Option<&serde_json::Value>) -> std::path::PathBuf {
    let dir = unique_dir();
    std::fs::write(dir.join("Pipfile"), pipfile).unwrap();
    if let Some(lock) = lock {
        std::fs::write(
            dir.join("Pipfile.lock"),
            serde_json::to_string_pretty(lock).unwrap(),
        )
        .unwrap();
    }
    dir
}

fn preflight_with(dir: &std::path::Path, config: &config::SloppyJoeConfig) -> Result<Vec<Issue>> {
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), config)?;
    assert!(
        specs
            .iter()
            .any(|spec| spec.kind == ProjectInputKind::PyPipfile),
        "{specs:#?}"
    );
    preflight_project_inputs(dir, &specs, config)
}

fn preflight(dir: &std::path::Path) -> Result<Vec<Issue>> {
    preflight_with(dir, &config::SloppyJoeConfig::default())
}

fn assert_blocks(lock: &serde_json::Value, needle: &str) {
    let dir = write_project(PIPFILE, Some(lock));
    let err = preflight(&dir).expect_err("Pipfile.lock must block");
    assert!(
        format!("{err:#}").contains(needle),
        "expected '{needle}' in: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn consistent_pipfile_lock_passes_preflight() {
    let dir = write_project(PIPFILE, Some(&base_lock()));
    preflight(&dir).expect("consistent Pipfile.lock should pass");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipfile_without_lock_still_scans_as_legacy() {
    let dir = write_project(PIPFILE, None);
    let issues = preflight(&dir).expect("Pipfile without a lock stays a legacy scan");
    assert!(
        issues
            .iter()
            .any(|issue| issue.check == checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn declared_package_missing_from_lock_blocks() {
    let mut lock = base_lock();
    lock["default"].as_object_mut().unwrap().remove("flask");
    assert_blocks(&lock, "flask");
}

#[test]
fn dev_package_locked_only_in_default_blocks() {
    let mut lock = base_lock();
    let pytest = lock["develop"]
        .as_object_mut()
        .unwrap()
        .remove("pytest")
        .unwrap();
    lock["default"]["pytest"] = pytest;
    assert_blocks(&lock, "pytest");
}

#[test]
fn custom_category_package_missing_from_its_section_blocks() {
    let mut lock = base_lock();
    lock.as_object_mut().unwrap().remove("docs");
    assert_blocks(&lock, "mkdocs");
}

#[test]
fn unpinned_lock_version_blocks() {
    let mut lock = base_lock();
    lock["default"]["idna"]["version"] = serde_json::json!(">=3.0");
    assert_blocks(&lock, "idna");
}

#[test]
fn lock_entry_without_hashes_blocks() {
    let mut lock = base_lock();
    lock["default"]["idna"]
        .as_object_mut()
        .unwrap()
        .remove("hashes");
    assert_blocks(&lock, "hashes");
    let mut lock = base_lock();
    lock["develop"]["pluggy"]["hashes"] = serde_json::json!([]);
    assert_blocks(&lock, "hashes");
}

#[test]
fn lock_entries_with_non_registry_provenance_block() {
    for (key, value) in [
        ("git", serde_json::json!("https://github.com/evil/idna.git")),
        ("path", serde_json::json!("../idna")),
        ("file", serde_json::json!("https://evil.example/idna.whl")),
        ("editable", serde_json::json!(true)),
    ] {
        let mut lock = base_lock();
        lock["default"]["idna"][key] = value;
        assert_blocks(&lock, key);
    }
}

#[test]
fn lock_entry_from_non_pypi_index_blocks() {
    let mut lock = base_lock();
    lock["_meta"]["sources"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"name": "evil", "url": "https://evil.example/simple", "verify_ssl": true}));
    lock["default"]["idna"]["index"] = serde_json::json!("evil");
    assert_blocks(&lock, "evil");
}

#[test]
fn lock_entry_with_undeclared_index_name_blocks() {
    let mut lock = base_lock();
    lock["default"]["idna"]["index"] = serde_json::json!("nowhere");
    assert_blocks(&lock, "nowhere");
}

#[test]
fn lock_source_outside_index_allowlist_blocks() {
    let mut lock = base_lock();
    lock["_meta"]["sources"][0]["url"] = serde_json::json!("https://mirror.example/simple");
    assert_blocks(&lock, "mirror.example");
}

#[test]
fn allowlisted_lock_source_not_declared_in_pipfile_blocks() {
    let mut lock = base_lock();
    lock["_meta"]["sources"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"name": "corp", "url": "https://corp.example/simple", "verify_ssl": true}));
    let dir = write_project(PIPFILE, Some(&lock));
    let mut config = config::SloppyJoeConfig::default();
    config.trusted_indexes.insert(
        "pypi".to_string(),
        vec!["https://corp.example/simple".to_string()],
    );
    let err = preflight_with(&dir, &config).expect_err("lock source must match the Pipfile");
    assert!(format!("{err:#}").contains("corp.example"), "{err:#}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exact_pin_out_of_sync_with_lock_blocks() {
    let mut lock = base_lock();
    lock["default"]["requests"]["version"] = serde_json::json!("==2.31.0");
    assert_blocks(&lock, "requests");
}

#[test]
fn range_not_satisfied_by_locked_version_blocks() {
    let mut lock = base_lock();
    lock["default"]["flask"]["version"] = serde_json::json!("==2.3.0");
    assert_blocks(&lock, "flask");
}

#[test]
fn lock_names_are_matched_after_normalization() {
    let pipfile = PIPFILE.replace("flask = \">=3.0\"", "Flask_Login = \"==0.6.3\"");
    let mut lock = base_lock();
    lock["default"].as_object_mut().unwrap().remove("flask");
    lock["default"]["flask-login"] = entry("==0.6.3");
    let dir = write_project(&pipfile, Some(&lock));
    preflight(&dir).expect("normalized names should match");
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ scanning

type Queries = Vec<(String, Option<String>)>;

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Queries>>);

struct KnownRegistry {
    known: Vec<&'static str>,
}

#[async_trait]
impl RegistryExistence for KnownRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        Ok(self.known.contains(&package_name))
    }

    fn ecosystem(&self) -> &str {
        "pypi"
    }
}

#[async_trait]
impl RegistryMetadata for KnownRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        Ok(self.known.contains(&package_name).then(|| PackageMetadata {
            created: Some("2020-01-01T00:00:00Z".to_string()),
            latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
            downloads: Some(5_000_000),
            ..Default::default()
        }))
    }
}

struct RecordingOsv(Recorder);

#[async_trait]
impl OsvClient for RecordingOsv {
    async fn query(
        &self,
        name: &str,
        _ecosystem: &str,
        version: Option<&str>,
    ) -> Result<Vec<String>> {
        self.0
            .0
            .lock()
            .unwrap()
            .push((name.to_string(), version.map(str::to_string)));
        Ok(vec![])
    }
}

async fn scan(dir: &std::path::Path, known: Vec<&'static str>) -> (ScanReport, Recorder) {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), &config).unwrap();
    let mut issues = preflight_project_inputs(dir, &specs, &config).unwrap();
    let projects = parse_project_inputs(dir, &specs, &config).unwrap();
    let queried = Recorder::default();
    let registry = KnownRegistry { known };
    let osv = RecordingOsv(queried.clone());
    let opts = ScanOptions {
        scan_mode: ScanMode::Ci,
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
    for project in &projects {
        let report = scan_parsed_project(project, config.clone(), &registry, &osv, &opts)
            .await
            .unwrap();
        issues.extend(report.issues);
    }
    (ScanReport::from_issues(0, issues), queried)
}

const KNOWN: &[&str] = &["requests", "flask", "idna", "pytest", "pluggy", "mkdocs"];

#[tokio::test]
async fn lock_resolves_direct_versions_and_scans_lock_only_transitives() {
    let dir = write_project(PIPFILE, Some(&base_lock()));
    let (report, queried) = scan(&dir, KNOWN.to_vec()).await;
    let seen = queried.0.lock().unwrap().clone();
    // Lock-only entries are transitives: scanned at their locked versions.
    assert!(
        seen.contains(&("idna".to_string(), Some("3.10".to_string()))),
        "{seen:?}"
    );
    assert!(
        seen.contains(&("pluggy".to_string(), Some("1.5.0".to_string()))),
        "{seen:?}"
    );
    // A range in the Pipfile resolves to the exact locked version.
    assert!(
        seen.contains(&("flask".to_string(), Some("3.0.3".to_string()))),
        "{seen:?}"
    );
    assert!(
        !report.issues.iter().any(
            |issue| issue.check.starts_with("resolution/") && issue.severity == Severity::Error
        ),
        "{:#?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn lock_only_typosquat_is_scanned_and_blocks() {
    let mut lock = base_lock();
    lock["default"]["zzghost"] = entry("==9.0.0");
    let dir = write_project(PIPFILE, Some(&lock));
    let (report, _) = scan(&dir, KNOWN.to_vec()).await;
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.package.contains("zzghost") && issue.severity == Severity::Error),
        "{:#?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}
