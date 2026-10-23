//! End-to-end: stale yarn.lock entries no dependency reaches are reported as a
//! non-blocking warning and never queried, while real transitives are scanned.
use super::*;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use crate::report::Severity;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-yarn-orphan-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[derive(Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Recorder {
    fn names(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

struct KnownRegistry {
    known: Vec<&'static str>,
    queried: Recorder,
}

#[async_trait]
impl RegistryExistence for KnownRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.queried
            .0
            .lock()
            .unwrap()
            .push(package_name.to_string());
        Ok(self.known.contains(&package_name))
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for KnownRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        self.queried
            .0
            .lock()
            .unwrap()
            .push(package_name.to_string());
        Ok(self.known.contains(&package_name).then(|| PackageMetadata {
            created: Some("2020-01-01T00:00:00Z".to_string()),
            latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
            downloads: Some(50000),
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
        _version: Option<&str>,
    ) -> Result<Vec<String>> {
        self.0.0.lock().unwrap().push(name.to_string());
        Ok(vec![])
    }
}

#[tokio::test]
async fn yarn_orphans_warn_without_blocking_and_are_never_queried() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","packageManager":"yarn@1.22.22","dependencies":{"lodash":"^4.17.21"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# yarn lockfile v1


lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#a"
  integrity sha512-a
  optionalDependencies:
    chalk "^5.0.0"

chalk@^5.0.0:
  version "5.3.0"
  resolved "https://registry.yarnpkg.com/chalk/-/chalk-5.3.0.tgz#a"
  integrity sha512-a

zzghost@^9.0.0:
  version "9.0.0"
  resolved "https://registry.yarnpkg.com/zzghost/-/zzghost-9.0.0.tgz#a"
  integrity sha512-a
"#,
    )
    .unwrap();
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("npm"), &config).unwrap();
    let mut issues = preflight_project_inputs(&dir, &specs, &config).unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config).unwrap();
    let registry = KnownRegistry {
        known: vec!["lodash", "chalk"],
        queried: Recorder::default(),
    };
    let osv = RecordingOsv(Recorder::default());
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
    let report = ScanReport::from_issues(0, issues);
    assert!(!report.has_errors(), "{:?}", report.issues);
    let orphan = report
        .issues
        .iter()
        .find(|i| i.check == "lockfile/orphan-entries")
        .unwrap_or_else(|| panic!("{:?}", report.issues));
    assert_eq!(orphan.severity, Severity::Warning);
    assert!(
        orphan.message.contains("zzghost@9.0.0"),
        "{}",
        orphan.message
    );
    let osv_names = osv.0.names();
    assert!(osv_names.contains(&"chalk".to_string()), "{osv_names:?}");
    assert!(!osv_names.contains(&"zzghost".to_string()), "{osv_names:?}");
    assert!(
        !registry.queried.names().contains(&"zzghost".to_string()),
        "{:?}",
        registry.queried.names()
    );
    std::fs::remove_dir_all(dir).unwrap();
}
