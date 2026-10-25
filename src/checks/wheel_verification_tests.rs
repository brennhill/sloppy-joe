//! Selection, severity, fail-closed handling and caching for PyPI wheel
//! startup-hook inspection.

use super::*;
use crate::registry::pypi_release::PypiRelease;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

enum Outcome {
    Facts(WheelFacts),
    Integrity,
    Fail,
    Unsupported,
}

/// Outcomes by wheel sha256.
struct FakeRegistry {
    outcomes: HashMap<String, Outcome>,
    calls: Mutex<Vec<String>>,
}

impl FakeRegistry {
    fn new(outcomes: Vec<(&str, Outcome)>) -> Self {
        Self {
            outcomes: outcomes
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            calls: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl RegistryExistence for FakeRegistry {
    async fn exists(&self, _: &str) -> Result<bool> {
        Ok(true)
    }
    fn ecosystem(&self) -> &str {
        "pypi"
    }
}

#[async_trait]
impl RegistryMetadata for FakeRegistry {
    async fn inspect_pypi_wheel(&self, _: &str, file: &PypiFile) -> Result<Option<WheelFacts>> {
        let sha = file.sha256.clone().unwrap_or_default();
        self.calls.lock().unwrap().push(sha.clone());
        match self.outcomes.get(&sha) {
            Some(Outcome::Facts(facts)) => Ok(Some(facts.clone())),
            Some(Outcome::Integrity) => Err(IntegrityMismatch("sha256 differs".into()).into()),
            Some(Outcome::Unsupported) => Ok(None),
            Some(Outcome::Fail) | None => Err(anyhow::anyhow!("connection reset")),
        }
    }
}

fn hook(path: &str, code: &str) -> StartupHook {
    StartupHook {
        path: path.into(),
        kind: HookKind::PthImport,
        code: vec![code.into()],
        unreadable: None,
    }
}

fn with_hook(path: &str, code: &str) -> WheelFacts {
    WheelFacts {
        startup_hooks: vec![hook(path, code)],
    }
}

fn clean() -> WheelFacts {
    WheelFacts::default()
}

fn wheel(sha: &str) -> PypiFile {
    PypiFile {
        filename: format!("p-1.0-{sha}.whl"),
        url: format!("https://files.pythonhosted.org/{sha}.whl"),
        sha256: Some(sha.into()),
        kind: PypiFileKind::Wheel,
        size: None,
        yanked: false,
    }
}

fn hours_ago(hours: u64) -> String {
    let secs = cache::now_epoch() as i64 - (hours as i64) * 3600;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn lookup(
    package: &str,
    shas: &[&str],
    version_age_hours: u64,
    created_age_hours: u64,
) -> MetadataLookup {
    MetadataLookup {
        package: package.into(),
        ecosystem: Ecosystem::PyPI,
        version: Some("==1.0".into()),
        resolved_version: Some("1.0".into()),
        unresolved_version: false,
        exists: true,
        metadata: Some(PackageMetadata {
            created: Some(hours_ago(created_age_hours)),
            latest_version_date: Some(hours_ago(version_age_hours)),
            pypi_release: Some(PypiRelease {
                version: "1.0".into(),
                files: shas.iter().map(|s| wheel(s)).collect(),
            }),
            ..Default::default()
        }),
    }
}

const OLD: u64 = 24 * 400;
const YOUNG: u64 = 24 * 5;

fn temp_cache() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-wheel-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn run(
    registry: &FakeRegistry,
    lookups: &mut [MetadataLookup],
    flagged: &[&str],
    verify_all: bool,
    cache_dir: Option<&Path>,
) -> Vec<Issue> {
    let flagged: HashSet<String> = flagged.iter().map(|s| s.to_string()).collect();
    inspect_python_wheels(
        registry,
        lookups,
        &flagged,
        &WheelVerificationOptions {
            cache_dir,
            no_cache: cache_dir.is_none(),
            verify_all,
        },
    )
    .await
}

#[tokio::test]
async fn established_unflagged_versions_are_not_downloaded() {
    let registry = FakeRegistry::new(vec![]);
    let mut lookups = [lookup("p", &["aa"], OLD, OLD)];
    assert!(
        run(&registry, &mut lookups, &[], false, None)
            .await
            .is_empty()
    );
    assert!(registry.calls().is_empty());
}

#[tokio::test]
async fn young_version_with_a_hook_blocks_and_marks_install_time_code() {
    let registry = FakeRegistry::new(vec![(
        "aa",
        Outcome::Facts(with_hook("p-setup.pth", "import os")),
    )]);
    let mut lookups = [lookup("p", &["aa"], YOUNG, OLD)];
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "metadata/python-startup-hook");
    assert_eq!(issues[0].severity, Severity::Error);
    assert!(issues[0].message.contains("p-setup.pth: import os"));
    assert!(lookups[0].metadata.as_ref().unwrap().has_install_scripts);
}

#[tokio::test]
async fn new_package_and_similarity_flag_each_select_the_version() {
    let registry = FakeRegistry::new(vec![
        ("aa", Outcome::Facts(clean())),
        ("bb", Outcome::Facts(clean())),
    ]);
    let mut lookups = [
        lookup("new", &["aa"], OLD, YOUNG),
        lookup("flagged", &["bb"], OLD, OLD),
    ];
    assert!(
        run(&registry, &mut lookups, &["flagged"], false, None)
            .await
            .is_empty()
    );
    assert_eq!(registry.calls().len(), 2);
}

#[tokio::test]
async fn undated_version_is_treated_as_young() {
    let registry = FakeRegistry::new(vec![("aa", Outcome::Facts(clean()))]);
    let mut lookups = [lookup("p", &["aa"], OLD, OLD)];
    lookups[0].metadata.as_mut().unwrap().latest_version_date = None;
    run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(registry.calls().len(), 1);
}

#[tokio::test]
async fn paranoid_inspects_established_versions_and_plain_hooks_only_warn() {
    let registry = FakeRegistry::new(vec![(
        "aa",
        Outcome::Facts(with_hook("ns.pth", "import sys, types")),
    )]);
    let mut lookups = [lookup("p", &["aa"], OLD, OLD)];
    let issues = run(&registry, &mut lookups, &[], true, None).await;
    assert_eq!(issues[0].check, "metadata/python-startup-hook");
    assert_eq!(issues[0].severity, Severity::Warning);
}

#[tokio::test]
async fn paranoid_hook_that_spawns_processes_blocks() {
    let registry = FakeRegistry::new(vec![(
        "aa",
        Outcome::Facts(with_hook(
            "x.pth",
            "import subprocess; subprocess.Popen(['x'])",
        )),
    )]);
    let mut lookups = [lookup("p", &["aa"], OLD, OLD)];
    let issues = run(&registry, &mut lookups, &[], true, None).await;
    assert_eq!(issues[0].severity, Severity::Error);
}

#[tokio::test]
async fn sitecustomize_and_unreadable_hooks_block_even_when_paranoid_only() {
    for bad in [
        StartupHook {
            path: "sitecustomize.py".into(),
            kind: HookKind::CustomizeModule,
            code: vec![],
            unreadable: None,
        },
        StartupHook {
            path: "big.pth".into(),
            kind: HookKind::PthImport,
            code: vec![],
            unreadable: Some("too big".into()),
        },
    ] {
        let registry = FakeRegistry::new(vec![(
            "aa",
            Outcome::Facts(WheelFacts {
                startup_hooks: vec![bad],
            }),
        )]);
        let mut lookups = [lookup("p", &["aa"], OLD, OLD)];
        let issues = run(&registry, &mut lookups, &[], true, None).await;
        assert_eq!(issues[0].severity, Severity::Error);
    }
}

#[tokio::test]
async fn a_hook_in_one_platform_wheel_is_found() {
    let registry = FakeRegistry::new(vec![
        ("aa", Outcome::Facts(clean())),
        ("bb", Outcome::Facts(with_hook("evil.pth", "import os"))),
    ]);
    let mut lookups = [lookup("p", &["aa", "bb"], YOUNG, OLD)];
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(issues.len(), 1);
    assert_eq!(registry.calls().len(), 2);
}

#[tokio::test]
async fn identical_hooks_across_wheels_are_listed_once() {
    let same = with_hook("p.pth", "import os");
    let registry = FakeRegistry::new(vec![
        ("aa", Outcome::Facts(same.clone())),
        ("bb", Outcome::Facts(same)),
    ]);
    let mut lookups = [lookup("p", &["aa", "bb"], YOUNG, OLD)];
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert!(!issues[0].message.contains("more"));
}

#[tokio::test]
async fn download_failure_blocks_as_unverified() {
    let registry = FakeRegistry::new(vec![("aa", Outcome::Fail)]);
    let mut lookups = [lookup("p", &["aa"], YOUNG, OLD)];
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(issues[0].check, "metadata/wheel-unverified");
    assert_eq!(issues[0].severity, Severity::Error);
}

#[tokio::test]
async fn registry_that_cannot_inspect_blocks_as_unverified() {
    let registry = FakeRegistry::new(vec![("aa", Outcome::Unsupported)]);
    let mut lookups = [lookup("p", &["aa"], YOUNG, OLD)];
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(issues[0].check, "metadata/wheel-unverified");
}

#[tokio::test]
async fn digest_mismatch_blocks_with_its_own_check() {
    let registry = FakeRegistry::new(vec![("aa", Outcome::Integrity)]);
    let mut lookups = [lookup("p", &["aa"], YOUNG, OLD)];
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(issues[0].check, "metadata/wheel-integrity-mismatch");
}

#[tokio::test]
async fn wheel_without_a_published_digest_is_never_downloaded() {
    let registry = FakeRegistry::new(vec![]);
    let mut lookups = [lookup("p", &["aa"], YOUNG, OLD)];
    lookups[0]
        .metadata
        .as_mut()
        .unwrap()
        .pypi_release
        .as_mut()
        .unwrap()
        .files[0]
        .sha256 = None;
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(issues[0].check, "metadata/wheel-unverified");
    assert!(registry.calls().is_empty());
}

#[tokio::test]
async fn sdist_only_release_has_nothing_to_inspect() {
    let registry = FakeRegistry::new(vec![]);
    let mut lookups = [lookup("p", &["aa"], YOUNG, OLD)];
    lookups[0]
        .metadata
        .as_mut()
        .unwrap()
        .pypi_release
        .as_mut()
        .unwrap()
        .files[0]
        .kind = PypiFileKind::Sdist;
    assert!(
        run(&registry, &mut lookups, &[], false, None)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn per_version_wheel_cap_blocks_the_excess_instead_of_passing_it() {
    let shas: Vec<String> = (0..MAX_WHEELS_PER_VERSION + 3)
        .map(|i| format!("h{i:03}"))
        .collect();
    let refs: Vec<&str> = shas.iter().map(String::as_str).collect();
    let outcomes = refs.iter().map(|s| (*s, Outcome::Facts(clean()))).collect();
    let registry = FakeRegistry::new(outcomes);
    let mut lookups = [lookup("p", &refs, YOUNG, OLD)];
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "metadata/wheel-unverified");
    assert!(issues[0].message.contains("3 were not inspected"));
    assert_eq!(registry.calls().len(), MAX_WHEELS_PER_VERSION);
}

#[tokio::test]
async fn per_scan_cap_downloads_urgent_packages_first_and_blocks_the_rest() {
    let mut lookups = Vec::new();
    let mut outcomes = Vec::new();
    let shas: Vec<String> = (0..MAX_WHEEL_FETCHES + 2)
        .map(|i| format!("s{i:03}"))
        .collect();
    for sha in &shas {
        lookups.push(lookup(&format!("pkg{sha}"), &[sha], YOUNG, OLD));
        outcomes.push((sha.as_str(), Outcome::Facts(clean())));
    }
    let registry = FakeRegistry::new(outcomes);
    let issues = run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(registry.calls().len(), MAX_WHEEL_FETCHES);
    assert_eq!(issues.len(), 2);
    assert!(
        issues
            .iter()
            .all(|i| i.check == "metadata/wheel-unverified")
    );
}

#[tokio::test]
async fn verified_wheels_are_cached_and_not_downloaded_twice() {
    let dir = temp_cache();
    let registry = FakeRegistry::new(vec![(
        "aa",
        Outcome::Facts(with_hook("p.pth", "import os")),
    )]);
    let mut first = [lookup("p", &["aa"], YOUNG, OLD)];
    run(&registry, &mut first, &[], false, Some(&dir)).await;
    let mut second = [lookup("p", &["aa"], YOUNG, OLD)];
    let issues = run(&registry, &mut second, &[], false, Some(&dir)).await;
    assert_eq!(registry.calls().len(), 1);
    assert_eq!(issues[0].check, "metadata/python-startup-hook");
}

#[tokio::test]
async fn failures_are_not_cached() {
    let dir = temp_cache();
    let registry = FakeRegistry::new(vec![("aa", Outcome::Fail)]);
    let mut first = [lookup("p", &["aa"], YOUNG, OLD)];
    run(&registry, &mut first, &[], false, Some(&dir)).await;
    let mut second = [lookup("p", &["aa"], YOUNG, OLD)];
    run(&registry, &mut second, &[], false, Some(&dir)).await;
    assert_eq!(registry.calls().len(), 2);
}

#[tokio::test]
async fn same_version_under_two_spellings_is_inspected_once() {
    let registry = FakeRegistry::new(vec![("aa", Outcome::Facts(clean()))]);
    let mut lookups = [
        lookup("Foo_Bar", &["aa"], YOUNG, OLD),
        lookup("foo-bar", &["aa"], YOUNG, OLD),
    ];
    run(&registry, &mut lookups, &[], false, None).await;
    assert_eq!(registry.calls().len(), 1);
}

#[tokio::test]
async fn non_pypi_and_unresolved_lookups_are_ignored() {
    let registry = FakeRegistry::new(vec![]);
    let mut npm = lookup("p", &["aa"], YOUNG, OLD);
    npm.ecosystem = Ecosystem::Npm;
    let mut unresolved = lookup("q", &["bb"], YOUNG, OLD);
    unresolved.unresolved_version = true;
    let mut lookups = [npm, unresolved];
    assert!(
        run(&registry, &mut lookups, &[], false, None)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn results_cached_by_an_older_inspector_are_discarded() {
    // A wheel the old inspector read as clean (e.g. `./x.pth`, missed before the
    // path fix) must be inspected again, not trusted for the rest of its TTL.
    let dir = temp_cache();
    let stale = WheelCache {
        format: WHEEL_CACHE_FORMAT - 1,
        timestamp: cache::now_epoch(),
        entries: BTreeMap::from([(
            "aa".to_string(),
            WheelCacheEntry {
                checked_at: cache::now_epoch(),
                facts: clean(),
            },
        )]),
    };
    cache::atomic_write_json(&cache_path(Some(&dir)), &stale);
    let registry = FakeRegistry::new(vec![(
        "aa",
        Outcome::Facts(with_hook("./x.pth", "import os")),
    )]);
    let mut lookups = [lookup("p", &["aa"], YOUNG, OLD)];
    let issues = run(&registry, &mut lookups, &[], false, Some(&dir)).await;
    assert_eq!(registry.calls(), ["aa"]);
    assert_eq!(issues[0].check, "metadata/python-startup-hook");
}

#[test]
fn path_and_start_hooks_are_described_by_what_they_do() {
    let path_hook = StartupHook {
        path: "x.pth".into(),
        kind: HookKind::PthPath,
        code: vec!["shared_dir".into()],
        unreadable: None,
    };
    assert!(describe_hook(&path_hook).contains("adds 'shared_dir' to sys.path"));
    let start = StartupHook {
        path: "x.start".into(),
        kind: HookKind::StartEntryPoint,
        code: vec!["pkg.boot:run".into()],
        unreadable: None,
    };
    assert!(describe_hook(&start).contains("calls pkg.boot:run"));
}
