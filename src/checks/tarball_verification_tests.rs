//! Selection, fail-closed handling, caching and signal integration for npm
//! tarball verification.

use super::*;
use crate::Ecosystem;
use crate::checks::metadata::{MetadataLookup, issues_from_lookups};
use crate::config::SloppyJoeConfig;
use crate::names;
use crate::registry::npm_tarball::{IntegrityMismatch, NpmManifestFacts, NpmTarballRef};
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use crate::report::{Issue, Severity};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

enum Outcome {
    Facts(NpmManifestFacts),
    Integrity,
    Fail,
    Unsupported,
}

struct FakeRegistry {
    outcomes: HashMap<String, Outcome>,
    calls: Mutex<Vec<String>>,
}

impl FakeRegistry {
    fn new(outcomes: Vec<(&str, Outcome)>) -> Self {
        Self {
            outcomes: outcomes
                .into_iter()
                .map(|(name, outcome)| (name.to_string(), outcome))
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
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for FakeRegistry {
    async fn verify_npm_tarball(
        &self,
        package_name: &str,
        _tarball: &NpmTarballRef,
    ) -> Result<Option<NpmManifestFacts>> {
        self.calls.lock().unwrap().push(package_name.to_string());
        match self.outcomes.get(package_name) {
            Some(Outcome::Facts(facts)) => Ok(Some(facts.clone())),
            Some(Outcome::Integrity) => Err(IntegrityMismatch("sha512 mismatch".into()).into()),
            Some(Outcome::Unsupported) => Ok(None),
            Some(Outcome::Fail) | None => Err(anyhow::anyhow!("connection reset")),
        }
    }
}

fn facts(scripts: &[(&str, &str)], deps: &[&str]) -> NpmManifestFacts {
    NpmManifestFacts {
        install_scripts: scripts
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        dependencies: deps.iter().map(|d| d.to_string()).collect(),
        gyp: false,
    }
}

fn clean() -> NpmManifestFacts {
    facts(&[], &["a"])
}

fn evil() -> NpmManifestFacts {
    facts(&[("postinstall", "node steal.js")], &["a"])
}

/// An old, popular, unflagged package: nothing selects it for verification.
fn quiet_meta(integrity: &str) -> PackageMetadata {
    PackageMetadata {
        created: Some("2015-01-01T00:00:00Z".into()),
        latest_version_date: Some("2020-01-01T00:00:00Z".into()),
        downloads: Some(5_000_000),
        repository_url: Some("https://github.com/acme/pkg".into()),
        dependency_count: Some(1),
        npm_tarball: Some(NpmTarballRef {
            version: "1.0.0".into(),
            tarball: Some("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz".into()),
            integrity: Some(integrity.into()),
            shasum: None,
            declared: clean(),
        }),
        ..Default::default()
    }
}

/// A version published moments ago: always selected.
fn recent_meta(integrity: &str) -> PackageMetadata {
    PackageMetadata {
        latest_version_date: Some(crate::cache::now_iso8601()),
        ..quiet_meta(integrity)
    }
}

fn lookup(package: &str, meta: PackageMetadata) -> MetadataLookup {
    MetadataLookup {
        package: package.into(),
        ecosystem: Ecosystem::Npm,
        version: Some("1.0.0".into()),
        resolved_version: Some("1.0.0".into()),
        unresolved_version: false,
        exists: true,
        metadata: Some(meta),
    }
}

fn options() -> TarballVerificationOptions<'static> {
    TarballVerificationOptions {
        cache_dir: None,
        no_cache: true,
        verify_all: false,
        max_fetches: DEFAULT_MAX_TARBALL_FETCHES,
    }
}

fn config() -> SloppyJoeConfig {
    SloppyJoeConfig {
        min_version_age_hours: 0,
        ..Default::default()
    }
}

async fn run(
    registry: &FakeRegistry,
    lookups: &mut [MetadataLookup],
    options: &TarballVerificationOptions<'_>,
) -> Vec<Issue> {
    verify_npm_tarballs(registry, lookups, &config(), &HashSet::new(), options).await
}

fn with_check<'a>(issues: &'a [Issue], check: &str) -> Vec<&'a Issue> {
    issues.iter().filter(|i| i.check == check).collect()
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-tarball-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── outcomes ──

#[tokio::test]
async fn matching_tarball_raises_nothing_and_uses_tarball_counts() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(facts(&[], &["a", "b"])))]);
    let mut meta = recent_meta("sha512-x");
    meta.npm_tarball.as_mut().unwrap().declared = facts(&[], &["a", "b"]);
    let mut lookups = vec![lookup("pkg", meta)];
    let issues = run(&registry, &mut lookups, &options()).await;
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(registry.calls(), vec!["pkg"]);
    let meta = lookups[0].metadata.as_ref().unwrap();
    assert_eq!(meta.dependency_count, Some(2));
    assert!(!meta.has_install_scripts);
}

#[tokio::test]
async fn hidden_postinstall_is_blocking_manifest_inconsistency() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(evil()))]);
    let mut lookups = vec![lookup("pkg", recent_meta("sha512-x"))];
    let issues = run(&registry, &mut lookups, &options()).await;
    let found = with_check(&issues, names::METADATA_MANIFEST_INCONSISTENCY);
    assert_eq!(found.len(), 1, "{issues:?}");
    assert_eq!(found[0].severity, Severity::Error);
    assert!(
        found[0].message.contains("postinstall"),
        "{}",
        found[0].message
    );
    // The tarball is the source of truth for downstream signals.
    let meta = lookups[0].metadata.as_ref().unwrap();
    assert!(meta.has_install_scripts);
}

#[tokio::test]
async fn tarball_truth_feeds_install_script_risk() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(evil()))]);
    let mut meta = recent_meta("sha512-x");
    meta.created = Some(crate::cache::now_iso8601()); // brand-new package
    meta.version_history = vec![crate::registry::VersionRecord {
        version: "1.0.0".into(),
        publisher: Some("mallory".into()),
        has_install_scripts: false,
        date: Some(crate::cache::now_iso8601()),
    }];
    let mut lookups = vec![lookup("pkg", meta)];
    let before = issues_from_lookups(&lookups, &config(), &HashSet::new());
    assert!(with_check(&before, names::METADATA_INSTALL_SCRIPT_RISK).is_empty());

    run(&registry, &mut lookups, &options()).await;
    let after = issues_from_lookups(&lookups, &config(), &HashSet::new());
    assert_eq!(
        with_check(&after, names::METADATA_INSTALL_SCRIPT_RISK).len(),
        1
    );
    let meta = lookups[0].metadata.as_ref().unwrap();
    assert!(meta.version_history[0].has_install_scripts);
}

#[tokio::test]
async fn hidden_dependency_is_blocking_and_counted() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(facts(&[], &["a", "stealer"])))]);
    let mut lookups = vec![lookup("pkg", recent_meta("sha512-x"))];
    let issues = run(&registry, &mut lookups, &options()).await;
    let found = with_check(&issues, names::METADATA_MANIFEST_INCONSISTENCY);
    assert_eq!(found.len(), 1, "{issues:?}");
    assert!(found[0].message.contains("'stealer'"));
    assert_eq!(
        lookups[0].metadata.as_ref().unwrap().dependency_count,
        Some(2)
    );
}

#[tokio::test]
async fn integrity_mismatch_is_blocking() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Integrity)]);
    let mut lookups = vec![lookup("pkg", recent_meta("sha512-x"))];
    let issues = run(&registry, &mut lookups, &options()).await;
    let found = with_check(&issues, names::METADATA_TARBALL_INTEGRITY);
    assert_eq!(found.len(), 1, "{issues:?}");
    assert_eq!(found[0].severity, Severity::Error);
}

#[tokio::test]
async fn fetch_failure_is_blocking() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Fail)]);
    let mut lookups = vec![lookup("pkg", recent_meta("sha512-x"))];
    let issues = run(&registry, &mut lookups, &options()).await;
    let found = with_check(&issues, names::METADATA_TARBALL_UNVERIFIED);
    assert_eq!(found.len(), 1, "{issues:?}");
    assert_eq!(found[0].severity, Severity::Error);
    assert!(found[0].message.contains("connection reset"));
}

#[tokio::test]
async fn registry_without_tarball_support_is_blocking_when_selected() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Unsupported)]);
    let mut lookups = vec![lookup("pkg", recent_meta("sha512-x"))];
    let issues = run(&registry, &mut lookups, &options()).await;
    assert_eq!(
        with_check(&issues, names::METADATA_TARBALL_UNVERIFIED).len(),
        1
    );
}

#[tokio::test]
async fn missing_hash_is_blocking_without_a_fetch() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(clean()))]);
    let mut meta = recent_meta("sha512-x");
    meta.npm_tarball.as_mut().unwrap().integrity = None;
    let mut lookups = vec![lookup("pkg", meta)];
    let issues = run(&registry, &mut lookups, &options()).await;
    assert_eq!(
        with_check(&issues, names::METADATA_TARBALL_UNVERIFIED).len(),
        1,
        "{issues:?}"
    );
    assert!(registry.calls().is_empty());
}

// ── selection ──

#[tokio::test]
async fn old_popular_unflagged_version_is_not_fetched() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Fail)]);
    let mut lookups = vec![lookup("pkg", quiet_meta("sha512-x"))];
    let issues = run(&registry, &mut lookups, &options()).await;
    assert!(issues.is_empty(), "{issues:?}");
    assert!(registry.calls().is_empty());
}

#[tokio::test]
async fn non_npm_and_packument_less_lookups_are_not_fetched() {
    let registry = FakeRegistry::new(vec![]);
    let mut pypi = lookup("pkg", recent_meta("sha512-x"));
    pypi.ecosystem = Ecosystem::PyPI;
    let mut no_ref = recent_meta("sha512-x");
    no_ref.npm_tarball = None;
    let mut lookups = vec![pypi, lookup("other", no_ref)];
    let issues = run(&registry, &mut lookups, &options()).await;
    assert!(issues.is_empty(), "{issues:?}");
    assert!(registry.calls().is_empty());
}

#[tokio::test]
async fn each_selection_reason_triggers_a_fetch() {
    let mut cases: Vec<(&str, PackageMetadata, HashSet<String>)> = Vec::new();
    let mut low = quiet_meta("sha512-x");
    low.downloads = Some(10);
    cases.push(("low-downloads", low, HashSet::new()));
    let mut unknown = quiet_meta("sha512-x");
    unknown.downloads = None;
    cases.push(("unknown-downloads", unknown, HashSet::new()));
    let mut new_pkg = quiet_meta("sha512-x");
    new_pkg.created = Some(crate::cache::now_iso8601());
    cases.push(("new-package", new_pkg, HashSet::new()));
    let mut undated = quiet_meta("sha512-x");
    undated.latest_version_date = None;
    cases.push(("undated", undated, HashSet::new()));
    let mut takeover = quiet_meta("sha512-x");
    takeover.previous_publisher = Some("alice".into()); // metadata/maintainer-change
    takeover.current_publisher = Some("mallory".into());
    cases.push(("flagged-by-signal", takeover, HashSet::new()));
    cases.push((
        "similarity",
        quiet_meta("sha512-x"),
        ["similarity".to_string()].into(),
    ));

    for (name, meta, similarity) in cases {
        let registry = FakeRegistry::new(vec![(name, Outcome::Facts(clean()))]);
        let mut lookups = vec![lookup(name, meta)];
        verify_npm_tarballs(&registry, &mut lookups, &config(), &similarity, &options()).await;
        assert_eq!(registry.calls(), vec![name.to_string()], "{name}");
    }
}

#[tokio::test]
async fn verify_all_policy_fetches_every_npm_package() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(clean()))]);
    let mut lookups = vec![lookup("pkg", quiet_meta("sha512-x"))];
    let opts = TarballVerificationOptions {
        verify_all: true,
        ..options()
    };
    run(&registry, &mut lookups, &opts).await;
    assert_eq!(registry.calls(), vec!["pkg"]);
}

#[tokio::test]
async fn fetch_cap_blocks_the_overflow_instead_of_skipping_it() {
    let registry = FakeRegistry::new(vec![
        ("a", Outcome::Facts(clean())),
        ("b", Outcome::Facts(clean())),
        ("c", Outcome::Facts(clean())),
    ]);
    let mut lookups = vec![
        lookup("a", recent_meta("sha512-a")),
        lookup("b", recent_meta("sha512-b")),
        lookup("c", recent_meta("sha512-c")),
    ];
    let opts = TarballVerificationOptions {
        max_fetches: 2,
        ..options()
    };
    let issues = run(&registry, &mut lookups, &opts).await;
    assert_eq!(registry.calls().len(), 2);
    let unverified = with_check(&issues, names::METADATA_TARBALL_UNVERIFIED);
    assert_eq!(unverified.len(), 1, "{issues:?}");
    assert!(
        unverified[0].message.contains("limit"),
        "{}",
        unverified[0].message
    );
}

#[tokio::test]
async fn duplicate_lookups_share_one_fetch_and_one_issue() {
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(evil()))]);
    let mut lookups = vec![
        lookup("pkg", recent_meta("sha512-x")),
        lookup("pkg", recent_meta("sha512-x")),
    ];
    let issues = run(&registry, &mut lookups, &options()).await;
    assert_eq!(registry.calls().len(), 1);
    assert_eq!(
        with_check(&issues, names::METADATA_MANIFEST_INCONSISTENCY).len(),
        1
    );
    assert!(
        lookups
            .iter()
            .all(|l| l.metadata.as_ref().unwrap().has_install_scripts)
    );
}

// ── cache ──

#[tokio::test]
async fn verified_facts_are_cached_by_name_version_and_integrity() {
    let dir = unique_dir();
    let opts = TarballVerificationOptions {
        cache_dir: Some(&dir),
        no_cache: false,
        ..options()
    };
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(evil()))]);
    let mut lookups = vec![lookup("pkg", recent_meta("sha512-x"))];
    run(&registry, &mut lookups, &opts).await;
    assert_eq!(registry.calls().len(), 1);

    // Second scan: served from cache, mismatch still detected.
    let registry = FakeRegistry::new(vec![]);
    let mut lookups = vec![lookup("pkg", recent_meta("sha512-x"))];
    let issues = run(&registry, &mut lookups, &opts).await;
    assert!(registry.calls().is_empty());
    assert_eq!(
        with_check(&issues, names::METADATA_MANIFEST_INCONSISTENCY).len(),
        1
    );

    // A different integrity is a different artifact: fetched again.
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(clean()))]);
    let mut lookups = vec![lookup("pkg", recent_meta("sha512-y"))];
    let issues = run(&registry, &mut lookups, &opts).await;
    assert_eq!(registry.calls().len(), 1);
    assert!(issues.is_empty(), "{issues:?}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(tarball_cache_path(Some(&dir)))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn failures_are_not_cached_and_no_cache_skips_reads() {
    let dir = unique_dir();
    let cached = TarballVerificationOptions {
        cache_dir: Some(&dir),
        no_cache: false,
        ..options()
    };
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Fail)]);
    run(
        &registry,
        &mut [lookup("pkg", recent_meta("sha512-x"))],
        &cached,
    )
    .await;
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(clean()))]);
    run(
        &registry,
        &mut [lookup("pkg", recent_meta("sha512-x"))],
        &cached,
    )
    .await;
    assert_eq!(registry.calls().len(), 1, "failure must not be cached");

    let uncached = TarballVerificationOptions {
        cache_dir: Some(&dir),
        no_cache: true,
        ..options()
    };
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(clean()))]);
    run(
        &registry,
        &mut [lookup("pkg", recent_meta("sha512-x"))],
        &uncached,
    )
    .await;
    assert_eq!(
        registry.calls().len(),
        1,
        "--no-cache must not read the cache"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_cache_file_is_ignored() {
    let dir = unique_dir();
    let opts = TarballVerificationOptions {
        cache_dir: Some(&dir),
        no_cache: false,
        ..options()
    };
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(clean()))]);
    run(
        &registry,
        &mut [lookup("pkg", recent_meta("sha512-x"))],
        &opts,
    )
    .await;
    let path = tarball_cache_path(Some(&dir));
    let real = dir.join("elsewhere.json");
    std::fs::rename(&path, &real).unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();
    let registry = FakeRegistry::new(vec![("pkg", Outcome::Facts(clean()))]);
    run(
        &registry,
        &mut [lookup("pkg", recent_meta("sha512-x"))],
        &opts,
    )
    .await;
    assert_eq!(registry.calls().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── pipeline ──

struct NoOsv;
#[async_trait]
impl crate::checks::malicious::OsvClient for NoOsv {
    async fn query(&self, _: &str, _: &str, _: Option<&str>) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

struct PipelineRegistry {
    inner: FakeRegistry,
}

#[async_trait]
impl RegistryExistence for PipelineRegistry {
    async fn exists(&self, _: &str) -> Result<bool> {
        Ok(true)
    }
    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for PipelineRegistry {
    async fn metadata(&self, _: &str, _: Option<&str>) -> Result<Option<PackageMetadata>> {
        Ok(Some(recent_meta("sha512-x")))
    }
    async fn verify_npm_tarball(
        &self,
        package_name: &str,
        tarball: &NpmTarballRef,
    ) -> Result<Option<NpmManifestFacts>> {
        self.inner.verify_npm_tarball(package_name, tarball).await
    }
}

#[tokio::test]
async fn default_pipeline_blocks_hidden_postinstall() {
    let deps = vec![crate::test_helpers::npm_dep("left-pad")];
    let config = config();
    let resolution = crate::lockfiles::ResolutionResult::default();
    let opts = crate::ScanOptions {
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
    let registry = PipelineRegistry {
        inner: FakeRegistry::new(vec![("left-pad", Outcome::Facts(evil()))]),
    };
    let ctx = crate::checks::CheckContext {
        checkable_deps: &deps,
        non_internal_deps: &deps,
        config: &config,
        registry: &registry,
        osv_client: &NoOsv,
        resolution: &resolution,
        ecosystem: Ecosystem::Npm,
        opts: &opts,
    };
    let mut acc = crate::checks::ScanAccumulator::new();
    for check in crate::checks::pipeline::default_pipeline() {
        check.run(&ctx, &mut acc).await.unwrap();
    }
    let found = with_check(&acc.issues, names::METADATA_MANIFEST_INCONSISTENCY);
    assert_eq!(found.len(), 1, "{:?}", acc.issues);
    assert_eq!(found[0].severity, Severity::Error);
}
