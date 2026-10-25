use super::*;
use crate::registry::pypi_release::{PypiRequiresDist, PypiVersionListing};
use crate::registry::{RegistryExistence, RegistryMetadata};
use async_trait::async_trait;
use std::sync::Mutex;

/// A PyPI stand-in: version listings and `Requires-Dist` per release, names whose lookups fail,
/// and a log of every request.
#[derive(Default)]
struct FakePypi {
    listings: HashMap<String, Vec<(String, bool)>>,
    requires: HashMap<(String, String), PypiRequiresDist>,
    failing: BTreeSet<String>,
    calls: Mutex<Vec<String>>,
}

impl FakePypi {
    fn package(mut self, name: &str, versions: &[&str]) -> Self {
        self.listings.insert(
            name.to_string(),
            versions.iter().map(|v| (v.to_string(), false)).collect(),
        );
        for version in versions {
            self.requires
                .entry((name.to_string(), version.to_string()))
                .or_default();
        }
        self
    }

    fn requires(mut self, name: &str, version: &str, entries: &[&str]) -> Self {
        self.requires.insert(
            (name.to_string(), version.to_string()),
            PypiRequiresDist {
                requirements: entries.iter().map(|e| e.to_string()).collect(),
                metadata_missing: false,
            },
        );
        self
    }

    /// A release PyPI publishes no dependency metadata for (sdist only, `requires_dist: null`).
    fn without_metadata(mut self, name: &str, version: &str) -> Self {
        self.requires.insert(
            (name.to_string(), version.to_string()),
            PypiRequiresDist {
                requirements: Vec::new(),
                metadata_missing: true,
            },
        );
        self
    }

    fn failing(mut self, name: &str) -> Self {
        self.failing.insert(name.to_string());
        self
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl RegistryExistence for FakePypi {
    async fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.listings.contains_key(name))
    }

    fn ecosystem(&self) -> &str {
        "pypi"
    }
}

#[async_trait]
impl RegistryMetadata for FakePypi {
    async fn pypi_versions(&self, name: &str) -> Result<Option<Vec<PypiVersionListing>>> {
        self.calls.lock().unwrap().push(format!("versions {name}"));
        if self.failing.contains(name) {
            anyhow::bail!("PyPI metadata lookup for '{name}' returned HTTP 503");
        }
        Ok(self.listings.get(name).map(|versions| {
            versions
                .iter()
                .map(|(version, yanked)| PypiVersionListing {
                    version: version.clone(),
                    yanked: *yanked,
                })
                .collect()
        }))
    }

    async fn pypi_requires_dist(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<PypiRequiresDist>> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("requires {name} {version}"));
        if self.failing.contains(name) {
            anyhow::bail!("PyPI metadata lookup for '{name}' returned HTTP 503");
        }
        Ok(self
            .requires
            .get(&(name.to_string(), version.to_string()))
            .cloned())
    }
}

fn root(name: &str, specifier: &str) -> Root {
    Root {
        name: name.to_string(),
        specifier: specifier.to_string(),
        extras: Extras::Requested(BTreeSet::new()),
    }
}

async fn project_with(registry: &FakePypi, roots: Vec<Root>, bounds: Bounds) -> Projection {
    project_with_config(registry, roots, bounds, &config::SloppyJoeConfig::default()).await
}

async fn project_with_config(
    registry: &FakePypi,
    roots: Vec<Root>,
    bounds: Bounds,
    config: &config::SloppyJoeConfig,
) -> Projection {
    let opts = ScanOptions::default();
    Projector::new(
        registry,
        config,
        &opts,
        std::path::Path::new("requirements.txt"),
        bounds,
    )
    .run(roots)
    .await
}

async fn project(registry: &FakePypi, roots: Vec<Root>) -> Projection {
    project_with(registry, roots, Bounds::default()).await
}

fn names(projection: &Projection) -> Vec<String> {
    projection
        .deps
        .iter()
        .map(|dep| format!("{}{}", dep.name, dep.version.as_deref().unwrap_or("")))
        .collect()
}

fn checks(projection: &Projection) -> Vec<(&str, &str, Severity)> {
    projection
        .issues
        .iter()
        .map(|issue| (issue.package.as_str(), issue.check.as_str(), issue.severity))
        .collect()
}

fn requests_world() -> FakePypi {
    FakePypi::default()
        .package("requests", &["2.0.0", "2.31.0"])
        .requires(
            "requests",
            "2.31.0",
            &[
                "urllib3<3,>=1.21.1",
                "idna (<4,>=2.5)",
                "PySocks!=1.5.7,>=1.5.6; extra == \"socks\"",
                "win-inet-pton; sys_platform == \"win32\" and extra == \"socks\"",
                "colorama; sys_platform == \"win32\"",
            ],
        )
        .package("urllib3", &["1.26.18", "2.2.1", "3.0.0"])
        .package("idna", &["3.6", "4.0"])
        .package("pysocks", &["1.7.1"])
        .package("win-inet-pton", &["1.1.0"])
        .package("colorama", &["0.4.6"])
}

#[tokio::test]
async fn the_closure_follows_the_newest_allowed_versions_and_every_environment() {
    let registry = requests_world();
    let projection = project(&registry, vec![root("requests", ">=2")]).await;
    assert_eq!(
        names(&projection),
        vec!["colorama==0.4.6", "idna==3.6", "urllib3==2.2.1"]
    );
    assert!(projection.issues.is_empty(), "{:?}", projection.issues);
}

#[tokio::test]
async fn requested_extras_pull_in_their_requirements() {
    let registry = requests_world();
    let mut requests = root("requests", ">=2");
    requests.extras = Extras::Requested(BTreeSet::from(["socks".to_string()]));
    let projection = project(&registry, vec![requests]).await;
    let found = names(&projection);
    assert!(found.contains(&"pysocks==1.7.1".to_string()), "{found:?}");
    assert!(
        found.contains(&"win-inet-pton==1.1.0".to_string()),
        "{found:?}"
    );
}

#[tokio::test]
async fn unknown_extras_count_every_extra() {
    let registry = requests_world();
    let mut requests = root("requests", "");
    requests.extras = Extras::Any;
    let found = names(&project(&registry, vec![requests]).await);
    assert!(found.contains(&"pysocks==1.7.1".to_string()), "{found:?}");
}

#[tokio::test]
async fn an_exact_pin_is_taken_without_listing_versions() {
    let registry = requests_world();
    let projection = project(&registry, vec![root("requests", "==2.31.0")]).await;
    assert!(names(&projection).contains(&"urllib3==2.2.1".to_string()));
    let calls = registry.calls();
    assert!(calls.contains(&"requires requests 2.31.0".to_string()));
    assert!(
        !calls.contains(&"versions requests".to_string()),
        "{calls:?}"
    );
}

#[tokio::test]
async fn a_pin_spelled_differently_from_the_release_is_found_through_the_listing() {
    let registry = FakePypi::default()
        .package("pkg", &["2.0"])
        .requires("pkg", "2.0", &["child"])
        .package("child", &["1.0"]);
    let projection = project(&registry, vec![root("pkg", "==2.0.0")]).await;
    assert_eq!(names(&projection), vec!["child==1.0"]);
    assert!(projection.issues.is_empty(), "{:?}", projection.issues);
}

#[tokio::test]
async fn specifiers_from_several_dependents_are_merged() {
    let registry = FakePypi::default()
        .package("a", &["1.0"])
        .requires("a", "1.0", &["shared>=1"])
        .package("b", &["1.0"])
        .requires("b", "1.0", &["shared<2"])
        .package("shared", &["0.9", "1.5", "2.5"]);
    let projection = project(&registry, vec![root("a", ""), root("b", "")]).await;
    assert_eq!(names(&projection), vec!["shared==1.5"]);
}

#[tokio::test]
async fn conflicting_specifiers_warn_and_check_each_candidate() {
    let registry = FakePypi::default()
        .package("a", &["1.0"])
        .requires("a", "1.0", &["shared<2"])
        .package("b", &["1.0"])
        .requires("b", "1.0", &["shared>=3"])
        .package("shared", &["1.0", "3.0"]);
    let projection = project(&registry, vec![root("a", ""), root("b", "")]).await;
    assert_eq!(names(&projection), vec!["shared==1.0", "shared==3.0"]);
    assert_eq!(
        checks(&projection),
        vec![(
            "shared",
            checks::names::RESOLUTION_PYTHON_PROJECTED_CONFLICT,
            Severity::Warning
        )]
    );
}

#[tokio::test]
async fn a_package_pypi_does_not_list_is_scanned_by_name_so_existence_reports_it() {
    let registry = FakePypi::default()
        .package("app-helper", &["1.0"])
        .requires("app-helper", "1.0", &["hallucinated-pkg>=1"]);
    let projection = project(&registry, vec![root("app-helper", "")]).await;
    assert_eq!(names(&projection), vec!["hallucinated-pkg"]);
}

#[tokio::test]
async fn a_failed_lookup_blocks_and_the_rest_is_still_projected() {
    let registry = FakePypi::default()
        .package("a", &["1.0"])
        .requires("a", "1.0", &["broken", "fine"])
        .package("fine", &["1.0"])
        .failing("broken");
    let projection = project(&registry, vec![root("a", "")]).await;
    assert_eq!(names(&projection), vec!["broken", "fine==1.0"]);
    let issue = projection
        .issues
        .iter()
        .find(|issue| issue.check == checks::names::RESOLUTION_PYTHON_PROJECTION_FAILED)
        .expect("failed lookup must block");
    assert_eq!(issue.severity, Severity::Error);
    assert_eq!(issue.package, "broken");
    assert!(issue.message.contains("HTTP 503"), "{}", issue.message);
}

#[tokio::test]
async fn a_requirement_the_projection_cannot_model_blocks() {
    let registry = FakePypi::default().package("a", &["1.0"]).requires(
        "a",
        "1.0",
        &["evil @ https://example.com/evil.whl"],
    );
    let projection = project(&registry, vec![root("a", "")]).await;
    assert_eq!(
        checks(&projection),
        vec![(
            "a",
            checks::names::RESOLUTION_PYTHON_PROJECTION_FAILED,
            Severity::Error
        )]
    );
}

fn chain(length: usize) -> FakePypi {
    let mut registry = FakePypi::default();
    for index in 0..length {
        let name = format!("p{index}");
        registry = registry.package(&name, &["1.0"]);
        if index + 1 < length {
            let child = format!("p{}", index + 1);
            registry = registry.requires(&name, "1.0", &[child.as_str()]);
        }
    }
    registry
}

fn bound_issues(projection: &Projection) -> Vec<&Issue> {
    projection
        .issues
        .iter()
        .filter(|issue| issue.check == checks::names::RESOLUTION_PYTHON_PROJECTION_BOUND)
        .collect()
}

#[tokio::test]
async fn exceeding_the_depth_bound_blocks_and_names_it() {
    let registry = chain(6);
    let bounds = Bounds {
        depth: 3,
        ..Bounds::default()
    };
    let projection = project_with(&registry, vec![root("p0", "")], bounds).await;
    let issues = bound_issues(&projection);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, Severity::Error);
    assert!(
        issues[0].message.contains("depth bound (3"),
        "{}",
        issues[0].message
    );
    let within = project_with(&registry, vec![root("p0", "")], Bounds::default()).await;
    assert!(bound_issues(&within).is_empty());
    assert_eq!(within.deps.len(), 5);
}

#[tokio::test]
async fn exceeding_the_package_bound_blocks_and_names_it() {
    let registry = FakePypi::default()
        .package("root", &["1.0"])
        .requires("root", "1.0", &["a", "b", "c"])
        .package("a", &["1.0"])
        .package("b", &["1.0"])
        .package("c", &["1.0"]);
    let bounds = Bounds {
        packages: 2,
        ..Bounds::default()
    };
    let projection = project_with(&registry, vec![root("root", "")], bounds).await;
    let issues = bound_issues(&projection);
    assert_eq!(issues.len(), 1);
    assert!(
        issues[0].message.contains("package bound (2 projected"),
        "{}",
        issues[0].message
    );
    let exact = Bounds {
        packages: 3,
        ..Bounds::default()
    };
    let projection = project_with(&registry, vec![root("root", "")], exact).await;
    assert!(bound_issues(&projection).is_empty());
}

#[tokio::test]
async fn exceeding_the_fetch_bound_blocks_and_names_it() {
    let registry = chain(4);
    let bounds = Bounds {
        fetches: 3,
        ..Bounds::default()
    };
    let projection = project_with(&registry, vec![root("p0", "")], bounds).await;
    let issues = bound_issues(&projection);
    assert_eq!(issues.len(), 1);
    assert!(
        issues[0].message.contains("metadata fetch bound (3"),
        "{}",
        issues[0].message
    );
    assert!(registry.calls().len() <= 3);
}

#[tokio::test]
async fn dependency_cycles_terminate() {
    let registry = FakePypi::default()
        .package("a", &["1.0"])
        .requires("a", "1.0", &["b"])
        .package("b", &["1.0"])
        .requires("b", "1.0", &["a"]);
    let projection = project(&registry, vec![root("a", "")]).await;
    assert_eq!(names(&projection), vec!["b==1.0"]);
    assert!(projection.issues.is_empty());
}

#[tokio::test]
async fn internal_packages_are_never_looked_up_on_pypi() {
    let registry = FakePypi::default()
        .package("public", &["1.0"])
        .requires("public", "1.0", &["acme-core==2.0"])
        .package("acme-core", &["9.9"])
        .requires("acme-core", "9.9", &["attacker-payload"]);
    let config: config::SloppyJoeConfig =
        serde_json::from_str(r#"{"internal": {"pypi": ["acme-core"]}}"#).unwrap();
    let projection = project_with_config(
        &registry,
        vec![root("public", "")],
        Bounds::default(),
        &config,
    )
    .await;
    assert_eq!(names(&projection), vec!["acme-core==2.0"]);
    assert!(
        registry
            .calls()
            .iter()
            .all(|call| !call.contains("acme-core")),
        "{:?}",
        registry.calls()
    );
    assert_eq!(
        checks(&projection),
        vec![(
            "acme-core",
            checks::names::RESOLUTION_PYTHON_UNPROJECTABLE,
            Severity::Warning
        )]
    );
}

#[tokio::test]
async fn a_direct_dependency_is_never_reported_as_projected() {
    let registry = FakePypi::default()
        .package("a", &["1.0"])
        .requires("a", "1.0", &["b>=1"])
        .package("b", &["1.0", "2.0"]);
    let projection = project(&registry, vec![root("a", ""), root("b", "==1.0")]).await;
    assert!(projection.deps.is_empty(), "{:?}", projection.deps);
}

#[tokio::test]
async fn direct_dependencies_do_not_count_against_the_package_bound() {
    let mut registry = FakePypi::default();
    let mut roots = Vec::new();
    for index in 0..5 {
        let name = format!("direct{index}");
        registry = registry.package(&name, &["1.0"]);
        roots.push(root(&name, "==1.0"));
    }
    let bounds = Bounds {
        packages: 1,
        ..Bounds::default()
    };
    let projection = project_with(&registry, roots, bounds).await;
    assert!(
        bound_issues(&projection).is_empty(),
        "{:?}",
        projection.issues
    );
}

#[tokio::test]
async fn a_release_without_dependency_metadata_warns_that_its_dependencies_are_unknown() {
    let registry = FakePypi::default()
        .package("a", &["1.0"])
        .requires("a", "1.0", &["legacy-sdist"])
        .package("legacy-sdist", &["0.3"])
        .without_metadata("legacy-sdist", "0.3");
    let projection = project(&registry, vec![root("a", "")]).await;
    assert_eq!(names(&projection), vec!["legacy-sdist==0.3"]);
    let warning = projection
        .issues
        .iter()
        .find(|issue| issue.check == checks::names::RESOLUTION_PYTHON_UNPROJECTABLE)
        .expect("unknown dependency metadata must be visible");
    assert_eq!(warning.package, "legacy-sdist");
    assert_eq!(warning.severity, Severity::Warning);
    assert!(warning.message.contains("0.3"), "{}", warning.message);
}
