//! Transitive dependencies of a Python manifest that has no lockfile (requirements files without
//! hashes, setup.py, setup.cfg, non-Poetry/uv pyproject.toml, a Pipfile without Pipfile.lock),
//! projected from PyPI metadata.
//!
//! pip resolves those at install time, so nothing in the repository records them. The projection
//! walks `Requires-Dist` breadth first: each package's version is the newest one PyPI lists that
//! every collected specifier allows (an `==` pin is taken as is), markers are evaluated for every
//! environment, and `extra == "..."` only for the extras requested. The packages found are
//! scanned as transitive dependencies with a reduced-confidence label: pip may choose other
//! versions.
//!
//! Fail closed: a metadata lookup that fails blocks, and so does exceeding any bound (depth,
//! packages, metadata fetches); the projection never silently stops short. Names that may come
//! from a private index are not looked up on PyPI at all.

use super::*;
mod requires;
mod select;

use futures::StreamExt;
pub(crate) use requires::Extras;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Limits on one projection. Exceeding any blocks the project.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    /// Breadth-first rounds (dependency levels, plus re-selections when specifiers merge).
    pub(crate) depth: usize,
    /// Distinct packages, direct dependencies included.
    pub(crate) packages: usize,
    /// PyPI metadata requests.
    pub(crate) fetches: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            depth: 40,
            packages: 500,
            fetches: 1500,
        }
    }
}

const FETCH_CONCURRENCY: usize = 16;

/// Appended to every finding on a projected package.
pub(crate) const PROJECTED_CONFIDENCE_NOTE: &str = "[projected transitive: no lockfile records this package; its version was projected from PyPI metadata and pip may install a different one]";

/// A direct dependency the projection starts from.
pub(crate) struct Root {
    pub(crate) name: String,
    pub(crate) specifier: String,
    pub(crate) extras: Extras,
}

#[derive(Default)]
struct Node {
    specs: BTreeSet<String>,
    extras: BTreeSet<String>,
    any_extras: bool,
    direct: bool,
    internal: bool,
    /// The registry has no metadata for an `==` pin under that spelling: list the versions.
    force_listing: bool,
    /// PyPI does not list the package.
    missing: bool,
    /// The versions last chosen.
    chosen: Vec<String>,
    conflict: Option<String>,
    /// (version, requested extras) whose requirements were already followed.
    expanded: BTreeSet<(String, String)>,
}

impl Node {
    fn extras(&self) -> Extras {
        if self.any_extras {
            Extras::Any
        } else {
            Extras::Requested(self.extras.clone())
        }
    }

    fn extras_key(&self) -> String {
        if self.any_extras {
            return "*".to_string();
        }
        self.extras.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

/// What a projection found.
#[derive(Debug, Default)]
pub(crate) struct Projection {
    /// Projected transitive packages, `==<version>` (or no version for a package PyPI does not
    /// list, so the existence check reports it).
    pub(crate) deps: Vec<Dependency>,
    pub(crate) issues: Vec<Issue>,
}

pub(crate) struct Projector<'a> {
    registry: &'a dyn registry::Registry,
    config: &'a config::SloppyJoeConfig,
    profile: parsers::python_scope::PythonProfile,
    bounds: Bounds,
    manifest: String,
    nodes: BTreeMap<String, Node>,
    listings: HashMap<String, Option<Vec<registry::pypi_release::PypiVersionListing>>>,
    requires: HashMap<(String, String), Option<Vec<String>>>,
    failed: BTreeSet<String>,
    fetches: usize,
    exceeded: bool,
    issues: Vec<Issue>,
}

impl<'a> Projector<'a> {
    pub(crate) fn new(
        registry: &'a dyn registry::Registry,
        config: &'a config::SloppyJoeConfig,
        opts: &ScanOptions<'_>,
        manifest: &std::path::Path,
        bounds: Bounds,
    ) -> Self {
        let mut profile = active_python_profile(opts).for_every_environment();
        profile.all_extras = true;
        Self {
            registry,
            config,
            profile,
            bounds,
            manifest: manifest.display().to_string(),
            nodes: BTreeMap::new(),
            listings: HashMap::new(),
            requires: HashMap::new(),
            failed: BTreeSet::new(),
            fetches: 0,
            exceeded: false,
            issues: Vec::new(),
        }
    }

    /// Project the transitive closure of `roots`.
    pub(crate) async fn run(mut self, roots: Vec<Root>) -> Projection {
        let mut dirty = BTreeSet::new();
        for root in roots {
            let node = self.nodes.entry(root.name.clone()).or_default();
            node.direct = true;
            node.specs.insert(root.specifier);
            match root.extras {
                Extras::Any => node.any_extras = true,
                Extras::Requested(extras) => node.extras.extend(extras),
            }
            dirty.insert(root.name);
        }
        let mut depth = 0;
        while !dirty.is_empty() && !self.exceeded {
            depth += 1;
            dirty = self.round(dirty, depth).await;
        }
        self.finish()
    }

    async fn round(&mut self, dirty: BTreeSet<String>, depth: usize) -> BTreeSet<String> {
        if depth > self.bounds.depth {
            self.exceed("depth", self.bounds.depth, "dependency levels");
            return BTreeSet::new();
        }
        if self.nodes.len() > self.bounds.packages {
            self.exceed("package", self.bounds.packages, "distinct packages");
            return BTreeSet::new();
        }
        self.fetch_listings(&dirty).await;
        let chosen = self.choose_versions(&dirty);
        self.fetch_requires(&chosen).await;
        if self.exceeded {
            return BTreeSet::new();
        }
        self.expand(&chosen)
    }

    fn needs_listing(&self, name: &str) -> bool {
        let Some(node) = self.nodes.get(name) else {
            return false;
        };
        !node.internal
            && !self.failed.contains(name)
            && !self.listings.contains_key(name)
            && (node.force_listing || select::exact_pin(&node.specs).is_none())
    }

    /// Count `count` more metadata requests against the bound.
    fn reserve(&mut self, count: usize) -> bool {
        if self.fetches + count > self.bounds.fetches {
            self.exceed(
                "metadata fetch",
                self.bounds.fetches,
                "PyPI metadata requests",
            );
            return false;
        }
        self.fetches += count;
        true
    }

    /// A name is looked up only when it is safe to put in a registry URL.
    fn lookable(&mut self, name: &str) -> bool {
        if crate::ecosystem::validate_package_name_for_ecosystem(name, Ecosystem::PyPI) {
            return true;
        }
        let error = anyhow::anyhow!("the name is not a valid PyPI project name");
        self.fail(name, None, &error);
        false
    }

    async fn fetch_listings(&mut self, dirty: &BTreeSet<String>) {
        let names: Vec<String> = dirty
            .iter()
            .filter(|name| self.needs_listing(name))
            .cloned()
            .collect();
        let names: Vec<String> = names
            .into_iter()
            .filter(|name| self.lookable(name))
            .collect();
        if names.is_empty() || !self.reserve(names.len()) {
            return;
        }
        let registry = self.registry;
        let results: Vec<_> = futures::stream::iter(names)
            .map(|name| async move {
                let result = registry.pypi_versions(&name).await;
                (name, result)
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .collect()
            .await;
        for (name, result) in results {
            match result {
                Ok(listing) => {
                    self.listings.insert(name, listing);
                }
                Err(error) => self.fail(&name, None, &error),
            }
        }
    }

    fn choose_versions(&mut self, dirty: &BTreeSet<String>) -> Vec<(String, String)> {
        let mut chosen = Vec::new();
        for name in dirty {
            let choice = self.choice_for(name);
            let Some(node) = self.nodes.get_mut(name) else {
                continue;
            };
            node.missing = matches!(self.listings.get(name), Some(None));
            node.conflict = choice.conflict;
            node.chosen = choice.versions;
            chosen.extend(node.chosen.iter().map(|v| (name.clone(), v.clone())));
        }
        chosen
    }

    fn choice_for(&self, name: &str) -> select::Choice {
        let Some(node) = self.nodes.get(name) else {
            return select::Choice::default();
        };
        if node.internal || self.failed.contains(name) {
            return select::Choice::default();
        }
        match self.listings.get(name) {
            Some(Some(listing)) => select::choose(listing, &node.specs),
            Some(None) => select::Choice::default(),
            None => select::Choice {
                versions: select::exact_pin(&node.specs).into_iter().collect(),
                conflict: None,
            },
        }
    }

    async fn fetch_requires(&mut self, chosen: &[(String, String)]) {
        let mut wanted: Vec<(String, String)> = chosen
            .iter()
            .filter(|key| !self.requires.contains_key(*key) && !self.failed.contains(&key.0))
            .cloned()
            .collect();
        wanted.dedup();
        if wanted.is_empty() || !self.reserve(wanted.len()) {
            return;
        }
        let registry = self.registry;
        let results: Vec<_> = futures::stream::iter(wanted)
            .map(|(name, version)| async move {
                let result = registry.pypi_requires_dist(&name, &version).await;
                ((name, version), result)
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .collect()
            .await;
        for ((name, version), result) in results {
            match result {
                Ok(requires) => {
                    self.requires.insert((name, version), requires);
                }
                Err(error) => self.fail(&name, Some(&version), &error),
            }
        }
    }

    /// Follow the requirements of every chosen version; the names whose specifiers or extras
    /// changed are the next round.
    fn expand(&mut self, chosen: &[(String, String)]) -> BTreeSet<String> {
        let mut dirty = BTreeSet::new();
        for (name, version) in chosen {
            let Some(entries) = self.release_requirements(name, version, &mut dirty) else {
                continue;
            };
            let Some(node) = self.nodes.get_mut(name) else {
                continue;
            };
            if !node.expanded.insert((version.clone(), node.extras_key())) {
                continue;
            }
            let extras = node.extras();
            for raw in &entries {
                self.follow(name, version, raw, &extras, &mut dirty);
            }
        }
        dirty
    }

    /// The `Requires-Dist` of `name` `version`, or `None` when there is nothing to follow. A pin
    /// PyPI has no release for under that spelling is retried through the version listing.
    fn release_requirements(
        &mut self,
        name: &str,
        version: &str,
        dirty: &mut BTreeSet<String>,
    ) -> Option<Vec<String>> {
        match self
            .requires
            .get(&(name.to_string(), version.to_string()))?
        {
            Some(entries) => Some(entries.clone()),
            None if !self.listings.contains_key(name) => {
                if let Some(node) = self.nodes.get_mut(name) {
                    node.force_listing = true;
                }
                dirty.insert(name.to_string());
                None
            }
            None => {
                let error =
                    anyhow::anyhow!("PyPI lists this version but serves no metadata for it");
                self.fail(name, Some(version), &error);
                None
            }
        }
    }

    fn follow(
        &mut self,
        owner: &str,
        version: &str,
        raw: &str,
        extras: &Extras,
        dirty: &mut BTreeSet<String>,
    ) {
        let label = format!("{owner} {version}");
        match requires::applicable(raw, &label, extras, &self.profile) {
            Ok(Some(requirement)) => {
                let name = requirement.name.clone();
                if self.add(requirement) {
                    dirty.insert(name);
                }
            }
            Ok(None) => {}
            Err(error) => self.fail(owner, Some(version), &error),
        }
    }

    /// Merge a requirement into its package; whether anything changed.
    fn add(&mut self, requirement: requires::Requirement) -> bool {
        let internal = self.config.is_internal("pypi", &requirement.name);
        let mut changed = !self.nodes.contains_key(&requirement.name);
        let node = self.nodes.entry(requirement.name).or_insert_with(|| Node {
            internal,
            ..Node::default()
        });
        changed |= node.specs.insert(requirement.specifier);
        for extra in requirement.extras {
            changed |= node.extras.insert(extra);
        }
        changed
    }

    fn fail(&mut self, name: &str, version: Option<&str>, error: &anyhow::Error) {
        self.failed.insert(name.to_string());
        let at = version.map(|v| format!(" {v}")).unwrap_or_default();
        self.issues.push(
            Issue::new(
                name,
                checks::names::RESOLUTION_PYTHON_PROJECTION_FAILED,
                Severity::Error,
            )
            .message(format!(
                "Could not read the PyPI dependency metadata of '{}{}' while projecting the transitive dependencies of '{}': {}. The packages pip installs for it were not checked.",
                report::sanitize_for_terminal(name),
                report::sanitize_for_terminal(&at),
                self.manifest,
                report::sanitize_for_terminal(&crate::http::describe_error(error)),
            ))
            .fix(LOCK_FIX),
        );
    }

    fn exceed(&mut self, bound: &str, limit: usize, what: &str) {
        self.exceeded = true;
        self.issues.push(
            Issue::new(
                &self.manifest,
                checks::names::RESOLUTION_PYTHON_PROJECTION_BOUND,
                Severity::Error,
            )
            .message(format!(
                "Projecting the transitive dependencies of '{}' from PyPI metadata exceeded the {bound} bound ({limit} {what}). The projection stopped there, so packages beyond it were not checked.",
                self.manifest
            ))
            .fix(LOCK_FIX),
        );
    }

    fn finish(mut self) -> Projection {
        let mut deps = Vec::new();
        let mut issues = std::mem::take(&mut self.issues);
        for (name, node) in &self.nodes {
            if let Some(conflict) = &node.conflict {
                issues.push(conflict_warning(name, conflict, &self.manifest));
            }
            if node.direct {
                continue;
            }
            deps.extend(projected_deps(name, node, self.failed.contains(name)));
            if node.internal {
                issues.push(internal_unprojectable_warning(name, &self.manifest));
            }
        }
        Projection { deps, issues }
    }
}

const LOCK_FIX: &str = "Commit a lockfile that records every installed package (`uv lock` or `poetry lock`, or `pip-compile --generate-hashes`), or run `sloppy-joe fix-lockfile`; then rerun the scan.";

/// The dependencies to scan for one projected package. A package PyPI does not list, one whose
/// lookup failed and an internal one are scanned by name (at an `==` pin when there is one) so
/// existence and the other checks still see them.
fn projected_deps(name: &str, node: &Node, failed: bool) -> Vec<Dependency> {
    let dependency = |version: Option<String>| Dependency {
        name: name.to_string(),
        version: version.map(|version| format!("=={version}")),
        ecosystem: Ecosystem::PyPI,
        actual_name: None,
    };
    if !node.chosen.is_empty() {
        return node
            .chosen
            .iter()
            .cloned()
            .map(Some)
            .map(dependency)
            .collect();
    }
    if node.missing || node.internal || failed {
        return vec![dependency(select::exact_pin(&node.specs))];
    }
    Vec::new()
}

fn conflict_warning(name: &str, conflict: &str, manifest: &str) -> Issue {
    Issue::new(
        name,
        checks::names::RESOLUTION_PYTHON_PROJECTED_CONFLICT,
        Severity::Warning,
    )
    .message(format!(
        "While projecting the transitive dependencies of '{manifest}', '{}': {conflict}. pip would refuse this set or settle it by other rules.",
        report::sanitize_for_terminal(name),
    ))
    .fix(LOCK_FIX)
}

fn internal_unprojectable_warning(name: &str, manifest: &str) -> Issue {
    Issue::new(
        name,
        checks::names::RESOLUTION_PYTHON_UNPROJECTABLE,
        Severity::Warning,
    )
    .message(format!(
        "'{}' is an internal package (configured `internal`) reached while projecting the transitive dependencies of '{manifest}'. It resolves from a private index, so sloppy-joe did not look it up on PyPI and the dependencies it pulls in were not projected or scanned.",
        report::sanitize_for_terminal(name),
    ))
    .fix("Commit a lockfile so the internal package's dependencies are recorded and scanned.")
}

/// The Python plugin's projection for `project`: empty for kinds whose lockfile records their
/// transitive dependencies.
pub(crate) async fn project_transitives(
    project: &ParsedProject,
    config: &config::SloppyJoeConfig,
    registry: &dyn registry::Registry,
    opts: &ScanOptions<'_>,
    bounds: Bounds,
) -> Result<ProjectedTransitives> {
    let flavors::Projection::On { extras_known } =
        flavor(project.spec.kind).projection(&project.spec)
    else {
        return Ok(ProjectedTransitives::default());
    };
    let manifest = &project.spec.manifest_path;
    if !project.package_indexes.is_empty() {
        return Ok(ProjectedTransitives {
            issues: vec![index_unprojectable_warning(
                manifest,
                &project.package_indexes,
            )],
            ..ProjectedTransitives::default()
        });
    }
    let mut issues = Vec::new();
    let roots = roots(project, config, extras_known, &mut issues);
    if roots.is_empty() {
        return Ok(ProjectedTransitives {
            issues,
            ..ProjectedTransitives::default()
        });
    }
    let projection = Projector::new(registry, config, opts, manifest, bounds)
        .run(roots)
        .await;
    issues.extend(projection.issues);
    issues.push(projected_summary(
        manifest,
        projection.deps.len(),
        opts.deep,
    ));
    Ok(ProjectedTransitives {
        deps: projection.deps,
        issues,
        confidence_note: PROJECTED_CONFIDENCE_NOTE.to_string(),
    })
}

/// The direct dependencies to project from. Internal ones resolve from a private index and are
/// never looked up on PyPI.
fn roots(
    project: &ParsedProject,
    config: &config::SloppyJoeConfig,
    extras_known: bool,
    issues: &mut Vec<Issue>,
) -> Vec<Root> {
    let manifest = project.spec.manifest_path.display().to_string();
    let mut roots = Vec::new();
    for dep in &project.deps {
        let name = parsers::requirements::normalize_distribution_name(dep.package_name());
        if config.is_internal("pypi", dep.package_name()) {
            issues.push(internal_unprojectable_warning(&name, &manifest));
            continue;
        }
        let extras = if extras_known {
            Extras::Requested(
                project
                    .python_root_extras
                    .get(&name)
                    .cloned()
                    .unwrap_or_default(),
            )
        } else {
            Extras::Any
        };
        roots.push(Root {
            name,
            specifier: dep.version.clone().unwrap_or_default(),
            extras,
        });
    }
    roots
}

fn projected_summary(manifest: &std::path::Path, count: usize, deep: bool) -> Issue {
    let similarity = if deep {
        ", and for similarity because of --deep"
    } else {
        "; similarity runs on them with --deep"
    };
    Issue::new(
        manifest.display().to_string(),
        checks::names::RESOLUTION_PYTHON_PROJECTED_TRANSITIVES,
        Severity::Warning,
    )
    .message(format!(
        "'{}' has no lockfile, so pip resolves its transitive dependencies at install time. sloppy-joe PROJECTED {count} transitive package(s) from PyPI metadata (the newest version each collected specifier allows, every environment's markers included) and checked them for existence, metadata and known vulnerabilities{similarity}. Projected versions may differ from what pip installs.",
        manifest.display()
    ))
    .fix("For exact transitive coverage, create a lockfile with `uv lock` or `poetry lock`, or run `sloppy-joe fix-lockfile`.")
}

fn index_unprojectable_warning(manifest: &std::path::Path, indexes: &[String]) -> Issue {
    let indexes = indexes
        .iter()
        .map(|index| format!("'{}'", report::sanitize_for_terminal(index)))
        .collect::<Vec<_>>()
        .join(", ");
    Issue::new(
        manifest.display().to_string(),
        checks::names::RESOLUTION_PYTHON_UNPROJECTABLE,
        Severity::Warning,
    )
    .message(format!(
        "'{}' installs from package index {indexes}, not only from PyPI. sloppy-joe does not ask PyPI about packages another index may serve, so the transitive dependencies of this manifest were not projected and are not scanned.",
        manifest.display()
    ))
    .fix("Commit a lockfile that records every installed package and its index (`uv lock` or `poetry lock` with the index declared), so transitive dependencies are scanned exactly.")
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;
