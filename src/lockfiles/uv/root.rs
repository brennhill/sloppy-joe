use super::*;

/// Which part of the project a uv.lock root entry belongs to. uv records project dependencies
/// under `dependencies` / `metadata.requires-dist`, extras under `optional-dependencies`
/// (`requires-dist` entries carry an `extra == ...` marker), and dependency groups (including
/// `[tool.uv] dev-dependencies`, recorded as `dev`) under `dev-dependencies` /
/// `metadata.requires-dev`. Names are normalized.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UvRootScope {
    Main,
    Extra(String),
    Group(String),
}

impl UvRootScope {
    pub(crate) fn in_profile(&self, profile: &PythonProfile) -> bool {
        match self {
            Self::Main => true,
            Self::Extra(extra) => profile.includes_extra(extra),
            Self::Group(group) => profile.includes_group(group),
        }
    }

    pub(crate) fn resolved_section(&self) -> String {
        match self {
            Self::Main => "dependencies".to_string(),
            Self::Extra(extra) => format!("optional-dependencies.{extra}"),
            Self::Group(group) => format!("dev-dependencies.{group}"),
        }
    }

    pub(crate) fn metadata_section(&self) -> String {
        match self {
            Self::Main | Self::Extra(_) => "metadata.requires-dist".to_string(),
            Self::Group(group) => format!("metadata.requires-dev.{group}"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UvRootRequiresEntry {
    pub(crate) normalized_name: String,
    pub(crate) specifier: Option<String>,
    pub(crate) marker: Option<String>,
    pub(crate) scope: UvRootScope,
}

#[derive(Clone, Debug)]
pub(crate) struct UvRootDependencyEntry {
    pub(crate) normalized_name: String,
    pub(crate) version: Option<String>,
    pub(crate) requested_extras: BTreeSet<String>,
    pub(crate) marker: Option<String>,
    pub(crate) scope: UvRootScope,
}

/// How a manifest dependency's specifier relates to the in-scope uv.lock root metadata.
pub(crate) enum UvRootSpecifierMatch {
    /// No in-scope requires-dist / requires-dev entry names the package.
    Missing,
    Matched,
    /// The package is recorded, but with a different specifier.
    Mismatch(Option<String>),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UvSelectedRootDependency {
    pub(crate) version: Option<String>,
    pub(crate) requested_extras: BTreeSet<String>,
}

pub(crate) fn validate_manifest_consistency(
    parsed: &toml::Value,
    deps: &[Dependency],
    source_path: &Path,
    lock_profile: Option<&PythonLockfileProfile>,
) -> Result<()> {
    let root_requires = extract_root_requires_entries(parsed)?.ok_or_else(|| {
        anyhow::anyhow!(
            "Broken lockfile '{}': missing root package metadata.requires-dist",
            source_path.display()
        )
    })?;
    let root_dependencies = extract_root_dependency_entries(parsed)?.unwrap_or_default();
    let profile = effective_python_profile(lock_profile);
    let packages = package_entries(parsed);

    for dep in deps {
        let normalized = normalize_name(&dep.name);
        match match_root_specifier(
            &root_requires,
            &normalized,
            &profile,
            dep.version.as_deref(),
        )? {
            UvRootSpecifierMatch::Matched => {}
            UvRootSpecifierMatch::Missing => {
                return Err(crate::remedy::problem(
                    &crate::remedy::UV_LOCK,
                    format!(
                        "Broken lockfile '{}': '{}' is missing from the root requires-dist / requires-dev metadata",
                        source_path.display(),
                        crate::report::sanitize_for_terminal(&dep.name)
                    ),
                ));
            }
            UvRootSpecifierMatch::Mismatch(_) => {
                return Err(crate::remedy::problem(
                    &crate::remedy::UV_LOCK,
                    format!(
                        "Broken lockfile '{}': '{}' is out of sync with pyproject.toml",
                        source_path.display(),
                        crate::report::sanitize_for_terminal(&dep.name)
                    ),
                ));
            }
        }
        let specifier = dep.version.clone();

        let selected_root = select_root_dependency(&root_dependencies, &normalized, &profile)?;
        if let Some(root_version) = selected_root
            .as_ref()
            .and_then(|selection| selection.version.as_deref())
            && !version_matches_uv_specifier(root_version, specifier.as_deref())?
        {
            return Err(crate::remedy::problem(
                &crate::remedy::LOCK_PIN_MISMATCH,
                format!(
                    "Broken lockfile '{}': '{}' is out of sync with requires-dist because root-selected version '{}' contradicts '{}'",
                    source_path.display(),
                    dep.name,
                    root_version,
                    specifier.as_deref().unwrap_or("")
                ),
            ));
        }

        let candidates: Vec<&toml::value::Table> = packages
            .iter()
            .copied()
            .filter(|pkg| {
                pkg.get("name")
                    .and_then(|value| value.as_str())
                    .is_some_and(|name| normalize_name(name) == normalized)
                    && !is_local_root_package(pkg)
            })
            .collect();

        if candidates.is_empty() {
            return Err(crate::remedy::problem(
                &crate::remedy::UV_LOCK,
                format!(
                    "Broken lockfile '{}': '{}' is missing a resolved package entry",
                    source_path.display(),
                    dep.name
                ),
            ));
        }

        let expected_version = selected_root
            .and_then(|selection| selection.version)
            .or_else(|| dep.exact_version());
        if let Some(expected_version) = expected_version.as_deref() {
            if !candidates.iter().any(|pkg| {
                pkg.get("version")
                    .and_then(|value| value.as_str())
                    .is_some_and(|version| version == expected_version)
            }) {
                return Err(crate::remedy::problem(
                    &crate::remedy::LOCK_PIN_MISMATCH,
                    format!(
                        "Broken lockfile '{}': '{}' is missing the root-selected resolved package entry '{}'",
                        source_path.display(),
                        dep.name,
                        expected_version
                    ),
                ));
            }
        } else if let [candidate] = candidates.as_slice() {
            let version = candidate
                .get("version")
                .and_then(|version| version.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("Broken uv.lock: resolved package is missing version")
                })?;
            if !version_matches_uv_specifier(version, specifier.as_deref())? {
                return Err(crate::remedy::problem(
                    &crate::remedy::LOCK_PIN_MISMATCH,
                    format!(
                        "Broken lockfile '{}': '{}' resolved version '{}' is out of sync with '{}'",
                        source_path.display(),
                        dep.name,
                        version,
                        specifier.as_deref().unwrap_or("")
                    ),
                ));
            }
        } else if candidates.len() > 1 {
            bail!(
                "Broken lockfile '{}': '{}' resolves ambiguously and cannot be trusted exactly",
                source_path.display(),
                dep.name
            );
        }
    }

    Ok(())
}

/// Every manifest dependency in coverage scope (any environment, the same group and extra
/// selection) must be recorded by uv.lock, as `uv lock --check` requires. A dependency whose
/// marker is false for the scan target is still installed elsewhere; if the lock does not
/// record it, nothing vouches for what that environment installs. `profile` is the coverage
/// profile, so markers are undecided and several forked entries may hold at once: the manifest
/// specifier must equal one recorded entry and one locked version must satisfy it.
pub(crate) fn validate_coverage_roots_are_locked(
    parsed: &toml::Value,
    roots: &[Dependency],
    source_path: &Path,
    profile: &PythonProfile,
) -> Result<()> {
    let root_requires = extract_root_requires_entries(parsed)?.unwrap_or_default();
    let packages = package_entries(parsed);
    for dep in roots {
        let normalized = normalize_name(&dep.name);
        let recorded = recorded_specifiers(&root_requires, &normalized, profile)?;
        let name = crate::report::sanitize_for_terminal(&dep.name);
        let problem = |remedy, detail: String| {
            crate::remedy::problem(
                remedy,
                format!(
                    "Broken lockfile '{}': '{name}' {detail}",
                    source_path.display()
                ),
            )
        };
        if recorded.is_empty() {
            return Err(problem(
                &crate::remedy::UV_LOCK,
                "is missing from the root requires-dist / requires-dev metadata".to_string(),
            ));
        }
        if !recorded.contains(&dep.version.as_deref()) {
            return Err(problem(
                &crate::remedy::UV_LOCK,
                "is out of sync with pyproject.toml".to_string(),
            ));
        }
        let locked = locked_versions(&packages, &normalized);
        if locked.is_empty() {
            return Err(problem(
                &crate::remedy::UV_LOCK,
                "is missing a resolved package entry".to_string(),
            ));
        }
        let mut satisfied = false;
        for version in &locked {
            satisfied |= version_matches_uv_specifier(version, dep.version.as_deref())?;
        }
        if !satisfied {
            return Err(problem(
                &crate::remedy::LOCK_PIN_MISMATCH,
                format!(
                    "has no locked version satisfying '{}'",
                    crate::report::sanitize_for_terminal(dep.version.as_deref().unwrap_or(""))
                ),
            ));
        }
    }
    Ok(())
}

/// The specifiers uv.lock records for `normalized_name` in the profile's scope.
fn recorded_specifiers<'a>(
    entries: &'a [UvRootRequiresEntry],
    normalized_name: &str,
    profile: &PythonProfile,
) -> Result<Vec<Option<&'a str>>> {
    let mut recorded = Vec::new();
    for entry in entries {
        if entry.normalized_name == normalized_name
            && entry.scope.in_profile(profile)
            && root_marker_matches_profile(entry.marker.as_deref(), profile)?
        {
            recorded.push(entry.specifier.as_deref());
        }
    }
    Ok(recorded)
}

/// Every version uv.lock resolves for `normalized_name` (the project root excluded).
fn locked_versions<'a>(packages: &[&'a toml::value::Table], normalized_name: &str) -> Vec<&'a str> {
    packages
        .iter()
        .filter(|pkg| !is_local_root_package(pkg))
        .filter(|pkg| {
            pkg.get("name")
                .and_then(|value| value.as_str())
                .is_some_and(|name| normalize_name(name) == normalized_name)
        })
        .filter_map(|pkg| pkg.get("version").and_then(|value| value.as_str()))
        .collect()
}

/// The reverse of [`validate_manifest_consistency`]: every package the uv.lock root installs or
/// records (main dependencies, extras, dependency groups) must be declared in the same section
/// of pyproject.toml. A lock-only entry means the lockfile is stale or was modified, and the
/// package would otherwise be installed without ever being scanned. All manifest declarations are
/// considered, so narrowing the scanned groups cannot hide drift in the groups left out.
pub(crate) fn validate_root_declarations_are_declared(
    parsed: &toml::Value,
    declared: &[crate::parsers::python_scope::PythonScopedDependency],
    source_path: &Path,
) -> Result<()> {
    let declared: Vec<_> = declared
        .iter()
        .filter(|dep| !dep.unlocked_tool_env)
        .map(|dep| {
            (
                normalize_name(dep.dependency.package_name()),
                dep.dependency.version.as_deref(),
                dep.groups
                    .iter()
                    .map(|group| normalize_name(group))
                    .collect::<BTreeSet<_>>(),
                dep.extras
                    .iter()
                    .map(|extra| normalize_name(extra))
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect();
    let in_section =
        |groups: &BTreeSet<String>, extras: &BTreeSet<String>, scope: &UvRootScope| match scope {
            UvRootScope::Main => groups.is_empty() && extras.is_empty(),
            UvRootScope::Extra(extra) => extras.contains(extra),
            UvRootScope::Group(group) => groups.contains(group),
        };

    for entry in extract_root_dependency_entries(parsed)?.unwrap_or_default() {
        let is_declared = declared.iter().any(|(name, _, groups, extras)| {
            *name == entry.normalized_name && in_section(groups, extras, &entry.scope)
        });
        if !is_declared {
            return Err(crate::remedy::problem(
                &crate::remedy::UV_LOCK,
                format!(
                    "Broken lockfile '{}': '{}' is locked in the root package's {} but is not declared in the matching pyproject.toml section",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(&entry.normalized_name),
                    crate::report::sanitize_for_terminal(&entry.scope.resolved_section())
                ),
            ));
        }
    }

    for entry in extract_root_requires_entries(parsed)?.unwrap_or_default() {
        let is_declared = declared.iter().any(|(name, version, groups, extras)| {
            *name == entry.normalized_name
                && *version == entry.specifier.as_deref()
                && match &entry.scope {
                    // requires-dist holds the main dependencies and every extra.
                    UvRootScope::Main | UvRootScope::Extra(_) => groups.is_empty(),
                    scope => in_section(groups, extras, scope),
                }
        });
        if !is_declared {
            return Err(crate::remedy::problem(
                &crate::remedy::UV_LOCK,
                format!(
                    "Broken lockfile '{}': '{}{}' is recorded in the root {} but is not declared that way in pyproject.toml",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(&entry.normalized_name),
                    crate::report::sanitize_for_terminal(entry.specifier.as_deref().unwrap_or("")),
                    crate::report::sanitize_for_terminal(&entry.scope.metadata_section())
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn effective_python_profile(
    lock_profile: Option<&PythonLockfileProfile>,
) -> PythonProfile {
    lock_profile
        .map(|lock_profile| lock_profile.environment.clone())
        .unwrap_or_else(PythonProfile::runtime_for_current_host)
}

pub(crate) fn root_marker_matches_profile(
    marker: Option<&str>,
    profile: &PythonProfile,
) -> Result<bool> {
    match marker {
        Some(marker) => evaluate_marker_for_profile_extras(marker, profile),
        None => Ok(true),
    }
}

pub(crate) fn merge_selected_scalar(
    current: &mut Option<String>,
    next: Option<&str>,
    package_name: &str,
    field: &str,
) -> Result<()> {
    let Some(next) = next.filter(|value| !value.trim().is_empty()) else {
        return Ok(());
    };
    match current {
        Some(current) if current != next => bail!(
            "Dependency '{}' has multiple in-scope uv root {} entries and cannot be trusted exactly",
            crate::report::sanitize_for_terminal(package_name),
            field
        ),
        Some(_) => Ok(()),
        None => {
            *current = Some(next.to_string());
            Ok(())
        }
    }
}

/// Compare a manifest specifier with the in-scope root metadata. `requires-dist` (main
/// dependencies and extras) and each selected `requires-dev` group are merged separately, so a
/// package may legitimately carry a different specifier in a dependency group than in the main
/// dependencies; the manifest specifier must equal one of them.
pub(crate) fn match_root_specifier(
    entries: &[UvRootRequiresEntry],
    normalized_name: &str,
    profile: &PythonProfile,
    wanted: Option<&str>,
) -> Result<UvRootSpecifierMatch> {
    let mut by_section: std::collections::BTreeMap<UvRootScope, Option<String>> =
        std::collections::BTreeMap::new();
    for entry in entries {
        if entry.normalized_name != normalized_name
            || !entry.scope.in_profile(profile)
            || !root_marker_matches_profile(entry.marker.as_deref(), profile)?
        {
            continue;
        }
        let section = match &entry.scope {
            UvRootScope::Extra(_) => UvRootScope::Main,
            scope => scope.clone(),
        };
        let field = if section == UvRootScope::Main {
            "requires-dist"
        } else {
            "requires-dev"
        };
        merge_selected_scalar(
            by_section.entry(section).or_default(),
            entry.specifier.as_deref(),
            normalized_name,
            field,
        )?;
    }
    if by_section.is_empty() {
        return Ok(UvRootSpecifierMatch::Missing);
    }
    if by_section
        .values()
        .any(|specifier| specifier.as_deref() == wanted)
    {
        return Ok(UvRootSpecifierMatch::Matched);
    }
    Ok(UvRootSpecifierMatch::Mismatch(
        by_section.into_values().next().flatten(),
    ))
}

pub(crate) fn select_root_dependency(
    entries: &[UvRootDependencyEntry],
    normalized_name: &str,
    profile: &PythonProfile,
) -> Result<Option<UvSelectedRootDependency>> {
    let mut selected = false;
    let mut version = None;
    let mut requested_extras = BTreeSet::new();
    for entry in entries {
        if entry.normalized_name != normalized_name
            || !entry.scope.in_profile(profile)
            || !root_marker_matches_profile(entry.marker.as_deref(), profile)?
        {
            continue;
        }
        selected = true;
        // Across every environment a root may lock one version per fork; the coverage graph
        // leaves the version open and walks them all.
        if !profile.any_environment {
            merge_selected_scalar(
                &mut version,
                entry.version.as_deref(),
                normalized_name,
                "dependency version",
            )?;
        }
        requested_extras.extend(entry.requested_extras.iter().cloned());
    }
    Ok(selected.then_some(UvSelectedRootDependency {
        version,
        requested_extras,
    }))
}

pub(crate) fn root_package(parsed: &toml::Value) -> Option<&toml::value::Table> {
    package_entries(parsed)
        .into_iter()
        .find(|pkg| is_local_root_package(pkg))
}

/// A table of named dependency lists (`optional-dependencies`, `dev-dependencies`,
/// `metadata.requires-dev`), each scoped by its normalized key.
pub(crate) fn scoped_root_lists<'a>(
    value: Option<&'a toml::Value>,
    label: &str,
    scope: fn(String) -> UvRootScope,
) -> Result<Vec<(UvRootScope, &'a toml::value::Table)>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let table = value
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Broken uv.lock: root {label} must be a table"))?;
    let mut lists = Vec::new();
    for (key, entries) in table {
        for entry in lock_dependency_tables(entries, &format!("root {label}"))? {
            lists.push((scope(normalize_name(key)), entry));
        }
    }
    Ok(lists)
}

pub(crate) fn extract_root_requires_entries(
    parsed: &toml::Value,
) -> Result<Option<Vec<UvRootRequiresEntry>>> {
    let Some(root) = root_package(parsed) else {
        return Ok(None);
    };
    let Some(metadata) = root.get("metadata") else {
        return Ok(None);
    };
    let metadata = metadata
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Broken uv.lock: root metadata must be a table"))?;
    let mut lists: Vec<(UvRootScope, &toml::value::Table)> = Vec::new();
    match metadata.get("requires-dist") {
        Some(requires) => {
            for entry in lock_dependency_tables(requires, "root requires-dist")? {
                lists.push((UvRootScope::Main, entry));
            }
        }
        // uv omits requires-dist for a project without dependencies, but a root that records
        // neither requires-dist nor requires-dev is not lock metadata sloppy-joe can trust.
        None if metadata.contains_key("requires-dev") => {}
        None => return Ok(None),
    }
    lists.extend(scoped_root_lists(
        metadata.get("requires-dev"),
        "requires-dev",
        UvRootScope::Group,
    )?);

    let mut entries = Vec::new();
    for (scope, table) in lists {
        let name = table
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("Broken uv.lock: root requirement entry missing name")
            })?;
        entries.push(UvRootRequiresEntry {
            normalized_name: normalize_name(name),
            specifier: table
                .get("specifier")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            marker: table
                .get("marker")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            scope,
        });
    }
    Ok(Some(entries))
}

pub(crate) fn extract_root_dependency_entries(
    parsed: &toml::Value,
) -> Result<Option<Vec<UvRootDependencyEntry>>> {
    let Some(root) = root_package(parsed) else {
        return Ok(None);
    };
    let mut lists: Vec<(UvRootScope, &toml::value::Table)> = Vec::new();
    if let Some(dependencies) = root.get("dependencies") {
        for entry in lock_dependency_tables(dependencies, "root dependencies")? {
            lists.push((UvRootScope::Main, entry));
        }
    }
    lists.extend(scoped_root_lists(
        root.get("optional-dependencies"),
        "optional-dependencies",
        UvRootScope::Extra,
    )?);
    lists.extend(scoped_root_lists(
        root.get("dev-dependencies"),
        "dev-dependencies",
        UvRootScope::Group,
    )?);

    let mut entries = Vec::new();
    for (scope, table) in lists {
        let name = table
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("Broken uv.lock: root dependency entry missing name"))?;
        entries.push(UvRootDependencyEntry {
            normalized_name: normalize_name(name),
            version: table
                .get("version")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            requested_extras: python_lock_dependency_extras(table)?,
            marker: table
                .get("marker")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            scope,
        });
    }
    Ok(Some(entries))
}
