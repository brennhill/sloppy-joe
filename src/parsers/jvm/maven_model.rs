//! Effective dependency versions of a Maven POM.
//!
//! A `pom.xml` rarely states every version itself: `${property}` references,
//! `<dependencyManagement>` / `<pluginManagement>` entries, imported BOMs and
//! the `<parent>` chain all supply versions Maven applies when it builds the
//! effective model. The static parser reads declarations only, so the versions
//! here are filled in afterwards from the same sources Maven uses. A version
//! that cannot be derived is left unset, never guessed: the scan then reports
//! it as unresolved instead of checking a placeholder such as `${x.version}`.
mod source;
pub(crate) use source::*;
mod level;
pub(crate) use level::*;

use super::*;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};

/// Parents deeper than this are treated as a broken chain.
const MAX_CHAIN_DEPTH: usize = 12;
/// POMs fetched from the repository for one project (parents and BOMs).
const MAX_FETCHES: usize = 40;
/// BOM imports nested deeper than this are not followed.
const MAX_IMPORT_DEPTH: usize = 4;
/// Largest POM accepted from the repository.
const MAX_POM_BYTES: usize = 2 * 1024 * 1024;

/// A POM and its ancestors, nearest first. A parent whose version is a
/// property cannot be fetched, so the chain simply ends there and whatever it
/// would have managed stays unresolved.
struct Chain {
    levels: Vec<PomLevel>,
}

struct Budget(usize);

impl Budget {
    fn spend(&mut self) -> Result<()> {
        if self.0 == 0 {
            bail!("Maven parent and BOM resolution needs more than {MAX_FETCHES} POMs");
        }
        self.0 -= 1;
        Ok(())
    }
}

async fn load_chain(
    first: PomLevel,
    first_path: Option<&Path>,
    source: &dyn PomSource,
    budget: &mut Budget,
) -> Result<Chain> {
    let mut levels = vec![first];
    let mut path = first_path.map(Path::to_path_buf);
    while let Some(parent) = levels.last().and_then(|level| level.parent.clone()) {
        if levels.len() >= MAX_CHAIN_DEPTH {
            bail!("Maven parent chain is deeper than {MAX_CHAIN_DEPTH} levels");
        }
        let coordinate = &parent.coordinate;
        if coordinate.version.contains("${") {
            break;
        }
        let local = match &path {
            Some(path) => maven_local_parent(
                path,
                &coordinate.group,
                &coordinate.artifact,
                Some(&coordinate.version),
                parent.relative_path.clone(),
                parent.relative_path_declared,
            )?,
            None => None,
        };
        let (next_path, content) = match local {
            Some((local_path, content)) => (Some(local_path), content),
            None => {
                budget.spend()?;
                (None, source.fetch(coordinate).await?)
            }
        };
        levels.push(parse_level(&content)?);
        path = next_path;
    }
    Ok(Chain { levels })
}

struct Effective {
    properties: HashMap<String, String>,
    dep_mgmt: Managed,
    plugin_mgmt: Managed,
    imports: Vec<Coordinate>,
    /// Other values a profile may give a property or a managed version. Which profile is
    /// active depends on the JDK, OS and `-P` flags of the build, so each is a candidate.
    property_alternatives: HashMap<String, Vec<String>>,
    dep_alternatives: HashMap<String, Vec<String>>,
    plugin_alternatives: HashMap<String, Vec<String>>,
}

fn add_alternative(map: &mut HashMap<String, Vec<String>>, key: &str, value: &str) {
    let values = map.entry(key.to_string()).or_default();
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

/// Profile properties of `chain.levels[index]`: where a profile gives a different value than the
/// base, both are candidates; where the base has none, the property stays unresolved.
fn apply_profile_properties(
    chain: &Chain,
    index: usize,
    properties: &mut HashMap<String, String>,
    alternatives: &mut HashMap<String, Vec<String>>,
) {
    for (name, value) in &chain.levels[index].profile_properties {
        if properties.get(name) == Some(value) {
            continue;
        }
        // A nearer POM's own property wins over an inherited profile's.
        if chain.levels[..index]
            .iter()
            .any(|nearer| nearer.properties.contains_key(name))
        {
            continue;
        }
        if properties.contains_key(name) {
            add_alternative(alternatives, name, value);
        } else {
            properties.remove(name);
        }
    }
}

fn apply_profile_management(
    base: &mut Managed,
    profile_entries: &[(String, String)],
    alternatives: &mut HashMap<String, Vec<String>>,
) {
    for (key, version) in profile_entries {
        match base.get(key) {
            Some(Some(current)) if current == version => {}
            Some(Some(_)) => add_alternative(alternatives, key, version),
            Some(None) => {}
            None => {
                base.insert(key.clone(), None);
            }
        }
    }
}

/// The built-in `project.*` / `pom.*` properties of the leaf POM.
fn insert_project_properties(
    properties: &mut HashMap<String, String>,
    leaf: &PomLevel,
    version: Option<String>,
    group: Option<String>,
) {
    let parent = leaf.parent.as_ref().map(|parent| &parent.coordinate);
    for (key, value) in [
        ("version", version.clone()),
        ("project.version", version.clone()),
        ("pom.version", version),
        ("groupId", group.clone()),
        ("project.groupId", group.clone()),
        ("pom.groupId", group),
        ("artifactId", leaf.artifact.clone()),
        ("project.artifactId", leaf.artifact.clone()),
        ("pom.artifactId", leaf.artifact.clone()),
        (
            "project.parent.version",
            parent.map(|parent| parent.version.clone()),
        ),
        (
            "project.parent.groupId",
            parent.map(|parent| parent.group.clone()),
        ),
        (
            "project.parent.artifactId",
            parent.map(|parent| parent.artifact.clone()),
        ),
    ] {
        if let Some(value) = value {
            properties.insert(key.to_string(), value);
        }
    }
}

fn effective(chain: &Chain) -> Effective {
    let mut properties = HashMap::new();
    let mut dep_mgmt = Managed::new();
    let mut plugin_mgmt = Managed::new();
    let mut imports = Vec::new();
    // Farthest ancestor first, so nearer levels override it.
    for level in chain.levels.iter().rev() {
        properties.extend(level.properties.clone());
        dep_mgmt.extend(level.dep_mgmt.clone());
        plugin_mgmt.extend(level.plugin_mgmt.clone());
    }
    for level in &chain.levels {
        imports.extend(level.imports.clone());
    }
    // A profile may be active (by default, JDK, OS or `-P`). Where it gives a different value
    // than the base, both are candidates; where the base has no value at all, the version
    // cannot be pinned and stays unresolved.
    let mut property_alternatives: HashMap<String, Vec<String>> = HashMap::new();
    let mut dep_alternatives: HashMap<String, Vec<String>> = HashMap::new();
    let mut plugin_alternatives: HashMap<String, Vec<String>> = HashMap::new();
    for (index, level) in chain.levels.iter().enumerate() {
        apply_profile_properties(chain, index, &mut properties, &mut property_alternatives);
        apply_profile_management(
            &mut dep_mgmt,
            &level.profile_dep_mgmt,
            &mut dep_alternatives,
        );
        apply_profile_management(
            &mut plugin_mgmt,
            &level.profile_plugin_mgmt,
            &mut plugin_alternatives,
        );
    }
    let leaf = &chain.levels[0];
    let parent_coordinate = leaf.parent.as_ref().map(|parent| &parent.coordinate);
    let group = leaf
        .group
        .clone()
        .or_else(|| parent_coordinate.map(|parent| parent.group.clone()));
    let version = leaf
        .version
        .clone()
        .or_else(|| parent_coordinate.map(|parent| parent.version.clone()));
    // Interpolate the project's own version before exposing it, so
    // `<version>${revision}</version>` settles to the property's value.
    let version = version.and_then(|version| interpolate(&version, &properties));
    insert_project_properties(&mut properties, leaf, version, group);
    Effective {
        properties,
        dep_mgmt,
        plugin_mgmt,
        imports,
        property_alternatives,
        dep_alternatives,
        plugin_alternatives,
    }
}

/// Dependency management a BOM contributes, with the BOM's own properties
/// applied. Nested imports are followed up to [`MAX_IMPORT_DEPTH`].
async fn bom_management(
    bom: &Coordinate,
    source: &dyn PomSource,
    budget: &mut Budget,
    depth: usize,
    seen: &mut HashSet<(String, String, String)>,
) -> Result<Vec<(String, Option<String>)>> {
    if depth > MAX_IMPORT_DEPTH {
        bail!(
            "BOM {}:{}:{} is imported more than {MAX_IMPORT_DEPTH} levels deep",
            bom.group,
            bom.artifact,
            bom.version
        );
    }
    let key = (bom.group.clone(), bom.artifact.clone(), bom.version.clone());
    if !seen.insert(key) {
        return Ok(Vec::new());
    }
    budget.spend()?;
    let level = parse_level(&source.fetch(bom).await?)?;
    let chain = load_chain(level, None, source, budget).await?;
    let model = effective(&chain);
    let mut managed: Vec<(String, Option<String>)> = Vec::new();
    for (name, version) in &model.dep_mgmt {
        // A BOM version a profile could change is not pinned.
        let resolved = version
            .as_deref()
            .and_then(|version| {
                candidate_values(version, &model.properties, &model.property_alternatives)
            })
            .filter(|values| values.len() == 1 && !model.dep_alternatives.contains_key(name))
            .map(|mut values| values.remove(0));
        managed.push((name.clone(), resolved));
    }
    for import in &model.imports {
        let Some(version) = interpolate(&import.version, &model.properties) else {
            continue;
        };
        let nested = Coordinate {
            version,
            ..import.clone()
        };
        let inner = Box::pin(bom_management(&nested, source, budget, depth + 1, seen)).await?;
        managed.extend(inner);
    }
    Ok(managed)
}

/// Property names a project's `.mvn/maven.config` (or an ancestor's, up to the
/// repository root) defines on the command line. Those override the POM, and
/// their values are not modeled, so the properties are dropped.
fn maven_config_defines(pom_path: &Path) -> Vec<String> {
    let Some(start) = pom_path.parent() else {
        return Vec::new();
    };
    let start = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    let root = crate::cache::find_git_root(&start).ok().flatten();
    let mut names = Vec::new();
    let mut current = Some(start.as_path());
    while let Some(dir) = current {
        if let Ok(config) = std::fs::read_to_string(dir.join(".mvn").join("maven.config")) {
            let mut tokens = config.split_whitespace();
            while let Some(token) = tokens.next() {
                let define = if let Some(rest) = token.strip_prefix("--define=") {
                    Some(rest)
                } else if token == "-D" || token == "--define" {
                    tokens.next()
                } else {
                    token.strip_prefix("-D")
                };
                if let Some(define) = define {
                    let name = define.split('=').next().unwrap_or(define);
                    if !name.is_empty() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        if root.as_deref() == Some(dir) {
            break;
        }
        current = dir.parent();
    }
    names
}

/// Fill in the versions Maven would derive for `deps`, which were read
/// statically from `pom_path`. Fetch failures are errors (fail closed);
/// versions that cannot be derived come back as `None`.
pub(crate) async fn resolve_pom_versions(
    pom_path: &Path,
    deps: Vec<Dependency>,
    source: &dyn PomSource,
) -> Result<Vec<Dependency>> {
    let content = read_pom(pom_path)?;
    let leaf = parse_level(&content)?;
    let mut budget = Budget(MAX_FETCHES);
    let chain = load_chain(leaf, Some(pom_path), source, &mut budget).await?;
    let mut model = effective(&chain);
    for name in maven_config_defines(pom_path) {
        model.properties.remove(&name);
        model.property_alternatives.remove(&name);
    }
    merge_bom_management(&mut model, source, &mut budget).await?;

    let mut plugin_names = used_plugin_names(&content)?;
    let deps = with_inherited_declarations(deps, &chain, &mut plugin_names, pom_path)?;

    let mut resolved = Vec::new();
    for dep in deps {
        for version in candidate_versions(&dep, &model, &plugin_names) {
            resolved.push(Dependency {
                version,
                ..dep.clone()
            });
        }
    }
    Ok(resolved)
}

/// BOMs: entries the POM chain manages itself win; among imports the first wins.
async fn merge_bom_management(
    model: &mut Effective,
    source: &dyn PomSource,
    budget: &mut Budget,
) -> Result<()> {
    let mut seen = HashSet::new();
    let imports = model.imports.clone();
    for import in imports {
        let Some(version) = interpolate(&import.version, &model.properties) else {
            continue;
        };
        let import = Coordinate { version, ..import };
        for (name, version) in bom_management(&import, source, budget, 1, &mut seen).await? {
            model.dep_mgmt.entry(name).or_insert(version);
        }
    }
    Ok(())
}

/// Plugins the project uses (build, reporting and profile sections) are versioned from
/// plugin management; a `pluginManagement` entry alone never runs, so it is excluded.
/// A plugin that appears only in `pluginManagement` still takes its version from the
/// parent's plugin management, unless a dependency shares its name.
fn used_plugin_names(content: &str) -> Result<HashSet<String>> {
    let mut plugin_names: HashSet<String> = HashSet::new();
    let mut outside_management = String::new();
    let mut rest = content;
    while let Some(start) = rest.find("<pluginManagement>") {
        outside_management.push_str(&rest[..start]);
        match rest[start..].find("</pluginManagement>") {
            Some(end) => rest = &rest[start + end + "</pluginManagement>".len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    outside_management.push_str(rest);
    for body in maven_element_bodies(&outside_management, "plugin")? {
        let entry = xml_direct_children(body);
        if let Some(artifact) = text_of(&entry, "artifactId") {
            plugin_names.insert(format!("{}:{artifact}", plugin_group(&entry)));
        }
    }
    let mut dependency_names = HashSet::new();
    for body in maven_element_bodies(content, "dependency")? {
        let entry = xml_direct_children(body);
        if let (Some(group), Some(artifact)) =
            (text_of(&entry, "groupId"), text_of(&entry, "artifactId"))
        {
            dependency_names.insert(format!("{group}:{artifact}"));
        }
    }
    for body in maven_element_bodies(content, "plugin")? {
        let entry = xml_direct_children(body);
        if let Some(artifact) = text_of(&entry, "artifactId") {
            let name = format!("{}:{artifact}", plugin_group(&entry));
            if !dependency_names.contains(&name) {
                plugin_names.insert(name);
            }
        }
    }
    Ok(plugin_names)
}

/// Everything an ancestor declares is inherited by this project, so it is
/// installed (or executed) by this build too.
fn with_inherited_declarations(
    mut deps: Vec<Dependency>,
    chain: &Chain,
    plugin_names: &mut HashSet<String>,
    pom_path: &Path,
) -> Result<Vec<Dependency>> {
    let mut known: HashSet<(String, Option<String>)> = deps
        .iter()
        .map(|dep| (dep.name.clone(), dep.version.clone()))
        .collect();
    for level in chain.levels.iter().skip(1) {
        let mut inherited: Vec<(String, Option<String>, bool)> = level
            .declared
            .iter()
            .map(|declared| {
                (
                    declared.name.clone(),
                    declared.version.clone(),
                    declared.plugin,
                )
            })
            .collect();
        if let Some(parent) = &level.parent {
            let coordinate = &parent.coordinate;
            inherited.push((
                format!("{}:{}", coordinate.group, coordinate.artifact),
                Some(coordinate.version.clone()),
                false,
            ));
        }
        for (name, version, plugin) in inherited {
            if plugin {
                plugin_names.insert(name.clone());
            }
            if known.insert((name.clone(), version.clone())) {
                let dep = Dependency {
                    name,
                    version,
                    ecosystem: crate::Ecosystem::Jvm,
                    actual_name: None,
                };
                crate::parsers::validate_dependency(&dep, pom_path)?;
                deps.push(dep);
            }
        }
    }
    Ok(deps)
}

/// Every version the build could end up with for `raw`; empty when it cannot be derived.
fn resolve_all(model: &Effective, raw: &str) -> Vec<String> {
    candidate_values(raw, &model.properties, &model.property_alternatives).unwrap_or_default()
}

/// Every version a dependency could end up with; `[None]` when it cannot be pinned.
fn candidate_versions(
    dep: &Dependency,
    model: &Effective,
    plugin_names: &HashSet<String>,
) -> Vec<Option<String>> {
    match dep.version.as_deref() {
        Some(declared) if declared.contains("${") => {
            let values = resolve_all(model, declared);
            if values.is_empty() {
                vec![None]
            } else {
                values.into_iter().map(Some).collect()
            }
        }
        Some(declared) => vec![Some(declared.to_string())],
        None => managed_versions(dep, model, plugin_names),
    }
}

/// Versions from dependency or plugin management, plus every profile alternative.
fn managed_versions(
    dep: &Dependency,
    model: &Effective,
    plugin_names: &HashSet<String>,
) -> Vec<Option<String>> {
    let (map, alternatives) = if plugin_names.contains(&dep.name) {
        (&model.plugin_mgmt, &model.plugin_alternatives)
    } else {
        (&model.dep_mgmt, &model.dep_alternatives)
    };
    let Some(Some(base)) = map.get(&dep.name) else {
        return vec![None];
    };
    let mut values = resolve_all(model, base);
    let mut complete = !values.is_empty();
    for alternative in alternatives.get(&dep.name).into_iter().flatten() {
        let extra = resolve_all(model, alternative);
        complete &= !extra.is_empty();
        for value in extra {
            if !values.contains(&value) {
                values.push(value);
            }
        }
    }
    if complete {
        values.into_iter().map(Some).collect()
    } else {
        vec![None]
    }
}

#[cfg(test)]
#[path = "maven_model_tests.rs"]
mod tests;
