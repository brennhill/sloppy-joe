//! Effective dependency versions of a Maven POM.
//!
//! A `pom.xml` rarely states every version itself: `${property}` references,
//! `<dependencyManagement>` / `<pluginManagement>` entries, imported BOMs and
//! the `<parent>` chain all supply versions Maven applies when it builds the
//! effective model. The static parser reads declarations only, so the versions
//! here are filled in afterwards from the same sources Maven uses. A version
//! that cannot be derived is left unset, never guessed: the scan then reports
//! it as unresolved instead of checking a placeholder such as `${x.version}`.

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Coordinate {
    pub group: String,
    pub artifact: String,
    pub version: String,
}

/// Where parent and imported POMs come from.
#[async_trait]
pub(crate) trait PomSource: Send + Sync {
    async fn fetch(&self, coordinate: &Coordinate) -> Result<String>;
}

/// Maven Central's repository layout.
pub(crate) struct CentralPomSource {
    client: reqwest::Client,
    base: String,
}

impl CentralPomSource {
    pub(crate) fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base: crate::registry::gradle_plugins::MAVEN_CENTRAL_URL.to_string(),
        }
    }
}

fn plain_segment(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

#[async_trait]
impl PomSource for CentralPomSource {
    async fn fetch(&self, coordinate: &Coordinate) -> Result<String> {
        let Coordinate {
            group,
            artifact,
            version,
        } = coordinate;
        if !plain_segment(group) || !plain_segment(artifact) || !plain_segment(version) {
            bail!("invalid Maven coordinate {group}:{artifact}:{version}");
        }
        let url = format!(
            "{}{}/{artifact}/{version}/{artifact}-{version}.pom",
            self.base,
            group.replace('.', "/")
        );
        let mut resp = crate::registry::retry_get(&self.client, &url).await?;
        if !resp.status().is_success() {
            bail!(
                "POM {group}:{artifact}:{version} could not be fetched from Maven Central (HTTP {}); its managed versions cannot be verified",
                resp.status()
            );
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_POM_BYTES {
                bail!("POM {group}:{artifact}:{version} exceeds {MAX_POM_BYTES} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

#[derive(Debug, Clone)]
struct ParentRef {
    coordinate: Coordinate,
    relative_path: Option<String>,
    relative_path_declared: bool,
}

/// `Some(version)`, or `None` when the same key is managed twice with
/// different versions (which one applies depends on classifiers we do not model).
type Managed = HashMap<String, Option<String>>;

#[derive(Debug, Clone, Default)]
struct PomLevel {
    group: Option<String>,
    artifact: Option<String>,
    version: Option<String>,
    parent: Option<ParentRef>,
    properties: HashMap<String, String>,
    dep_mgmt: Managed,
    plugin_mgmt: Managed,
    imports: Vec<Coordinate>,
}

fn manage(map: &mut Managed, key: String, version: String) {
    match map.get(&key) {
        Some(existing) if existing.as_deref() != Some(version.as_str()) => {
            map.insert(key, None);
        }
        Some(_) => {}
        None => {
            map.insert(key, Some(version));
        }
    }
}

fn text_of(children: &[(String, String)], name: &str) -> Option<String> {
    children
        .iter()
        .find(|(child, _)| child == name)
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn body_of<'a>(children: &'a [(String, String)], name: &str) -> Option<&'a str> {
    children
        .iter()
        .find(|(child, _)| child == name)
        .map(|(_, value)| value.as_str())
}

fn parse_level(content: &str) -> Result<PomLevel> {
    let Some(project) = maven_project_body(content) else {
        bail!("POM has no <project> element");
    };
    let children = xml_direct_children(project);
    let mut level = PomLevel {
        group: text_of(&children, "groupId"),
        artifact: text_of(&children, "artifactId"),
        version: text_of(&children, "version"),
        ..PomLevel::default()
    };
    if let Some(parent) = body_of(&children, "parent") {
        let parent = xml_direct_children(parent);
        if let (Some(group), Some(artifact), Some(version)) = (
            text_of(&parent, "groupId"),
            text_of(&parent, "artifactId"),
            text_of(&parent, "version"),
        ) {
            level.parent = Some(ParentRef {
                coordinate: Coordinate {
                    group,
                    artifact,
                    version,
                },
                relative_path: text_of(&parent, "relativePath"),
                relative_path_declared: parent.iter().any(|(name, _)| name == "relativePath"),
            });
        }
    }
    if let Some(properties) = body_of(&children, "properties") {
        for (name, value) in xml_direct_children(properties) {
            level.properties.insert(name, value.trim().to_string());
        }
    }
    if let Some(management) = body_of(&children, "dependencyManagement")
        && let Some(dependencies) = body_of(&xml_direct_children(management), "dependencies")
    {
        for body in maven_element_bodies(dependencies, "dependency")? {
            let entry = xml_direct_children(body);
            let (Some(group), Some(artifact), Some(version)) = (
                text_of(&entry, "groupId"),
                text_of(&entry, "artifactId"),
                text_of(&entry, "version"),
            ) else {
                continue;
            };
            let is_import = text_of(&entry, "scope").as_deref() == Some("import")
                && text_of(&entry, "type").as_deref() == Some("pom");
            if is_import {
                level.imports.push(Coordinate {
                    group,
                    artifact,
                    version,
                });
            } else {
                manage(&mut level.dep_mgmt, format!("{group}:{artifact}"), version);
            }
        }
    }
    if let Some(build) = body_of(&children, "build")
        && let Some(management) = body_of(&xml_direct_children(build), "pluginManagement")
        && let Some(plugins) = body_of(&xml_direct_children(management), "plugins")
    {
        for body in maven_element_bodies(plugins, "plugin")? {
            let entry = xml_direct_children(body);
            let group = text_of(&entry, "groupId")
                .unwrap_or_else(|| MAVEN_DEFAULT_PLUGIN_GROUP.to_string());
            let (Some(artifact), Some(version)) =
                (text_of(&entry, "artifactId"), text_of(&entry, "version"))
            else {
                continue;
            };
            manage(
                &mut level.plugin_mgmt,
                format!("{group}:{artifact}"),
                version,
            );
        }
    }
    Ok(level)
}

/// `${name}` substitution against `properties`. `None` when a reference is
/// undefined, unterminated, or the substitution does not settle.
fn interpolate(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    let mut current = value.trim().to_string();
    for _ in 0..16 {
        let Some(start) = current.find("${") else {
            return Some(current);
        };
        let end = start + current[start..].find('}')?;
        let replacement = properties.get(&current[start + 2..end])?;
        current = format!(
            "{}{}{}",
            &current[..start],
            replacement,
            &current[end + 1..]
        );
    }
    None
}

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
            parent_coordinate.map(|parent| parent.version.clone()),
        ),
        (
            "project.parent.groupId",
            parent_coordinate.map(|parent| parent.group.clone()),
        ),
        (
            "project.parent.artifactId",
            parent_coordinate.map(|parent| parent.artifact.clone()),
        ),
    ] {
        if let Some(value) = value {
            properties.insert(key.to_string(), value);
        }
    }
    Effective {
        properties,
        dep_mgmt,
        plugin_mgmt,
        imports,
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
        let resolved = version
            .as_deref()
            .and_then(|version| interpolate(version, &model.properties));
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

/// Fill in the versions Maven would derive for `deps`, which were read
/// statically from `pom_path`. Fetch failures are errors (fail closed);
/// versions that cannot be derived come back as `None`.
pub(crate) async fn resolve_pom_versions(
    pom_path: &Path,
    deps: Vec<Dependency>,
    source: &dyn PomSource,
) -> Result<Vec<Dependency>> {
    let content = super::super::read_file_limited(pom_path, super::super::MAX_MANIFEST_BYTES)
        .context("Failed to read pom.xml")?;
    let leaf = parse_level(&content)?;
    let mut budget = Budget(MAX_FETCHES);
    let chain = load_chain(leaf, Some(pom_path), source, &mut budget).await?;
    let mut model = effective(&chain);

    // BOMs: entries the POM chain manages itself win; among imports the first wins.
    let mut seen = HashSet::new();
    let imports = model.imports.clone();
    for import in imports {
        let Some(version) = interpolate(&import.version, &model.properties) else {
            continue;
        };
        let import = Coordinate { version, ..import };
        for (name, version) in bom_management(&import, source, &mut budget, 1, &mut seen).await? {
            model.dep_mgmt.entry(name).or_insert(version);
        }
    }

    let mut plugin_names = HashSet::new();
    for body in maven_element_bodies(&content, "plugin")? {
        let entry = xml_direct_children(body);
        if let Some(artifact) = text_of(&entry, "artifactId") {
            let group = text_of(&entry, "groupId")
                .unwrap_or_else(|| MAVEN_DEFAULT_PLUGIN_GROUP.to_string());
            plugin_names.insert(format!("{group}:{artifact}"));
        }
    }

    let managed_version = |map: &Managed, name: &str| -> Option<Option<String>> {
        map.get(name).map(|version| {
            version
                .as_deref()
                .and_then(|version| interpolate(version, &model.properties))
        })
    };

    Ok(deps
        .into_iter()
        .map(|mut dep| {
            dep.version = match dep.version.as_deref() {
                Some(declared) if declared.contains("${") => {
                    interpolate(declared, &model.properties)
                }
                Some(declared) => Some(declared.to_string()),
                None => {
                    let (first, second) = if plugin_names.contains(&dep.name) {
                        (&model.plugin_mgmt, &model.dep_mgmt)
                    } else {
                        (&model.dep_mgmt, &model.plugin_mgmt)
                    };
                    managed_version(first, &dep.name)
                        .or_else(|| managed_version(second, &dep.name))
                        .flatten()
                }
            };
            dep
        })
        .collect())
}

#[cfg(test)]
#[path = "maven_model_tests.rs"]
mod tests;
