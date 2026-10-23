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
    /// Dependencies, build plugins and extensions this POM declares itself;
    /// a child inherits them.
    declared: Vec<Declared>,
    /// Values a `<profile>` assigns. A profile may be active by default or by
    /// `-P`, so a value that differs from the base cannot be relied on.
    profile_properties: Vec<(String, String)>,
    profile_dep_mgmt: Vec<(String, String)>,
    profile_plugin_mgmt: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
struct Declared {
    name: String,
    version: Option<String>,
    plugin: bool,
}

/// Management key. Entries with a classifier or a non-jar type manage a
/// different artifact than the plain `group:artifact`, so they get their own key.
fn management_key(entry: &[(String, String)], group: &str, artifact: &str) -> String {
    let classifier = text_of(entry, "classifier");
    let kind = text_of(entry, "type").filter(|kind| kind != "jar");
    match (classifier, kind) {
        (None, None) => format!("{group}:{artifact}"),
        (classifier, kind) => format!(
            "{group}:{artifact}:{}:{}",
            classifier.unwrap_or_default(),
            kind.unwrap_or_default()
        ),
    }
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
    let content = strip_xml_comments(content)?;
    validate_pom_structure(&content)?;
    let Some(project) = maven_project_body(&content) else {
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
                let key = management_key(&entry, &group, &artifact);
                manage(&mut level.dep_mgmt, key, version);
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
            let key = management_key(&entry, &group, &artifact);
            manage(&mut level.plugin_mgmt, key, version);
        }
    }
    collect_declared(&children, &mut level)?;
    collect_profiles(&children, &mut level)?;
    Ok(level)
}

fn plugin_group(entry: &[(String, String)]) -> String {
    text_of(entry, "groupId").unwrap_or_else(|| MAVEN_DEFAULT_PLUGIN_GROUP.to_string())
}

fn collect_declared(children: &[(String, String)], level: &mut PomLevel) -> Result<()> {
    if let Some(dependencies) = body_of(children, "dependencies") {
        for body in maven_element_bodies(dependencies, "dependency")? {
            let entry = xml_direct_children(body);
            if let (Some(group), Some(artifact)) =
                (text_of(&entry, "groupId"), text_of(&entry, "artifactId"))
            {
                level.declared.push(Declared {
                    name: format!("{group}:{artifact}"),
                    version: text_of(&entry, "version"),
                    plugin: false,
                });
            }
        }
    }
    if let Some(reporting) = body_of(children, "reporting")
        && let Some(plugins) = body_of(&xml_direct_children(reporting), "plugins")
    {
        for body in maven_element_bodies(plugins, "plugin")? {
            let entry = xml_direct_children(body);
            if let Some(artifact) = text_of(&entry, "artifactId") {
                level.declared.push(Declared {
                    name: format!("{}:{artifact}", plugin_group(&entry)),
                    version: text_of(&entry, "version"),
                    plugin: true,
                });
            }
        }
    }
    if let Some(build) = body_of(children, "build") {
        let build = xml_direct_children(build);
        for (section, element, default_group) in [
            ("plugins", "plugin", true),
            ("extensions", "extension", false),
        ] {
            let Some(body) = body_of(&build, section) else {
                continue;
            };
            for body in maven_element_bodies(body, element)? {
                let entry = xml_direct_children(body);
                let group = if default_group {
                    Some(plugin_group(&entry))
                } else {
                    text_of(&entry, "groupId")
                };
                if let (Some(group), Some(artifact)) = (group, text_of(&entry, "artifactId")) {
                    level.declared.push(Declared {
                        name: format!("{group}:{artifact}"),
                        version: text_of(&entry, "version"),
                        plugin: true,
                    });
                }
            }
        }
    }
    Ok(())
}

fn collect_profiles(children: &[(String, String)], level: &mut PomLevel) -> Result<()> {
    let Some(profiles) = body_of(children, "profiles") else {
        return Ok(());
    };
    for body in maven_element_bodies(profiles, "profile")? {
        let profile = xml_direct_children(body);
        if let Some(properties) = body_of(&profile, "properties") {
            for (name, value) in xml_direct_children(properties) {
                level
                    .profile_properties
                    .push((name, value.trim().to_string()));
            }
        }
        if let Some(management) = body_of(&profile, "dependencyManagement")
            && let Some(dependencies) = body_of(&xml_direct_children(management), "dependencies")
        {
            for body in maven_element_bodies(dependencies, "dependency")? {
                let entry = xml_direct_children(body);
                if let (Some(group), Some(artifact), Some(version)) = (
                    text_of(&entry, "groupId"),
                    text_of(&entry, "artifactId"),
                    text_of(&entry, "version"),
                ) {
                    let key = management_key(&entry, &group, &artifact);
                    level.profile_dep_mgmt.push((key, version));
                }
            }
        }
        if let Some(build) = body_of(&profile, "build")
            && let Some(management) = body_of(&xml_direct_children(build), "pluginManagement")
            && let Some(plugins) = body_of(&xml_direct_children(management), "plugins")
        {
            for body in maven_element_bodies(plugins, "plugin")? {
                let entry = xml_direct_children(body);
                if let (Some(artifact), Some(version)) =
                    (text_of(&entry, "artifactId"), text_of(&entry, "version"))
                {
                    let key = management_key(&entry, &plugin_group(&entry), &artifact);
                    level.profile_plugin_mgmt.push((key, version));
                }
            }
        }
    }
    Ok(())
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

/// Every value `value` can take once its `${name}` references are substituted, counting
/// the alternatives a profile may select. `None` when a reference is undefined, the
/// substitution does not settle, or there are too many combinations to enumerate.
fn candidate_values(
    value: &str,
    properties: &HashMap<String, String>,
    alternatives: &HashMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    fn expand(
        current: String,
        properties: &HashMap<String, String>,
        alternatives: &HashMap<String, Vec<String>>,
        depth: usize,
        out: &mut Vec<String>,
    ) -> Option<()> {
        let Some(start) = current.find("${") else {
            if !out.contains(&current) {
                out.push(current);
            }
            return (out.len() <= 32).then_some(());
        };
        if depth > 16 {
            return None;
        }
        let end = start + current[start..].find('}')?;
        let name = &current[start + 2..end];
        let base = properties.get(name)?;
        let choices = std::iter::once(base).chain(alternatives.get(name).into_iter().flatten());
        for choice in choices {
            let next = format!("{}{}{}", &current[..start], choice, &current[end + 1..]);
            expand(next, properties, alternatives, depth + 1, out)?;
        }
        Some(())
    }
    let mut out = Vec::new();
    expand(
        value.trim().to_string(),
        properties,
        alternatives,
        0,
        &mut out,
    )?;
    Some(out)
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
        for (name, value) in &level.profile_properties {
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
                add_alternative(&mut property_alternatives, name, value);
            } else {
                properties.remove(name);
            }
        }
        for (key, version) in &level.profile_dep_mgmt {
            match dep_mgmt.get(key) {
                Some(Some(base)) if base == version => {}
                Some(Some(_)) => add_alternative(&mut dep_alternatives, key, version),
                Some(None) => {}
                None => {
                    dep_mgmt.insert(key.clone(), None);
                }
            }
        }
        for (key, version) in &level.profile_plugin_mgmt {
            match plugin_mgmt.get(key) {
                Some(Some(base)) if base == version => {}
                Some(Some(_)) => add_alternative(&mut plugin_alternatives, key, version),
                Some(None) => {}
                None => {
                    plugin_mgmt.insert(key.clone(), None);
                }
            }
        }
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
    let root = crate::config::registry::find_git_root(&start)
        .ok()
        .flatten();
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

    // Plugins the project uses (build, reporting and profile sections) are versioned from
    // plugin management; a `pluginManagement` entry alone never runs, so it is excluded.
    let mut plugin_names: HashSet<String> = HashSet::new();
    let mut outside_management = String::new();
    let mut rest = content.as_str();
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
    // A plugin that appears only in `pluginManagement` (configuration, no version) still takes
    // its version from the parent's plugin management, unless a dependency shares its name.
    let mut dependency_names = HashSet::new();
    for body in maven_element_bodies(&content, "dependency")? {
        let entry = xml_direct_children(body);
        if let (Some(group), Some(artifact)) =
            (text_of(&entry, "groupId"), text_of(&entry, "artifactId"))
        {
            dependency_names.insert(format!("{group}:{artifact}"));
        }
    }
    for body in maven_element_bodies(&content, "plugin")? {
        let entry = xml_direct_children(body);
        if let Some(artifact) = text_of(&entry, "artifactId") {
            let name = format!("{}:{artifact}", plugin_group(&entry));
            if !dependency_names.contains(&name) {
                plugin_names.insert(name);
            }
        }
    }

    // Everything an ancestor declares is inherited by this project, so it is
    // installed (or executed) by this build too.
    let mut deps = deps;
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

    // Every version the build could end up with; a dependency is reported once per candidate.
    let resolve_all = |raw: &str| -> Vec<String> {
        candidate_values(raw, &model.properties, &model.property_alternatives).unwrap_or_default()
    };

    let mut resolved = Vec::new();
    for dep in deps {
        let versions: Vec<Option<String>> = match dep.version.as_deref() {
            Some(declared) if declared.contains("${") => {
                let values = resolve_all(declared);
                if values.is_empty() {
                    vec![None]
                } else {
                    values.into_iter().map(Some).collect()
                }
            }
            Some(declared) => vec![Some(declared.to_string())],
            None => {
                let (map, alternatives) = if plugin_names.contains(&dep.name) {
                    (&model.plugin_mgmt, &model.plugin_alternatives)
                } else {
                    (&model.dep_mgmt, &model.dep_alternatives)
                };
                match map.get(&dep.name) {
                    Some(Some(base)) => {
                        let mut values = resolve_all(base);
                        let mut complete = !values.is_empty();
                        for alternative in alternatives.get(&dep.name).into_iter().flatten() {
                            let extra = resolve_all(alternative);
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
                    _ => vec![None],
                }
            }
        };
        for version in versions {
            resolved.push(Dependency {
                version,
                ..dep.clone()
            });
        }
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "maven_model_tests.rs"]
mod tests;
