use super::*;

#[derive(Debug, Clone)]
pub(crate) struct ParentRef {
    pub(crate) coordinate: Coordinate,
    pub(crate) relative_path: Option<String>,
    pub(crate) relative_path_declared: bool,
}

/// `Some(version)`, or `None` when the same key is managed twice with
/// different versions (which one applies depends on classifiers we do not model).
pub(crate) type Managed = HashMap<String, Option<String>>;

#[derive(Debug, Clone, Default)]
pub(crate) struct PomLevel {
    pub(crate) group: Option<String>,
    pub(crate) artifact: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) parent: Option<ParentRef>,
    pub(crate) properties: HashMap<String, String>,
    pub(crate) dep_mgmt: Managed,
    pub(crate) plugin_mgmt: Managed,
    pub(crate) imports: Vec<Coordinate>,
    /// Dependencies, build plugins and extensions this POM declares itself;
    /// a child inherits them.
    pub(crate) declared: Vec<Declared>,
    /// Values a `<profile>` assigns. A profile may be active by default or by
    /// `-P`, so a value that differs from the base cannot be relied on.
    pub(crate) profile_properties: Vec<(String, String)>,
    pub(crate) profile_dep_mgmt: Vec<(String, String)>,
    pub(crate) profile_plugin_mgmt: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub(crate) struct Declared {
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    pub(crate) plugin: bool,
}

/// Management key. Entries with a classifier or a non-jar type manage a
/// different artifact than the plain `group:artifact`, so they get their own key.
pub(crate) fn management_key(entry: &[(String, String)], group: &str, artifact: &str) -> String {
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

pub(crate) fn manage(map: &mut Managed, key: String, version: String) {
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

pub(crate) fn text_of(children: &[(String, String)], name: &str) -> Option<String> {
    children
        .iter()
        .find(|(child, _)| child == name)
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn body_of<'a>(children: &'a [(String, String)], name: &str) -> Option<&'a str> {
    children
        .iter()
        .find(|(child, _)| child == name)
        .map(|(_, value)| value.as_str())
}

pub(crate) fn parse_level(content: &str) -> Result<PomLevel> {
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

pub(crate) fn plugin_group(entry: &[(String, String)]) -> String {
    text_of(entry, "groupId").unwrap_or_else(|| MAVEN_DEFAULT_PLUGIN_GROUP.to_string())
}

pub(crate) fn collect_declared(children: &[(String, String)], level: &mut PomLevel) -> Result<()> {
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

pub(crate) fn collect_profiles(children: &[(String, String)], level: &mut PomLevel) -> Result<()> {
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
pub(crate) fn interpolate(value: &str, properties: &HashMap<String, String>) -> Option<String> {
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
pub(crate) fn candidate_values(
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
