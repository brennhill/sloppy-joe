use super::*;

/// Read a POM with XML comments removed, so commented-out declarations are
/// never mistaken for real ones, and reject documents Maven itself would not
/// read unambiguously.
pub(crate) fn read_pom(path: &Path) -> Result<String> {
    let raw = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)
        .context("Failed to read pom.xml")?;
    let content = strip_xml_comments(&raw)?;
    validate_pom_structure(&content)?;
    Ok(content)
}

/// Remove `<!-- ... -->` comments. An unterminated comment is an error: the
/// rest of the file would be ignored by an XML parser.
pub(crate) fn strip_xml_comments(content: &str) -> Result<String> {
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start + 4..].find("-->") else {
            bail!("Unterminated XML comment in POM");
        };
        rest = &rest[start + 4 + end + 3..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Sections that may appear only once under `<project>`. Which of two copies
/// Maven would honor depends on its version and strictness, so more than one
/// is rejected rather than guessed at.
pub(crate) const POM_SINGLE_SECTIONS: &[&str] = &[
    "parent",
    "properties",
    "dependencyManagement",
    "dependencies",
    "build",
    "profiles",
];

pub(crate) fn validate_pom_structure(content: &str) -> Result<()> {
    let Some(project) = maven_project_body(content) else {
        return Ok(());
    };
    let children = xml_direct_children(project);
    for section in POM_SINGLE_SECTIONS {
        if children.iter().filter(|(name, _)| name == section).count() > 1 {
            bail!(
                "Unsupported POM: <{section}> is declared more than once, so the versions Maven uses cannot be determined"
            );
        }
    }
    Ok(())
}

pub(crate) fn parse_pom(path: &Path) -> Result<Vec<Dependency>> {
    let content = read_pom(path)?;
    validate_pom_source_policy(&content, path)?;
    reject_core_extensions(path)?;
    let mut deps = Vec::new();
    let mut remaining = content.as_str();
    while let Some((_, body)) = remaining.split_once("<dependency>") {
        let (body, tail) = body
            .split_once("</dependency>")
            .context("Unterminated Maven dependency declaration")?;
        // Direct children only: an `<exclusion>` carries its own groupId,
        // artifactId and sometimes version, none of which belong to the dependency.
        let children = xml_direct_children(body);
        let direct = |name: &str| {
            children
                .iter()
                .find(|(child, _)| child == name)
                .map(|(_, value)| value.trim().to_string())
        };
        let group = direct("groupId").context("Maven dependency is missing groupId")?;
        let artifact = direct("artifactId").context("Maven dependency is missing artifactId")?;
        let dep = Dependency {
            name: format!("{group}:{artifact}"),
            version: direct("version").filter(|version| !version.is_empty()),
            ecosystem: crate::Ecosystem::Jvm,
            actual_name: None,
        };
        crate::parsers::validate_dependency(&dep, path)?;
        deps.push(dep);
        remaining = tail;
    }

    // Build-time coordinates: parent POM, build plugins and build extensions
    // are all downloaded from the repository and executed or inherited by the
    // build, so they get the same checks as dependencies.
    for (tag, default_group) in [
        ("parent", None),
        ("plugin", Some(MAVEN_DEFAULT_PLUGIN_GROUP)),
        ("extension", None),
    ] {
        for body in maven_element_bodies(&content, tag)? {
            let children = xml_direct_children(body);
            let child = |name: &str| {
                children
                    .iter()
                    .find(|(child, _)| child == name)
                    .map(|(_, value)| value.trim().to_string())
                    .filter(|value| !value.is_empty())
            };
            let group = child("groupId")
                .or_else(|| default_group.map(str::to_string))
                .ok_or_else(|| anyhow::anyhow!("Maven <{tag}> is missing groupId"))?;
            let artifact = child("artifactId")
                .ok_or_else(|| anyhow::anyhow!("Maven <{tag}> is missing artifactId"))?;
            let version = child("version");
            if tag == "parent"
                && maven_parent_is_local(
                    path,
                    &group,
                    &artifact,
                    version.as_deref(),
                    child("relativePath"),
                    children.iter().any(|(name, _)| name == "relativePath"),
                )?
            {
                continue;
            }
            let dep = Dependency {
                name: format!("{group}:{artifact}"),
                version,
                ecosystem: crate::Ecosystem::Jvm,
                actual_name: None,
            };
            crate::parsers::validate_dependency(&dep, path)?;
            deps.push(dep);
        }
    }
    Ok(deps)
}

pub(crate) const MAVEN_DEFAULT_PLUGIN_GROUP: &str = "org.apache.maven.plugins";

/// Return the inner text of every `<tag>...</tag>` element. These elements do
/// not nest in a POM, so the first closing tag terminates each body.
pub(crate) fn maven_element_bodies<'a>(content: &'a str, tag: &str) -> Result<Vec<&'a str>> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut bodies = Vec::new();
    let mut remaining = content;
    while let Some((_, body)) = remaining.split_once(open.as_str()) {
        let (body, tail) = body
            .split_once(close.as_str())
            .with_context(|| format!("Unterminated Maven <{tag}> declaration"))?;
        bodies.push(body);
        remaining = tail;
    }
    Ok(bodies)
}

/// Collect `(name, text)` for the direct child elements of an XML fragment,
/// ignoring anything nested deeper (plugin `<configuration>`, plugin
/// `<dependencies>`, ...). Self-closing children yield an empty value.
pub(crate) fn xml_direct_children(body: &str) -> Vec<(String, String)> {
    let mut children = Vec::new();
    let mut depth = 0usize;
    let mut current: Option<(String, usize)> = None;
    let mut rest = body;
    let mut offset = 0usize;
    while let Some(start) = rest.find('<') {
        let tag_start = offset + start;
        let after = &rest[start + 1..];
        let (inner, skip) = if after.starts_with("!--") {
            (None, after.find("-->").map(|i| i + 3))
        } else {
            match after.find('>') {
                Some(end) => (Some(&after[..end]), Some(end + 1)),
                None => (None, None),
            }
        };
        let Some(skip) = skip else {
            break;
        };
        let tag_end = tag_start + 1 + skip;
        if let Some(inner) = inner {
            if let Some(name) = inner.strip_prefix('/') {
                depth = depth.saturating_sub(1);
                if depth == 0
                    && let Some((open_name, value_start)) = current.take()
                    && open_name == name.trim()
                {
                    children.push((open_name, body[value_start..tag_start].to_string()));
                }
            } else if !inner.starts_with(['?', '!']) {
                let name = inner
                    .split(|c: char| c.is_whitespace() || c == '/')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                if inner.ends_with('/') {
                    if depth == 0 {
                        children.push((name, String::new()));
                    }
                } else {
                    if depth == 0 {
                        current = Some((name, tag_end));
                    }
                    depth += 1;
                }
            }
        }
        offset = tag_end;
        rest = &body[offset..];
    }
    children
}

/// Inner content of the root `<project ...>` element (attributes allowed).
pub(crate) fn maven_project_body(content: &str) -> Option<&str> {
    let mut search = 0usize;
    while let Some(found) = content[search..].find("<project") {
        let start = search + found + "<project".len();
        let next = content[start..].chars().next()?;
        if next == '>' || next.is_whitespace() {
            let open_end = start + content[start..].find('>')? + 1;
            let close = content.rfind("</project>")?;
            return (close >= open_end).then(|| &content[open_end..close]);
        }
        search = start;
    }
    None
}

/// Maven resolves `<parent>` from `relativePath` (default `../pom.xml`) when
/// the POM found there has the same coordinates; only otherwise is it fetched
/// from the repository. A local reactor parent is not a registry dependency.
pub(crate) fn maven_local_parent(
    pom_path: &Path,
    group: &str,
    artifact: &str,
    version: Option<&str>,
    relative_path: Option<String>,
    relative_path_declared: bool,
) -> Result<Option<(std::path::PathBuf, String)>> {
    let relative = match (relative_path, relative_path_declared) {
        (Some(relative), _) => relative,
        // `<relativePath/>` disables local lookup.
        (None, true) => return Ok(None),
        (None, false) => "../pom.xml".to_string(),
    };
    let base = pom_path.parent().unwrap_or(Path::new("."));
    let mut candidate = base.join(&relative);
    if !candidate.is_file() {
        candidate = candidate.join("pom.xml");
    }
    if !crate::parsers::path_detected(&candidate)? {
        return Ok(None);
    }
    let Ok(candidate) = std::fs::canonicalize(&candidate) else {
        return Ok(None);
    };
    let project_dir = std::fs::canonicalize(base)?;
    if let Some(root) = crate::cache::find_git_root(&project_dir).map_err(anyhow::Error::msg)?
        && !candidate.starts_with(&root)
    {
        return Ok(None);
    }
    let Ok(parent_content) =
        crate::parsers::read_file_limited(&candidate, crate::parsers::MAX_MANIFEST_BYTES)
    else {
        return Ok(None);
    };
    let Ok(parent_content) = strip_xml_comments(&parent_content) else {
        return Ok(None);
    };
    let Some(project_body) = maven_project_body(&parent_content) else {
        return Ok(None);
    };
    let children = xml_direct_children(project_body);
    let child = |name: &str| {
        children
            .iter()
            .find(|(child, _)| child == name)
            .map(|(_, value)| value.trim().to_string())
    };
    let inherited = children
        .iter()
        .find(|(name, _)| name == "parent")
        .map(|(_, body)| xml_direct_children(body));
    let inherited_child = |name: &str| {
        inherited.as_ref().and_then(|children| {
            children
                .iter()
                .find(|(child, _)| child == name)
                .map(|(_, value)| value.trim().to_string())
        })
    };
    let local_group = child("groupId").or_else(|| inherited_child("groupId"));
    let local_version = child("version").or_else(|| inherited_child("version"));
    let matches = local_group.as_deref() == Some(group)
        && child("artifactId").as_deref() == Some(artifact)
        && match (version, local_version.as_deref()) {
            (Some(wanted), Some(found)) => wanted == found,
            _ => true,
        };
    Ok(matches.then_some((candidate, parent_content)))
}

pub(crate) fn maven_parent_is_local(
    pom_path: &Path,
    group: &str,
    artifact: &str,
    version: Option<&str>,
    relative_path: Option<String>,
    relative_path_declared: bool,
) -> Result<bool> {
    Ok(maven_local_parent(
        pom_path,
        group,
        artifact,
        version,
        relative_path,
        relative_path_declared,
    )?
    .is_some())
}

pub(crate) fn xml_contains_open_tag(content: &str, target: &str) -> bool {
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '<' {
            i += 1;
            continue;
        }
        i += 1;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        if matches!(chars[i], '/' | '!' | '?') {
            while i < chars.len() && chars[i] != '>' {
                i += 1;
            }
            i += 1;
            continue;
        }

        let start = i;
        while i < chars.len() && !chars[i].is_whitespace() && !matches!(chars[i], '>' | '/') {
            i += 1;
        }
        let name: String = chars[start..i].iter().collect();
        let local_name = name.rsplit(':').next().unwrap_or(name.as_str());
        if local_name == target {
            return true;
        }
    }
    false
}

/// `.mvn/extensions.xml` (in the project or an ancestor up to the repository root) loads core
/// extensions into Maven itself before the build; they are fetched and run unscanned.
fn reject_core_extensions(pom_path: &Path) -> Result<()> {
    let Some(start) = pom_path.parent() else {
        return Ok(());
    };
    let start = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    let root = crate::cache::find_git_root(&start).ok().flatten();
    let mut current = Some(start.as_path());
    while let Some(dir) = current {
        let extensions = dir.join(".mvn").join("extensions.xml");
        if std::fs::symlink_metadata(&extensions).is_ok() {
            bail!(
                "Unsupported Maven core extensions in {}: extensions loaded by Maven itself are not scanned",
                extensions.display()
            );
        }
        if root.as_deref() == Some(dir) {
            break;
        }
        current = dir.parent();
    }
    Ok(())
}

pub(crate) fn validate_pom_source_policy(content: &str, path: &Path) -> Result<()> {
    for element in ["dependency", "parent", "plugin", "extension"] {
        if content.split('<').skip(1).any(|tag| {
            let name = tag
                .split(|c: char| c.is_whitespace() || matches!(c, '/' | '>'))
                .next()
                .unwrap_or_default();
            name.rsplit(':').next() == Some(element) && !tag.starts_with(&format!("{element}>"))
        }) {
            bail!(
                "Unsupported Maven {element} tag in {}: namespaced or attributed {element} elements cannot be verified",
                path.display()
            );
        }
    }
    if [
        "repositories",
        "pluginRepositories",
        "repository",
        "pluginRepository",
    ]
    .iter()
    .any(|tag| xml_contains_open_tag(content, tag))
    {
        bail!(
            "Unsupported Maven repository declaration in {}: custom repositories are not supported",
            path.display()
        );
    }

    if xml_contains_open_tag(content, "systemPath") {
        bail!(
            "Unsupported Maven dependency source in {}: systemPath dependencies are not supported",
            path.display()
        );
    }

    Ok(())
}
