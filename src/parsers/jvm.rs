use crate::Dependency;
use anyhow::{Context, Result, bail};
use std::path::Path;

mod gradle_plugins;
pub(crate) mod maven_model;

/// Fill in the versions Maven derives from properties, management sections,
/// imported BOMs and the parent chain (see [`maven_model`]).
pub(crate) async fn resolve_maven_versions(
    pom_path: &Path,
    deps: Vec<Dependency>,
    client: reqwest::Client,
) -> Result<Vec<Dependency>> {
    maven_model::resolve_pom_versions(pom_path, deps, &maven_model::CentralPomSource::new(client))
        .await
}

/// A parsed Gradle build script: regular dependencies, the plugin marker
/// artifacts its `plugins {}` requests resolve to, and the repositories Gradle
/// consults for those plugins.
#[derive(Debug, Clone)]
pub(crate) struct GradleBuild {
    pub deps: Vec<Dependency>,
    pub plugins: Vec<Dependency>,
    pub plugin_repositories: Vec<crate::config::PluginRepository>,
    /// A build or settings script lists `google()`, so dependencies may also
    /// resolve from Google's Maven repository.
    pub uses_google_maven: bool,
    /// `buildscript { dependencies { classpath } }` artifacts: build tooling
    /// that runs in the build but never appears in `gradle.lockfile`.
    pub classpath: Vec<Dependency>,
    /// The classpath's `buildscript { repositories {} }` lists `google()`.
    pub classpath_uses_google_maven: bool,
}

const GRADLE_DEPENDENCY_CONFIGS: &[&str] = &[
    "implementation",
    "api",
    "compileOnly",
    "runtimeOnly",
    "testImplementation",
];

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let gradle = project_dir.join("build.gradle");
    if super::path_detected(&gradle)? {
        return parse_gradle(&gradle);
    }
    let gradle_kts = project_dir.join("build.gradle.kts");
    if super::path_detected(&gradle_kts)? {
        return parse_gradle(&gradle_kts);
    }
    let pom = project_dir.join("pom.xml");
    parse_pom(&pom)
}

pub(crate) fn parse_manifest(path: &Path) -> Result<Vec<Dependency>> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("build.gradle") | Some("build.gradle.kts") => parse_gradle(path),
        Some("pom.xml") => parse_pom(path),
        _ => bail!("Unsupported JVM manifest: {}", path.display()),
    }
}

fn parse_gradle(path: &Path) -> Result<Vec<Dependency>> {
    let build = parse_gradle_build(path)?;
    if let Some(url) = build
        .plugin_repositories
        .iter()
        .find_map(|repository| match repository {
            crate::config::PluginRepository::Custom(url) => Some(url),
            _ => None,
        })
    {
        bail!(
            "Unsupported Gradle plugin repository '{}' for {}: plugins from a custom plugin repository cannot be verified unless the repository is allowlisted in trusted_registries.jvm of the out-of-repo sloppy-joe config",
            crate::config::redact_url_for_display(url),
            path.display()
        );
    }
    let mut deps = build.deps;
    deps.extend(build.classpath);
    deps.extend(build.plugins);
    Ok(deps)
}

/// Parse a Gradle build script, the settings scripts that enclose it, and the
/// plugin requests of both. Custom plugin repositories are returned, not
/// rejected: the caller decides whether they are allowlisted.
pub(crate) fn parse_gradle_build(path: &Path) -> Result<GradleBuild> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read build.gradle")?;
    let script = scan_gradle_script(&content, path)?;
    if script.has_plugin_management {
        bail!(
            "Unsupported Gradle plugin repository declaration in {}: pluginManagement is only valid in settings scripts",
            path.display()
        );
    }
    let project_dir = std::fs::canonicalize(path.parent().unwrap_or(Path::new(".")))?;
    let boundary = crate::cache::find_git_root(&project_dir)
        .map_err(anyhow::Error::msg)?
        .unwrap_or_else(|| project_dir.clone());
    let mut settings = Vec::new();
    for ancestor in project_dir
        .ancestors()
        .take_while(|dir| dir.starts_with(&boundary))
    {
        for filename in ["settings.gradle", "settings.gradle.kts"] {
            let settings_path = ancestor.join(filename);
            if super::path_detected(&settings_path)? {
                let content = super::read_file_limited(&settings_path, super::MAX_MANIFEST_BYTES)?;
                let settings_script = scan_gradle_script(&content, &settings_path)?;
                settings.push((settings_path, settings_script));
            }
        }
    }
    let mut deps = Vec::new();

    let tokens = tokenize_gradle(&content);
    for (idx, token) in tokens.iter().enumerate() {
        if let GradleToken::Ident(config) = token
            && GRADLE_DEPENDENCY_CONFIGS.contains(&config.as_str())
        {
            let next = idx
                + 1
                + usize::from(matches!(
                    tokens.get(idx + 1),
                    Some(GradleToken::Symbol('('))
                ));
            if let Some(GradleToken::Literal(literal)) = tokens.get(next) {
                let dep = extract_gradle_dep(literal, path)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported Gradle dependency notation in {}",
                        path.display()
                    )
                })?;
                super::validate_dependency(&dep, path)?;
                deps.push(dep);
            } else {
                bail!(
                    "Unsupported Gradle dependency notation in {}: expected literal coordinates",
                    path.display()
                );
            }
        }
    }

    let plugins = gradle_plugins::resolve_plugins(&gradle_plugins::PluginContext {
        build_path: path,
        project_dir: &project_dir,
        boundary: &boundary,
        build: &script,
        settings: &settings,
    })?;
    Ok(GradleBuild {
        deps,
        plugins,
        plugin_repositories: gradle_plugins::plugin_repositories(&settings),
        uses_google_maven: script.uses_google_maven
            || settings
                .iter()
                .any(|(_, settings)| settings.uses_google_maven),
        classpath: script
            .classpath
            .iter()
            .chain(
                settings
                    .iter()
                    .flat_map(|(_, settings)| &settings.classpath),
            )
            .cloned()
            .collect(),
        classpath_uses_google_maven: script.buildscript_uses_google
            || settings
                .iter()
                .any(|(_, settings)| settings.buildscript_uses_google),
    })
}

fn extract_gradle_dep(line: &str, source_path: &Path) -> Result<Option<Dependency>> {
    let Some(quote) = line.find(['\'', '"']) else {
        return Ok(None);
    };
    let ch = line.as_bytes()[quote] as char;
    let rest = &line[quote + 1..];
    let Some(end) = rest.find(ch) else {
        return Ok(None);
    };
    let coord = &rest[..end];
    let parts: Vec<&str> = coord.splitn(3, ':').collect();
    if coord.matches(':').count() > 2 {
        bail!(
            "Unsupported Gradle dependency notation '{}' in {}: classifier-bearing coordinates are not supported",
            crate::report::sanitize_for_terminal(coord),
            source_path.display()
        );
    }
    if parts.len() >= 2 {
        let name = format!("{}:{}", parts[0], parts[1]);
        let version = parts.get(2).map(|v| v.to_string());
        return Ok(Some(Dependency {
            name,
            version,
            ecosystem: crate::Ecosystem::Jvm,
            actual_name: None,
        }));
    }
    Ok(None)
}

/// Read a POM with XML comments removed, so commented-out declarations are
/// never mistaken for real ones, and reject documents Maven itself would not
/// read unambiguously.
pub(crate) fn read_pom(path: &Path) -> Result<String> {
    let raw = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)
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
const POM_SINGLE_SECTIONS: &[&str] = &[
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

fn parse_pom(path: &Path) -> Result<Vec<Dependency>> {
    let content = read_pom(path)?;
    validate_pom_source_policy(&content, path)?;
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
        super::validate_dependency(&dep, path)?;
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
            super::validate_dependency(&dep, path)?;
            deps.push(dep);
        }
    }
    Ok(deps)
}

const MAVEN_DEFAULT_PLUGIN_GROUP: &str = "org.apache.maven.plugins";

/// Return the inner text of every `<tag>...</tag>` element. These elements do
/// not nest in a POM, so the first closing tag terminates each body.
fn maven_element_bodies<'a>(content: &'a str, tag: &str) -> Result<Vec<&'a str>> {
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
fn xml_direct_children(body: &str) -> Vec<(String, String)> {
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
fn maven_project_body(content: &str) -> Option<&str> {
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
    if !super::path_detected(&candidate)? {
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
    let Ok(parent_content) = super::read_file_limited(&candidate, super::MAX_MANIFEST_BYTES) else {
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

fn maven_parent_is_local(
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum GradleToken {
    Ident(String),
    Literal(String),
    Symbol(char),
}

fn tokenize_gradle(content: &str) -> Vec<GradleToken> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            c if c.is_whitespace() => i += 1,
            '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                i += 2;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(chars.len());
            }
            '"' | '\'' => {
                let start = i;
                let quote = chars[i];
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if chars[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                tokens.push(GradleToken::Literal(
                    chars[start..i.min(chars.len())].iter().collect(),
                ));
            }
            '{' | '}' | '(' | ')' => {
                tokens.push(GradleToken::Symbol(chars[i]));
                i += 1;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                i += 1;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric()
                        || matches!(chars[i], '_' | '.' | '-' | ':'))
                {
                    i += 1;
                }
                tokens.push(GradleToken::Ident(chars[start..i].iter().collect()));
            }
            _ => i += 1,
        }
    }
    tokens
}

fn find_gradle_block_end(tokens: &[GradleToken], open_idx: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, token) in tokens.iter().enumerate().skip(open_idx) {
        match token {
            GradleToken::Symbol('{') => depth += 1,
            GradleToken::Symbol('}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn validate_gradle_repositories_block(tokens: &[GradleToken], path: &Path) -> Result<bool> {
    let mut google_declared = false;
    for (idx, window) in tokens.windows(2).enumerate() {
        let [GradleToken::Ident(name), GradleToken::Symbol(next)] = window else {
            continue;
        };
        if !matches!(next, '{' | '(') {
            continue;
        }
        // A bare `google()` is Google's Maven repository; any option block or
        // argument could narrow or redirect it, so only the plain call is
        // understood.
        if name == "google"
            && *next == '('
            && matches!(tokens.get(idx + 2), Some(GradleToken::Symbol(')')))
            && !matches!(tokens.get(idx + 3), Some(GradleToken::Symbol('{')))
        {
            google_declared = true;
            continue;
        }
        if matches!(
            name.as_str(),
            "maven" | "mavenLocal" | "flatDir" | "ivy" | "google" | "gradlePluginPortal"
        ) {
            bail!(
                "Unsupported Gradle repository in {}: only mavenCentral() and google() are supported for trusted registry resolution",
                path.display()
            );
        }
    }
    Ok(google_declared)
}

/// `buildscript { dependencies { classpath 'g:a:v' } }`: build tooling pinned
/// to literal, exact coordinates. Anything else cannot be verified.
fn parse_classpath_block(tokens: &[GradleToken], path: &Path) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    let mut idx = 0usize;
    while idx < tokens.len() {
        match &tokens[idx] {
            GradleToken::Ident(name) if name == "classpath" => {
                let next = idx
                    + 1
                    + usize::from(matches!(
                        tokens.get(idx + 1),
                        Some(GradleToken::Symbol('('))
                    ));
                let Some(GradleToken::Literal(literal)) = tokens.get(next) else {
                    bail!(
                        "Unsupported Gradle buildscript classpath in {}: expected literal coordinates",
                        path.display()
                    );
                };
                let dep = extract_gradle_dep(literal, path)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported Gradle buildscript classpath notation in {}",
                        path.display()
                    )
                })?;
                super::validate_dependency(&dep, path)?;
                // Gradle's dynamic selectors (`8.+`, `latest.release`) are not literal
                // releases even though they contain no range brackets.
                let pinned = dep.version.as_deref().is_some_and(|version| {
                    !version.is_empty()
                        && !version.starts_with("latest.")
                        && version
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                });
                if !pinned {
                    bail!(
                        "Unsupported Gradle buildscript classpath '{}' in {}: buildscript dependencies are not locked, so they must pin an exact version",
                        crate::report::sanitize_for_terminal(&dep.name),
                        path.display()
                    );
                }
                deps.push(dep);
                idx = next;
            }
            GradleToken::Symbol(_) | GradleToken::Literal(_) => {}
            GradleToken::Ident(name) => bail!(
                "Unsupported Gradle buildscript dependency expression '{}' in {}: only literal classpath coordinates can be verified",
                crate::report::sanitize_for_terminal(name),
                path.display()
            ),
        }
        idx += 1;
    }
    Ok(deps)
}

fn validate_gradle_dependencies_block(tokens: &[GradleToken], path: &Path) -> Result<()> {
    for token in tokens {
        let GradleToken::Ident(name) = token else {
            continue;
        };
        if ["project", "files", "fileTree", "includeBuild"].contains(&name.as_str()) {
            bail!(
                "Unsupported Gradle dependency source in {}: local project or file dependencies are not supported",
                path.display()
            );
        }
        if !GRADLE_DEPENDENCY_CONFIGS.contains(&name.as_str()) {
            bail!(
                "Unsupported Gradle dependency expression '{}' in {}: only literal coordinates in supported configurations can be verified",
                name,
                path.display()
            );
        }
    }
    Ok(())
}

/// Plugins bundled with the Gradle distribution. They are not downloaded from
/// any repository, so they carry no supply-chain risk for this scanner.
const GRADLE_CORE_PLUGINS: &[&str] = &[
    "antlr",
    "application",
    "assembler",
    "base",
    "build-dashboard",
    "build-init",
    "c",
    "checkstyle",
    "codenarc",
    "cpp",
    "cpp-application",
    "cpp-library",
    "cpp-unit-test",
    "distribution",
    "ear",
    "eclipse",
    "eclipse-wtp",
    "groovy",
    "groovy-base",
    "help-tasks",
    "idea",
    "ivy-publish",
    "jacoco",
    "jacoco-report-aggregation",
    "java",
    "java-base",
    "java-gradle-plugin",
    "java-library",
    "java-library-distribution",
    "java-platform",
    "java-test-fixtures",
    "jvm-test-suite",
    "maven-publish",
    "objective-c",
    "objective-cpp",
    "pmd",
    "project-report",
    "publishing",
    "reporting-base",
    "scala",
    "scala-base",
    "signing",
    "swift-application",
    "swift-library",
    "test-report-aggregation",
    "version-catalog",
    "visual-studio",
    "war",
    "windows-resources",
    "wrapper",
    "xcode",
    "xctest",
];

fn is_gradle_core_plugin(id: &str) -> bool {
    let short = id.strip_prefix("org.gradle.").unwrap_or(id);
    GRADLE_CORE_PLUGINS.contains(&short)
}

fn gradle_literal_value(literal: &str) -> Option<&str> {
    let quote = literal.chars().next()?;
    if !matches!(quote, '\'' | '"') || literal.len() < 2 || !literal.ends_with(quote) {
        return None;
    }
    let value = &literal[1..literal.len() - 1];
    // Interpolation and escapes make the effective plugin id unknowable.
    (!value.contains(['$', '\\'])).then_some(value)
}

fn scan_gradle_script(content: &str, path: &Path) -> Result<gradle_plugins::GradleScript> {
    let tokens = tokenize_gradle(content);
    let mut script = gradle_plugins::GradleScript::default();
    walk_gradle_script(&tokens, path, &mut script, false, false)?;
    Ok(script)
}

/// Enforce the Gradle source policy over `tokens` and collect plugin requests.
/// `plugin_management` is set inside a `pluginManagement { }` block, where
/// `repositories` and `plugins` configure plugin resolution.
fn walk_gradle_script(
    tokens: &[GradleToken],
    path: &Path,
    script: &mut gradle_plugins::GradleScript,
    plugin_management: bool,
    buildscript: bool,
) -> Result<()> {
    let block_end = |idx: usize, name: &str| {
        find_gradle_block_end(tokens, idx + 1).ok_or_else(|| {
            anyhow::anyhow!(
                "Broken Gradle manifest '{}': unclosed '{}' block.",
                path.display(),
                name
            )
        })
    };
    let mut idx = 0usize;
    while idx < tokens.len() {
        let opens_block = matches!(tokens.get(idx + 1), Some(GradleToken::Symbol('{')));
        match &tokens[idx] {
            GradleToken::Ident(name)
                if name.split('.').any(|part| part == "dependencies")
                    && (name != "dependencies" || !opens_block) =>
            {
                bail!(
                    "Unsupported Gradle dependency expression in {}: dependency mutations outside literal blocks cannot be verified",
                    path.display()
                );
            }
            GradleToken::Ident(name)
                if name
                    .split('.')
                    .any(|part| matches!(part, "repositories" | "pluginManagement"))
                    && (!matches!(name.as_str(), "repositories" | "pluginManagement")
                        || !opens_block) =>
            {
                bail!(
                    "Unsupported Gradle repository expression '{}' in {}: repositories can only be verified when declared in literal blocks",
                    crate::report::sanitize_for_terminal(name),
                    path.display()
                );
            }
            GradleToken::Ident(name)
                if name == "resolutionStrategy" || name.starts_with("resolutionStrategy.") =>
            {
                bail!(
                    "Unsupported Gradle resolution rule in {}: resolutionStrategy can substitute or force dependency versions that cannot be verified",
                    path.display()
                );
            }
            GradleToken::Ident(name)
                if name.split('.').any(|part| {
                    matches!(part, "versionCatalogs" | "defaultLibrariesExtensionName")
                }) =>
            {
                script.custom_catalogs = true;
            }
            GradleToken::Ident(name) if name == "pluginManagement" && opens_block => {
                let end = block_end(idx, name)?;
                script.has_plugin_management = true;
                walk_gradle_script(&tokens[idx + 2..end], path, script, true, false)?;
                idx = end;
            }
            GradleToken::Ident(name) if name == "buildscript" && opens_block && !buildscript => {
                let end = block_end(idx, name)?;
                walk_gradle_script(&tokens[idx + 2..end], path, script, false, true)?;
                idx = end;
            }
            GradleToken::Ident(name) if name == "plugins" && opens_block => {
                let end = block_end(idx, name)?;
                let plugins = gradle_plugins::parse_plugins_block(&tokens[idx + 2..end], path)?;
                if plugin_management {
                    script.managed_plugins.extend(plugins);
                } else {
                    script.plugins.extend(plugins);
                }
                idx = end;
            }
            GradleToken::Ident(name) if matches!(name.as_str(), "apply" | "includeBuild") => {
                bail!(
                    "Unsupported Gradle script source '{}' in {}: applied scripts and composite builds cannot be verified",
                    name,
                    path.display()
                );
            }
            GradleToken::Ident(name)
                if matches!(name.as_str(), "repositories" | "dependencies") && opens_block =>
            {
                let end = block_end(idx, name)?;
                let block = &tokens[idx + 2..end];
                if name == "dependencies" && buildscript {
                    script.classpath.extend(parse_classpath_block(block, path)?);
                } else if name == "dependencies" {
                    validate_gradle_dependencies_block(block, path)?;
                } else if plugin_management {
                    script
                        .plugin_repositories
                        .get_or_insert_with(Vec::new)
                        .extend(gradle_plugins::parse_plugin_repositories(block, path)?);
                } else {
                    let google = validate_gradle_repositories_block(block, path)?;
                    if buildscript {
                        script.buildscript_uses_google |= google;
                    } else {
                        script.uses_google_maven |= google;
                    }
                }
                idx = end;
            }
            _ => {}
        }
        idx += 1;
    }

    Ok(())
}

fn xml_contains_open_tag(content: &str, target: &str) -> bool {
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

fn validate_pom_source_policy(content: &str, path: &Path) -> Result<()> {
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

#[cfg(test)]
mod tests;
