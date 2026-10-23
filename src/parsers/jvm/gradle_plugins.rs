//! Gradle plugin request resolution.
//!
//! A `plugins { id 'x' version 'v' }` request makes Gradle download the plugin
//! marker artifact `x:x.gradle.plugin:v` from the plugin repositories
//! (`pluginManagement { repositories {} }`, default: the Gradle Plugin
//! Portal), whose POM points at the implementation that then runs inside the
//! build. Markers never appear in `gradle.lockfile`, so every request must be
//! statically resolvable to a literal id and a pinned version here; anything
//! computed, dynamic, or unresolvable fails closed.

use super::{GradleToken, find_gradle_block_end, gradle_literal_value, is_gradle_core_plugin};
use crate::Dependency;
use crate::registry::gradle_plugins::PluginRepository;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// How a plugin request names its plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PluginIdExpr {
    Literal(String),
    /// `alias(libs.plugins.<key>)`: the accessor path after `libs.plugins.`.
    Alias(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawPlugin {
    pub id: PluginIdExpr,
    pub version: Option<String>,
    /// Whether a `version` clause may follow (not for aliases or bare ids).
    versionable: bool,
}

/// What one Gradle script declares about plugins.
#[derive(Debug, Clone, Default)]
pub(super) struct GradleScript {
    /// Top-level `plugins {}` requests (build or settings plugins).
    pub plugins: Vec<RawPlugin>,
    /// `pluginManagement { plugins {} }` default versions.
    pub managed_plugins: Vec<RawPlugin>,
    /// `pluginManagement { repositories {} }`, if declared.
    pub plugin_repositories: Option<Vec<PluginRepository>>,
    pub has_plugin_management: bool,
    /// A `repositories {}` block declares `google()`.
    pub uses_google_maven: bool,
    /// The script customizes version catalogs, so `libs` may not be
    /// `gradle/libs.versions.toml`.
    pub custom_catalogs: bool,
}

pub(super) fn unsupported_plugin(path: &Path, what: &str, why: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Unsupported Gradle plugin {} in {}: {}",
        what,
        path.display(),
        why
    )
}

const UNPARSEABLE: &str = "only literal plugin ids with literal pinned versions (or libs.versions.toml aliases) can be verified against the plugin repository";

fn shown(value: &str) -> String {
    format!("'{}'", crate::report::sanitize_for_terminal(value))
}

/// Read `(literal)` or `literal` after a plugin-block keyword, returning the
/// literal and the index of the next unconsumed token.
fn argument(tokens: &[GradleToken], idx: usize) -> Option<(&str, usize)> {
    match tokens.get(idx) {
        Some(GradleToken::Literal(literal)) => Some((literal.as_str(), idx + 1)),
        Some(GradleToken::Symbol('(')) => match (tokens.get(idx + 1), tokens.get(idx + 2)) {
            (Some(GradleToken::Literal(literal)), Some(GradleToken::Symbol(')'))) => {
                Some((literal.as_str(), idx + 3))
            }
            _ => None,
        },
        _ => None,
    }
}

fn valid_plugin_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && !id.starts_with('.')
        && !id.ends_with('.')
        && !id.contains("..")
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
}

/// A version Gradle resolves to exactly one immutable release: no ranges,
/// `+` prefixes, `latest.*` selectors, or SNAPSHOTs.
pub(super) fn is_pinned_plugin_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && version.starts_with(|ch: char| ch.is_ascii_alphanumeric())
        && version
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
        && !version.to_ascii_lowercase().starts_with("latest.")
        && !version.to_ascii_uppercase().ends_with("SNAPSHOT")
}

/// Parse the body of a `plugins { }` block into requests. Expressions that
/// cannot be resolved statically fail closed.
pub(super) fn parse_plugins_block(tokens: &[GradleToken], path: &Path) -> Result<Vec<RawPlugin>> {
    let mut plugins: Vec<RawPlugin> = Vec::new();
    let mut idx = 0usize;
    while idx < tokens.len() {
        let GradleToken::Ident(name) = &tokens[idx] else {
            return Err(unsupported_plugin(path, "declaration", UNPARSEABLE));
        };
        match name.as_str() {
            "id" | "kotlin" => {
                let (literal, next) = argument(tokens, idx + 1)
                    .ok_or_else(|| unsupported_plugin(path, "id expression", UNPARSEABLE))?;
                let value = gradle_literal_value(literal)
                    .filter(|value| valid_plugin_id(value))
                    .ok_or_else(|| unsupported_plugin(path, "id expression", UNPARSEABLE))?;
                let id = if name == "kotlin" {
                    format!("org.jetbrains.kotlin.{value}")
                } else {
                    value.to_string()
                };
                plugins.push(RawPlugin {
                    id: PluginIdExpr::Literal(id),
                    version: None,
                    versionable: true,
                });
                idx = next;
            }
            "alias" => {
                let accessor = match (
                    tokens.get(idx + 1),
                    tokens.get(idx + 2),
                    tokens.get(idx + 3),
                ) {
                    (
                        Some(GradleToken::Symbol('(')),
                        Some(GradleToken::Ident(accessor)),
                        Some(GradleToken::Symbol(')')),
                    ) => accessor,
                    _ => return Err(unsupported_plugin(path, "alias expression", UNPARSEABLE)),
                };
                let key = accessor
                    .strip_prefix("libs.plugins.")
                    .filter(|key| key.split('.').all(|part| !part.is_empty()))
                    .ok_or_else(|| {
                        unsupported_plugin(
                            path,
                            &format!("alias {}", shown(accessor)),
                            "only aliases from the default 'libs' catalog (gradle/libs.versions.toml) can be resolved",
                        )
                    })?;
                plugins.push(RawPlugin {
                    id: PluginIdExpr::Alias(key.to_string()),
                    version: None,
                    versionable: false,
                });
                idx += 4;
            }
            "version" => {
                let (literal, next) = argument(tokens, idx + 1)
                    .ok_or_else(|| unsupported_plugin(path, "version expression", UNPARSEABLE))?;
                let version = gradle_literal_value(literal)
                    .ok_or_else(|| unsupported_plugin(path, "version expression", UNPARSEABLE))?;
                let plugin = plugins
                    .last_mut()
                    .filter(|plugin| plugin.versionable && plugin.version.is_none())
                    .ok_or_else(|| unsupported_plugin(path, "version clause", UNPARSEABLE))?;
                plugin.version = Some(version.to_string());
                idx = next;
            }
            "apply" => {
                let parenthesized = matches!(tokens.get(idx + 1), Some(GradleToken::Symbol('(')));
                let flag_idx = idx + 1 + usize::from(parenthesized);
                match tokens.get(flag_idx) {
                    Some(GradleToken::Ident(flag)) if matches!(flag.as_str(), "true" | "false") => {
                    }
                    _ => return Err(unsupported_plugin(path, "apply expression", UNPARSEABLE)),
                }
                idx = flag_idx + 1;
                if parenthesized {
                    if !matches!(tokens.get(idx), Some(GradleToken::Symbol(')'))) {
                        return Err(unsupported_plugin(path, "apply expression", UNPARSEABLE));
                    }
                    idx += 1;
                }
            }
            bare if is_gradle_core_plugin(bare) => {
                plugins.push(RawPlugin {
                    id: PluginIdExpr::Literal(bare.to_string()),
                    version: None,
                    versionable: false,
                });
                idx += 1;
            }
            other => {
                return Err(unsupported_plugin(
                    path,
                    &shown(other),
                    "only core plugins, literal plugin ids, kotlin(\"...\") and libs.plugins aliases can be resolved",
                ));
            }
        }
    }
    Ok(plugins)
}

fn unsupported_repository(path: &Path, what: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Unsupported Gradle plugin repository {} in {}: only gradlePluginPortal(), mavenCentral() and maven {{ url = \"<literal https URL>\" }} plugin repositories can be resolved",
        what,
        path.display()
    )
}

fn literal_repository_url(literal: &str, path: &Path) -> Result<String> {
    let url = gradle_literal_value(literal)
        .map(str::trim)
        .ok_or_else(|| unsupported_repository(path, "URL expression"))?;
    match reqwest::Url::parse(url) {
        Ok(parsed) if matches!(parsed.scheme(), "https" | "http") && parsed.host().is_some() => {
            Ok(url.to_string())
        }
        _ => Err(unsupported_repository(
            path,
            &format!("URL '{}'", crate::config::redact_url_for_display(url)),
        )),
    }
}

/// Skip a `( ... )` group starting at `open`, returning the index after it.
fn skip_parens(tokens: &[GradleToken], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, token) in tokens.iter().enumerate().skip(open) {
        match token {
            GradleToken::Symbol('(') => depth += 1,
            GradleToken::Symbol(')') => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The URL of a `maven { ... }` plugin repository. Credentials and
/// authentication settings are skipped; anything that could change which URL
/// or which artifacts the repository serves fails closed.
fn maven_block_url(tokens: &[GradleToken], path: &Path) -> Result<String> {
    let mut url = None;
    let mut set_url = |value: String| -> Result<()> {
        if url.replace(value).is_some() {
            return Err(unsupported_repository(path, "with several URLs"));
        }
        Ok(())
    };
    let mut idx = 0usize;
    while idx < tokens.len() {
        let GradleToken::Ident(name) = &tokens[idx] else {
            return Err(unsupported_repository(path, "configuration"));
        };
        match (name.as_str(), tokens.get(idx + 1)) {
            ("url", Some(GradleToken::Literal(literal))) => {
                set_url(literal_repository_url(literal, path)?)?;
                idx += 2;
            }
            ("url", Some(GradleToken::Ident(uri))) if uri == "uri" => {
                match (
                    tokens.get(idx + 2),
                    tokens.get(idx + 3),
                    tokens.get(idx + 4),
                ) {
                    (
                        Some(GradleToken::Symbol('(')),
                        Some(GradleToken::Literal(literal)),
                        Some(GradleToken::Symbol(')')),
                    ) => set_url(literal_repository_url(literal, path)?)?,
                    _ => return Err(unsupported_repository(path, "URL expression")),
                }
                idx += 5;
            }
            ("setUrl", Some(GradleToken::Symbol('('))) => {
                match (tokens.get(idx + 2), tokens.get(idx + 3)) {
                    (Some(GradleToken::Literal(literal)), Some(GradleToken::Symbol(')'))) => {
                        set_url(literal_repository_url(literal, path)?)?
                    }
                    _ => return Err(unsupported_repository(path, "URL expression")),
                }
                idx += 4;
            }
            ("name", Some(GradleToken::Literal(_))) => idx += 2,
            ("credentials" | "authentication", Some(GradleToken::Symbol('{'))) => {
                idx = find_gradle_block_end(tokens, idx + 1)
                    .ok_or_else(|| unsupported_repository(path, "configuration"))?
                    + 1;
            }
            ("credentials" | "authentication", Some(GradleToken::Symbol('('))) => {
                idx = skip_parens(tokens, idx + 1)
                    .ok_or_else(|| unsupported_repository(path, "configuration"))?;
                if matches!(tokens.get(idx), Some(GradleToken::Symbol('{'))) {
                    idx = find_gradle_block_end(tokens, idx)
                        .ok_or_else(|| unsupported_repository(path, "configuration"))?
                        + 1;
                }
            }
            (other, _) => {
                return Err(unsupported_repository(
                    path,
                    &format!("setting {}", shown(other)),
                ));
            }
        }
    }
    url.ok_or_else(|| unsupported_repository(path, "without a URL"))
}

/// Parse `pluginManagement { repositories { ... } }` in declaration order.
pub(super) fn parse_plugin_repositories(
    tokens: &[GradleToken],
    path: &Path,
) -> Result<Vec<PluginRepository>> {
    let mut repositories = Vec::new();
    let mut idx = 0usize;
    while idx < tokens.len() {
        let GradleToken::Ident(name) = &tokens[idx] else {
            return Err(unsupported_repository(path, "declaration"));
        };
        match name.as_str() {
            "gradlePluginPortal" | "mavenCentral" => {
                if !matches!(
                    (tokens.get(idx + 1), tokens.get(idx + 2)),
                    (
                        Some(GradleToken::Symbol('(')),
                        Some(GradleToken::Symbol(')'))
                    )
                ) || matches!(tokens.get(idx + 3), Some(GradleToken::Symbol('{')))
                {
                    return Err(unsupported_repository(path, &shown(name)));
                }
                repositories.push(if name == "gradlePluginPortal" {
                    PluginRepository::GradlePluginPortal
                } else {
                    PluginRepository::MavenCentral
                });
                idx += 3;
            }
            "maven" => match tokens.get(idx + 1) {
                Some(GradleToken::Symbol('(')) => {
                    let (literal, next) = match (
                        tokens.get(idx + 2),
                        tokens.get(idx + 3),
                        tokens.get(idx + 4),
                    ) {
                        (
                            Some(GradleToken::Literal(literal)),
                            Some(GradleToken::Symbol(')')),
                            _,
                        ) => (literal, idx + 4),
                        (
                            Some(GradleToken::Ident(url)),
                            Some(GradleToken::Literal(literal)),
                            Some(GradleToken::Symbol(')')),
                        ) if url == "url" => (literal, idx + 5),
                        _ => return Err(unsupported_repository(path, "URL expression")),
                    };
                    if matches!(tokens.get(next), Some(GradleToken::Symbol('{'))) {
                        return Err(unsupported_repository(path, "configuration"));
                    }
                    repositories.push(PluginRepository::Custom(literal_repository_url(
                        literal, path,
                    )?));
                    idx = next;
                }
                Some(GradleToken::Symbol('{')) => {
                    let end = find_gradle_block_end(tokens, idx + 1)
                        .ok_or_else(|| unsupported_repository(path, "configuration"))?;
                    repositories.push(PluginRepository::Custom(maven_block_url(
                        &tokens[idx + 2..end],
                        path,
                    )?));
                    idx = end + 1;
                }
                _ => return Err(unsupported_repository(path, "declaration")),
            },
            other => return Err(unsupported_repository(path, &shown(other))),
        }
    }
    Ok(repositories)
}

/// Plugin repositories for a build: the nearest settings script's
/// `pluginManagement` repositories (Gradle's default is the Plugin Portal).
/// Custom repositories declared by any enclosing settings script are kept too
/// so they are never silently ignored.
pub(super) fn plugin_repositories(settings: &[(PathBuf, GradleScript)]) -> Vec<PluginRepository> {
    let mut repositories = settings
        .first()
        .and_then(|(_, script)| script.plugin_repositories.clone())
        .unwrap_or_else(|| vec![PluginRepository::GradlePluginPortal]);
    for (_, script) in settings.iter().skip(1) {
        for repository in script.plugin_repositories.iter().flatten() {
            if matches!(repository, PluginRepository::Custom(_))
                && !repositories.contains(repository)
            {
                repositories.push(repository.clone());
            }
        }
    }
    repositories
}

/// The default `libs` version catalog (`gradle/libs.versions.toml`).
struct Catalog {
    path: PathBuf,
    custom_catalogs: bool,
    loaded: Option<toml::Table>,
}

impl Catalog {
    fn table(&mut self, source: &Path, alias: &str) -> Result<&toml::Table> {
        let what = format!("alias {}", shown(&format!("libs.plugins.{alias}")));
        if self.custom_catalogs {
            return Err(unsupported_plugin(
                source,
                &what,
                "the settings script customizes version catalogs, so the 'libs' catalog cannot be resolved statically",
            ));
        }
        if self.loaded.is_none() {
            if !crate::parsers::path_detected(&self.path)? {
                return Err(unsupported_plugin(
                    source,
                    &what,
                    &format!("version catalog '{}' was not found", self.path.display()),
                ));
            }
            let content =
                crate::parsers::read_file_limited(&self.path, crate::parsers::MAX_MANIFEST_BYTES)?;
            let table: toml::Table = toml::from_str(&content).map_err(|err| {
                unsupported_plugin(
                    source,
                    &what,
                    &format!(
                        "version catalog '{}' could not be parsed: {}",
                        self.path.display(),
                        err
                    ),
                )
            })?;
            self.loaded = Some(table);
        }
        Ok(self.loaded.as_ref().expect("catalog loaded above"))
    }

    /// Resolve `libs.plugins.<alias>` to a literal plugin id and version.
    fn plugin(&mut self, source: &Path, alias: &str) -> Result<(String, String)> {
        let what = format!("alias {}", shown(&format!("libs.plugins.{alias}")));
        let fail = |why: &str| unsupported_plugin(source, &what, why);
        let table = self.table(source, alias)?;
        let plugins = table.get("plugins").and_then(toml::Value::as_table);
        let mut matches = plugins
            .into_iter()
            .flatten()
            .filter(|(key, _)| key.replace(['-', '_'], ".") == alias);
        let Some((_, entry)) = matches.next() else {
            return Err(fail(
                "the alias is not declared in [plugins] of the version catalog",
            ));
        };
        if matches.next().is_some() {
            return Err(fail("the alias matches several [plugins] entries"));
        }
        let (id, version) = match entry {
            toml::Value::String(notation) => {
                let (id, version) = notation
                    .split_once(':')
                    .ok_or_else(|| fail("the catalog entry has no version"))?;
                (id.to_string(), version.to_string())
            }
            toml::Value::Table(entry) => {
                if entry
                    .keys()
                    .any(|key| !matches!(key.as_str(), "id" | "version"))
                {
                    return Err(fail("the catalog entry uses unsupported keys"));
                }
                let id = entry
                    .get("id")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| fail("the catalog entry has no literal id"))?;
                let version = match entry.get("version") {
                    Some(toml::Value::String(version)) => version.clone(),
                    Some(toml::Value::Table(version))
                        if version.len() == 1 && version.contains_key("ref") =>
                    {
                        let reference = version
                            .get("ref")
                            .and_then(toml::Value::as_str)
                            .ok_or_else(|| fail("the catalog version reference is not literal"))?;
                        table
                            .get("versions")
                            .and_then(toml::Value::as_table)
                            .and_then(|versions| versions.get(reference))
                            .and_then(toml::Value::as_str)
                            .ok_or_else(|| {
                                fail("the referenced [versions] entry is missing or not a literal version")
                            })?
                            .to_string()
                    }
                    Some(_) => {
                        return Err(fail(
                            "rich version constraints (strictly/require/prefer) cannot be pinned",
                        ));
                    }
                    None => return Err(fail("the catalog entry has no version")),
                };
                (id.to_string(), version)
            }
            _ => return Err(fail("the catalog entry is not a plugin declaration")),
        };
        if !valid_plugin_id(&id) {
            return Err(fail("the catalog entry has an invalid plugin id"));
        }
        Ok((id, version))
    }
}

/// Everything needed to resolve plugin requests of one build script.
pub(super) struct PluginContext<'a> {
    pub build_path: &'a Path,
    pub project_dir: &'a Path,
    pub boundary: &'a Path,
    pub build: &'a GradleScript,
    /// Settings scripts from the nearest directory outward.
    pub settings: &'a [(PathBuf, GradleScript)],
}

fn marker_dependency(id: &str, version: &str, source: &Path) -> Result<Dependency> {
    let dep = Dependency {
        name: format!("{id}:{id}.gradle.plugin"),
        version: Some(version.to_string()),
        ecosystem: crate::Ecosystem::Jvm,
        actual_name: None,
    };
    crate::parsers::validate_dependency(&dep, source)?;
    Ok(dep)
}

/// Resolve every non-core plugin request of the build script and of its
/// settings scripts to pinned plugin marker dependencies.
pub(super) fn resolve_plugins(ctx: &PluginContext<'_>) -> Result<Vec<Dependency>> {
    let build_root = ctx
        .settings
        .first()
        .and_then(|(path, _)| path.parent())
        .unwrap_or(ctx.project_dir)
        .to_path_buf();
    let mut catalog = Catalog {
        path: build_root.join("gradle").join("libs.versions.toml"),
        custom_catalogs: ctx.build.custom_catalogs
            || ctx
                .settings
                .iter()
                .any(|(_, script)| script.custom_catalogs),
        loaded: None,
    };
    let root_settings: Vec<&GradleScript> = ctx
        .settings
        .iter()
        .filter(|(path, _)| path.parent() == Some(build_root.as_path()))
        .map(|(_, script)| script)
        .collect();

    let mut deps: Vec<Dependency> = Vec::new();
    let mut push = |dep: Dependency| {
        if !deps
            .iter()
            .any(|seen| seen.name == dep.name && seen.version == dep.version)
        {
            deps.push(dep);
        }
    };

    let mut requests: Vec<(&Path, &RawPlugin, bool)> = ctx
        .build
        .plugins
        .iter()
        .map(|plugin| (ctx.build_path, plugin, true))
        .collect();
    for (path, script) in ctx.settings {
        requests.extend(
            script
                .plugins
                .iter()
                .map(|plugin| (path.as_path(), plugin, false)),
        );
    }

    let mut ancestors: Option<Vec<(PathBuf, GradleScript)>> = None;
    for (source, plugin, from_build) in requests {
        let (id, explicit_version) = match &plugin.id {
            PluginIdExpr::Literal(id) => (id.clone(), plugin.version.clone()),
            PluginIdExpr::Alias(alias) => {
                let (id, version) = catalog.plugin(source, alias)?;
                (id, Some(version))
            }
        };
        if is_gradle_core_plugin(&id) {
            continue;
        }
        let mut versions = Vec::new();
        if let Some(version) = explicit_version {
            versions.push(version);
        } else {
            for script in &root_settings {
                for managed in &script.managed_plugins {
                    if managed.id == PluginIdExpr::Literal(id.clone())
                        && let Some(version) = &managed.version
                    {
                        versions.push(version.clone());
                    }
                }
            }
            if from_build {
                let ancestors = match &mut ancestors {
                    Some(ancestors) => ancestors,
                    None => ancestors.insert(ancestor_build_scripts(ctx, &build_root)?),
                };
                'nearest: for (path, script) in ancestors.iter() {
                    for declared in &script.plugins {
                        let declared = match &declared.id {
                            PluginIdExpr::Literal(declared_id) => declared
                                .version
                                .clone()
                                .map(|version| (declared_id.clone(), version)),
                            PluginIdExpr::Alias(alias) => Some(catalog.plugin(path, alias)?),
                        };
                        if let Some((declared_id, version)) = declared
                            && declared_id == id
                        {
                            versions.push(version);
                            break 'nearest;
                        }
                    }
                }
            }
        }
        if versions.is_empty() {
            return Err(unsupported_plugin(
                source,
                &shown(&id),
                "no literal pinned version is declared for it (in the request, pluginManagement { plugins {} }, or an enclosing build script), so the downloaded plugin cannot be verified",
            ));
        }
        for version in versions {
            if !is_pinned_plugin_version(&version) {
                return Err(unsupported_plugin(
                    source,
                    &format!("{} version {}", shown(&id), shown(&version)),
                    "dynamic, ranged, or SNAPSHOT plugin versions cannot be verified; pin an exact release",
                ));
            }
            push(marker_dependency(&id, &version, source)?);
        }
    }
    Ok(deps)
}

/// Build scripts of enclosing projects (nearest first), up to the build root.
fn ancestor_build_scripts(
    ctx: &PluginContext<'_>,
    build_root: &Path,
) -> Result<Vec<(PathBuf, GradleScript)>> {
    let mut scripts = Vec::new();
    if ctx.project_dir == build_root {
        return Ok(scripts);
    }
    for dir in ctx.project_dir.ancestors().skip(1) {
        if !dir.starts_with(ctx.boundary) || !dir.starts_with(build_root) {
            break;
        }
        for filename in ["build.gradle", "build.gradle.kts"] {
            let path = dir.join(filename);
            if crate::parsers::path_detected(&path)? {
                let content =
                    crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
                scripts.push((path.clone(), super::scan_gradle_script(&content, &path)?));
            }
        }
        if dir == build_root {
            break;
        }
    }
    Ok(scripts)
}

#[cfg(test)]
#[path = "gradle_plugins_tests.rs"]
mod tests;
