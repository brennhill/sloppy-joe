mod gradle_scan;
pub(crate) use gradle_scan::*;
mod pom;
use crate::Dependency;
use anyhow::{Context, Result, bail};
pub(crate) use pom::*;
use std::path::Path;

mod gradle_plugins;
mod locking;
pub(crate) use locking::{GradleLocking, gradle_locking};
pub(crate) mod maven_model;
mod parent_builds;
mod surfaces;
mod sysprops;
mod verification_metadata;
pub(crate) use verification_metadata::{
    reject_unreadable_version_catalog, reject_weakened_verification_metadata,
};

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
    /// Entries in the surrounding config files that `config_key_allow` permitted.
    pub applied_allows: Vec<crate::config_surface::AppliedAllow>,
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
        return parse_gradle(&gradle, &[]).map(|(deps, _)| deps);
    }
    let gradle_kts = project_dir.join("build.gradle.kts");
    if super::path_detected(&gradle_kts)? {
        return parse_gradle(&gradle_kts, &[]).map(|(deps, _)| deps);
    }
    let pom = project_dir.join("pom.xml");
    parse_pom(&pom)
}

pub(crate) fn parse_manifest(path: &Path) -> Result<Vec<Dependency>> {
    parse_manifest_with(path, &[]).map(|(deps, _)| deps)
}

/// Like [`parse_manifest`], applying the operator's `config_key_allow` entries to the config files
/// around the project; the entries that were applied come back with the dependencies.
pub(crate) fn parse_manifest_with(
    path: &Path,
    allows: &[crate::config_surface::KeyAllow],
) -> Result<(Vec<Dependency>, Vec<crate::config_surface::AppliedAllow>)> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("build.gradle") | Some("build.gradle.kts") => parse_gradle(path, allows),
        Some("pom.xml") => parse_pom_with(path, allows),
        _ => bail!("Unsupported JVM manifest: {}", path.display()),
    }
}

fn parse_gradle(
    path: &Path,
    allows: &[crate::config_surface::KeyAllow],
) -> Result<(Vec<Dependency>, Vec<crate::config_surface::AppliedAllow>)> {
    let build = parse_gradle_build_with(path, Some(allows))?;
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
    Ok((deps, build.applied_allows))
}

/// How far up Gradle's enclosing settings scripts apply: the repository root, or without a git
/// checkout (Docker contexts, source tarballs) the filesystem root, since Gradle searches upward
/// regardless.
fn gradle_boundary(project_dir: &Path) -> Result<std::path::PathBuf> {
    let root = crate::cache::find_git_root(project_dir).map_err(anyhow::Error::msg)?;
    Ok(root.unwrap_or_else(|| {
        project_dir
            .ancestors()
            .last()
            .unwrap_or(project_dir)
            .to_path_buf()
    }))
}

/// Gradle compiles and runs `buildSrc` while configuring every build. Its dependencies are only
/// scanned through its own build script, so a `buildSrc` without one is code nothing reads.
fn reject_buildsrc_without_script(dir: &Path) -> Result<()> {
    let build_src = dir.join("buildSrc");
    if std::fs::symlink_metadata(&build_src).is_err() {
        return Ok(());
    }
    let has_script = ["build.gradle", "build.gradle.kts"]
        .iter()
        .any(|name| std::fs::symlink_metadata(build_src.join(name)).is_ok());
    if !has_script {
        bail!(
            "Unsupported Gradle buildSrc in {}: it has no build script, but its sources are compiled and run while Gradle configures the build, so they cannot be scanned",
            build_src.display()
        );
    }
    Ok(())
}

/// The Gradle wrapper downloads and runs a Gradle distribution; only Gradle's own hosts count.
fn reject_untrusted_gradle_wrapper(dir: &Path) -> Result<()> {
    let properties = dir.join("gradle/wrapper/gradle-wrapper.properties");
    if std::fs::symlink_metadata(&properties).is_err() {
        return Ok(());
    }
    for (key, value) in crate::untrusted::read_properties(&properties)? {
        if key == "distributionUrl"
            && ![
                "https://services.gradle.org/",
                "https://downloads.gradle.org/",
            ]
            .iter()
            .any(|trusted| value.trim().starts_with(trusted))
        {
            bail!(
                "Untrusted Gradle wrapper distributionUrl in {}: '{}' is not a Gradle-hosted distribution",
                properties.display(),
                crate::report::sanitize_for_terminal(&value)
            );
        }
    }
    Ok(())
}

/// Parse a Gradle build script, the settings scripts that enclose it, and the
/// plugin requests of both. Custom plugin repositories are returned, not
/// rejected: the caller decides whether they are allowlisted.
#[cfg(test)]
pub(crate) fn parse_gradle_build(path: &Path) -> Result<GradleBuild> {
    parse_gradle_build_with(path, Some(&[]))
}

/// Like [`parse_gradle_build`], applying the operator's `config_key_allow` entries to the config
/// files around the build. `None` skips those config checks: later phases re-read a build that
/// already passed them when it was first parsed with the operator's config.
pub(crate) fn parse_gradle_build_with(
    path: &Path,
    allows: Option<&[crate::config_surface::KeyAllow]>,
) -> Result<GradleBuild> {
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
    let boundary = gradle_boundary(&project_dir)?;
    let mut settings = Vec::new();
    let mut applied_allows = Vec::new();
    for ancestor in project_dir
        .ancestors()
        .take_while(|dir| dir.starts_with(&boundary))
    {
        reject_untrusted_gradle_wrapper(ancestor)?;
        if let Some(allows) = allows {
            applied_allows.extend(surfaces::check_gradle_properties(ancestor, allows)?);
            applied_allows.extend(surfaces::check_gradle_daemon_jvm(ancestor, allows)?);
        }
        reject_buildsrc_without_script(ancestor)?;
        for filename in ["settings.gradle", "settings.gradle.kts"] {
            let settings_path = ancestor.join(filename);
            if super::path_detected(&settings_path)? {
                let content = super::read_file_limited(&settings_path, super::MAX_MANIFEST_BYTES)?;
                let settings_script = scan_gradle_script(&content, &settings_path)?;
                settings.push((settings_path, settings_script));
            }
        }
    }
    let mut deps = literal_dependencies(&tokenize_gradle(&content), path)?;
    let parents = parent_builds::read_parent_builds(&project_dir, &boundary, &settings)?;
    deps.extend(parents.deps.iter().cloned());

    let mut plugins = gradle_plugins::resolve_plugins(&gradle_plugins::PluginContext {
        build_path: path,
        project_dir: &project_dir,
        boundary: &boundary,
        build: &script,
        settings: &settings,
    })?;
    for plugin in parent_builds::parent_plugins(&parents, &boundary, &settings)? {
        if !plugins
            .iter()
            .any(|seen| seen.name == plugin.name && seen.version == plugin.version)
        {
            plugins.push(plugin);
        }
    }
    let scripts = || std::iter::once(&script).chain(parents.scripts.iter().map(|(_, s)| s));
    Ok(GradleBuild {
        deps,
        plugins,
        plugin_repositories: gradle_plugins::plugin_repositories(&settings),
        uses_google_maven: scripts().any(|script| script.uses_google_maven)
            || settings
                .iter()
                .any(|(_, settings)| settings.uses_google_maven),
        classpath: scripts()
            .flat_map(|script| &script.classpath)
            .chain(
                settings
                    .iter()
                    .flat_map(|(_, settings)| &settings.classpath),
            )
            .cloned()
            .collect(),
        classpath_uses_google_maven: scripts().any(|script| script.buildscript_uses_google)
            || settings
                .iter()
                .any(|(_, settings)| settings.buildscript_uses_google),
        applied_allows,
    })
}

/// `implementation 'g:a:v'`-style declarations among `tokens`.
fn literal_dependencies(tokens: &[GradleToken], path: &Path) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
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
    Ok(deps)
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

#[cfg(test)]
mod build_override_tests;
#[cfg(test)]
mod gradle_lexer_tests;
#[cfg(test)]
mod redirect_tests;
#[cfg(test)]
mod tests;
