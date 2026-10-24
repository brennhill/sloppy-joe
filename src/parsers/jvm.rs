mod gradle_scan;
pub(crate) use gradle_scan::*;
mod pom;
use crate::Dependency;
use anyhow::{Context, Result, bail};
pub(crate) use pom::*;
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

/// The Gradle wrapper downloads and runs a Gradle distribution; only Gradle's own hosts count.
fn reject_untrusted_gradle_wrapper(dir: &Path) -> Result<()> {
    let properties = dir.join("gradle/wrapper/gradle-wrapper.properties");
    let Ok(content) = std::fs::read_to_string(&properties) else {
        return Ok(());
    };
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().replace('\\', "");
        if key.trim() == "distributionUrl"
            && ![
                "https://services.gradle.org/",
                "https://downloads.gradle.org/",
            ]
            .iter()
            .any(|trusted| value.starts_with(trusted))
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

/// Whether Gradle enforces `gradle.lockfile` for the build at `path`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GradleLocking {
    /// `dependencyLocking { lockAllConfigurations() }` is active in this build or an enclosing one.
    Strict,
    /// Locking is on but `LockMode.LENIENT` lets unlisted dependencies resolve.
    Lenient,
    /// Gradle resolves normally and ignores the lockfile.
    Off,
}

pub(crate) fn gradle_locking(path: &Path) -> Result<GradleLocking> {
    let project_dir = std::fs::canonicalize(path.parent().unwrap_or(Path::new(".")))?;
    let boundary = gradle_boundary(&project_dir)?;
    let mut locks = false;
    let mut lenient = false;
    for dir in project_dir
        .ancestors()
        .take_while(|dir| dir.starts_with(&boundary))
    {
        for name in ["build.gradle", "build.gradle.kts"] {
            let script = dir.join(name);
            if !super::path_detected(&script)? {
                continue;
            }
            let content = super::read_file_limited(&script, super::MAX_MANIFEST_BYTES)?;
            for token in tokenize_gradle(&content) {
                let GradleToken::Ident(ident) = token else {
                    continue;
                };
                let last = ident.rsplit('.').next().unwrap_or_default();
                locks |= last == "lockAllConfigurations";
                lenient |= matches!(last, "LENIENT" | "lockMode");
            }
        }
    }
    Ok(match (locks, lenient) {
        (false, _) => GradleLocking::Off,
        (true, true) => GradleLocking::Lenient,
        (true, false) => GradleLocking::Strict,
    })
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
    let boundary = gradle_boundary(&project_dir)?;
    let mut settings = Vec::new();
    for ancestor in project_dir
        .ancestors()
        .take_while(|dir| dir.starts_with(&boundary))
    {
        reject_untrusted_gradle_wrapper(ancestor)?;
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

#[cfg(test)]
mod tests;
