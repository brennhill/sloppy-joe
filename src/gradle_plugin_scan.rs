//! Gradle plugin scanning.
//!
//! `plugins {}` requests resolve to plugin marker artifacts that never appear
//! in `gradle.lockfile`, so they are scanned as a separate unlocked-tooling
//! project (pinned exact versions, enforced by the parser) against the
//! build's plugin repositories instead of Maven Central.
//!
//! A custom `pluginManagement` repository is repository-controlled, so it
//! blocks unless the exact URL is allowlisted in the out-of-repo config
//! (`trusted_registries.jvm`, name `gradle-plugins`). Plugins of a build with
//! an allowlisted repository are reported as unvetted: Gradle may serve them
//! from that repository, so checking the public portal would vet the wrong
//! artifact.

use super::*;
use crate::registry::gradle_plugins::{GradlePluginRegistry, PluginRepository, plugin_marker_id};

/// `trusted_registries.jvm[].name` for allowlisted Gradle plugin repositories.
pub(crate) use crate::config::TRUSTED_PLUGIN_REPOSITORY_NAME;

fn is_trusted_plugin_repository(config: &config::SloppyJoeConfig, url: &str) -> bool {
    let url = config::normalize_python_index_url(url);
    config.trusted_registries("jvm").iter().any(|rule| {
        rule.name == TRUSTED_PLUGIN_REPOSITORY_NAME
            && config::normalize_python_index_url(&rule.source) == url
    })
}

pub(super) fn parse_gradle_project_input(
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<ParsedInput> {
    let build = parsers::jvm::parse_gradle_build(&spec.manifest_path)?;
    let custom: Vec<&str> = build
        .plugin_repositories
        .iter()
        .filter_map(|repository| match repository {
            PluginRepository::Custom(url) => Some(url.as_str()),
            _ => None,
        })
        .collect();
    if let Some(url) = custom
        .iter()
        .find(|url| !is_trusted_plugin_repository(config, url))
    {
        anyhow::bail!(
            "Unsupported Gradle plugin repository '{}' for {}: a repository-controlled plugin repository cannot opt plugins out of public checks. If it is approved, add {{\"name\": \"{}\", \"source\": \"<repository URL>\"}} to trusted_registries.jvm in the out-of-repo sloppy-joe config; otherwise remove it from pluginManagement {{ repositories {{}} }}.",
            config::redact_url_for_display(url),
            spec.manifest_path.display(),
            TRUSTED_PLUGIN_REPOSITORY_NAME
        );
    }
    let mut warnings = Vec::new();
    let plugins = if custom.is_empty() {
        warnings.extend(known_plugin_lookalikes(&build.plugins, config));
        build.plugins
    } else {
        warnings.extend(
            build
                .plugins
                .iter()
                .map(|dep| unvetted_plugin_issue(dep, &custom)),
        );
        Vec::new()
    };
    // Buildscript classpath artifacts never reach gradle.lockfile either; they
    // are scanned as unlocked tooling with exact pins enforced by the parser.
    let mut tooling = build.classpath;
    tooling.extend(plugins);
    Ok(ParsedInput {
        deps: build.deps,
        warnings,
        unlocked_tooling_deps: tooling,
        ..ParsedInput::default()
    })
}

fn unvetted_plugin_issue(dep: &Dependency, repositories: &[&str]) -> Issue {
    let repositories: Vec<String> = repositories
        .iter()
        .map(|url| config::redact_url_for_display(url))
        .collect();
    let mut issue = Issue::new(
        &dep.name,
        checks::names::RESOLUTION_PRIVATE_REGISTRY_UNVETTED,
        Severity::Warning,
    )
    .message(format!(
        "Gradle plugin marker '{}' at {} may resolve from the allowlisted plugin repository {}: public existence, similarity, metadata, and advisory checks do not verify that repository's contents.",
        dep.name,
        dep.version.as_deref().unwrap_or("unpinned version"),
        repositories.join(", ")
    ))
    .fix("Review the private plugin repository's access controls, upstream provenance, and plugin contents separately.");
    issue.source = Some("direct".to_string());
    issue
}

/// Widely used plugin ids that typosquats imitate.
const WELL_KNOWN_PLUGIN_IDS: &[&str] = &[
    "com.adarshr.test-logger",
    "com.android.application",
    "com.android.library",
    "com.diffplug.spotless",
    "com.github.ben-manes.versions",
    "com.github.gmazzo.buildconfig",
    "com.github.johnrengelman.shadow",
    "com.github.node-gradle.node",
    "com.github.spotbugs",
    "com.google.cloud.tools.jib",
    "com.google.devtools.ksp",
    "com.google.firebase.crashlytics",
    "com.google.gms.google-services",
    "com.google.protobuf",
    "com.gradle.develocity",
    "com.gradle.enterprise",
    "com.gradle.plugin-publish",
    "com.gradleup.shadow",
    "com.vanniktech.maven.publish",
    "de.undercouch.download",
    "io.freefair.lombok",
    "io.github.gradle-nexus.publish-plugin",
    "io.gitlab.arturbosch.detekt",
    "io.micronaut.application",
    "io.micronaut.library",
    "io.quarkus",
    "io.spring.dependency-management",
    "me.champeau.jmh",
    "net.ltgt.errorprone",
    "org.asciidoctor.jvm.convert",
    "org.flywaydb.flyway",
    "org.gradle.toolchains.foojay-resolver-convention",
    "org.graalvm.buildtools.native",
    "org.jetbrains.compose",
    "org.jetbrains.dokka",
    "org.jetbrains.intellij",
    "org.jetbrains.intellij.platform",
    "org.jetbrains.kotlin.android",
    "org.jetbrains.kotlin.js",
    "org.jetbrains.kotlin.jvm",
    "org.jetbrains.kotlin.kapt",
    "org.jetbrains.kotlin.multiplatform",
    "org.jetbrains.kotlin.plugin.allopen",
    "org.jetbrains.kotlin.plugin.compose",
    "org.jetbrains.kotlin.plugin.jpa",
    "org.jetbrains.kotlin.plugin.noarg",
    "org.jetbrains.kotlin.plugin.serialization",
    "org.jetbrains.kotlin.plugin.spring",
    "org.jetbrains.kotlinx.binary-compatibility-validator",
    "org.jetbrains.kotlinx.kover",
    "org.jlleitschuh.gradle.ktlint",
    "org.liquibase.gradle",
    "org.openapi.generator",
    "org.owasp.dependencycheck",
    "org.sonarqube",
    "org.springframework.boot",
];

const LOOKALIKE_GENERATOR: &str = "known-plugin-id";

fn marker_name(id: &str) -> String {
    format!("{id}:{id}.gradle.plugin")
}

/// The well-known plugin id `id` most closely imitates, if any: a small edit
/// distance or the same id once separators are ignored.
fn closest_known_plugin(id: &str) -> Option<&'static str> {
    if WELL_KNOWN_PLUGIN_IDS.contains(&id) {
        return None;
    }
    let squash = |value: &str| value.replace(['.', '-', '_'], "").to_ascii_lowercase();
    let threshold = if id.len() < 12 { 1 } else { 2 };
    WELL_KNOWN_PLUGIN_IDS
        .iter()
        .filter_map(|known| {
            let distance = strsim::levenshtein(id, known);
            (distance <= threshold || squash(id) == squash(known)).then_some((distance, *known))
        })
        .min()
        .map(|(_, known)| known)
}

fn known_plugin_lookalikes(plugins: &[Dependency], config: &config::SloppyJoeConfig) -> Vec<Issue> {
    let mut issues = Vec::new();
    for dep in plugins {
        let Some(id) = plugin_marker_id(&dep.name) else {
            continue;
        };
        if config.is_allowed("jvm", &dep.name) || config.is_internal("jvm", &dep.name) {
            continue;
        }
        let Some(known) = closest_known_plugin(id) else {
            continue;
        };
        let candidate = marker_name(known);
        if config.is_similarity_exception("jvm", &dep.name, &candidate, LOOKALIKE_GENERATOR)
            || issues.iter().any(|issue: &Issue| issue.package == dep.name)
        {
            continue;
        }
        let mut issue = Issue::new(
            &dep.name,
            checks::names::SIMILARITY_MUTATION_MATCH,
            Severity::Error,
        )
        .message(format!(
            "Gradle plugin id '{id}' closely resembles the widely used plugin '{known}'. Look-alike plugin ids are a known way to get malicious code executed at build time."
        ))
        .fix(format!(
            "If you meant '{known}', fix the plugin id. If '{id}' is intended, add '{}' to the allowed list in your sloppy-joe config.",
            dep.name
        ))
        .suggestion(candidate);
        issue.source = Some("direct".to_string());
        issues.push(issue);
    }
    issues
}

/// The plugin repository client for a Gradle plugin project, `None` for any
/// other project.
pub(super) fn plugin_registry_for(
    project: &ParsedProject,
    client: reqwest::Client,
) -> Result<Option<Box<dyn Registry>>> {
    if project.spec.kind != ProjectInputKind::Gradle {
        return Ok(None);
    }
    let build = parsers::jvm::parse_gradle_build(&project.spec.manifest_path)?;
    // Dependencies and buildscript classpath artifacts come from Maven Central,
    // plus Google's repository when the matching `repositories {}` lists it.
    let maven_with = |google: bool| {
        google.then(|| {
            Box::new(registry::google_maven::MavenWithGoogleRegistry::with_client(client.clone()))
                as Box<dyn Registry>
        })
    };
    if !project.unlocked_tooling {
        return Ok(maven_with(build.uses_google_maven));
    }
    if !is_plugin_marker_project(project) {
        return Ok(maven_with(build.classpath_uses_google_maven));
    }
    Ok(Some(Box::new(GradlePluginRegistry::new(
        client,
        &build.plugin_repositories,
        &project.deps,
    )?)))
}

/// Whether an unlocked-tooling Gradle project holds plugin markers (as opposed
/// to buildscript classpath artifacts).
pub(super) fn is_plugin_marker_project(project: &ParsedProject) -> bool {
    project.unlocked_tooling
        && project.spec.kind == ProjectInputKind::Gradle
        && project
            .deps
            .iter()
            .any(|dep| plugin_marker_id(&dep.name).is_some())
}

/// Splits Gradle tooling dependencies into plugin markers and classpath artifacts.
pub(super) fn split_tooling_deps(deps: Vec<Dependency>) -> (Vec<Dependency>, Vec<Dependency>) {
    deps.into_iter()
        .partition(|dep| plugin_marker_id(&dep.name).is_some())
}

/// Advisory issues for the implementation artifacts of a Gradle plugin project
/// (empty for any other project).
pub(super) async fn project_implementation_issues(
    project: &ParsedProject,
    client: reqwest::Client,
    osv_client: &dyn checks::malicious::OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<Vec<Issue>> {
    if !is_plugin_marker_project(project) {
        return Ok(Vec::new());
    }
    let build = parsers::jvm::parse_gradle_build(&project.spec.manifest_path)?;
    let registry = GradlePluginRegistry::new(client, &build.plugin_repositories, &project.deps)?;
    let cache_path = if opts.disable_osv_disk_cache || opts.no_cache {
        None
    } else {
        opts.cache_dir.map(|dir| dir.join("osv-cache.json"))
    };
    implementation_advisory_issues(&registry, &project.deps, osv_client, cache_path.as_deref())
        .await
}

/// OSV advisory check of the artifacts a plugin marker delegates to.
///
/// A marker POM only redirects to the plugin's implementation artifacts, which
/// are what actually run in the build, so advisories are looked up for them
/// (Maven coordinates), not for the marker. A marker that cannot be read or
/// names an artifact that cannot be pinned blocks.
pub(crate) async fn implementation_advisory_issues(
    registry: &GradlePluginRegistry,
    plugins: &[Dependency],
    osv_client: &dyn checks::malicious::OsvClient,
    cache_path: Option<&std::path::Path>,
) -> Result<Vec<Issue>> {
    let mut issues = Vec::new();
    let mut artifacts: Vec<Dependency> = Vec::new();
    for plugin in plugins {
        let Some(version) = plugin
            .version
            .as_deref()
            .filter(|_| plugin.exact_version().is_some())
        else {
            continue;
        };
        match registry.implementation_artifacts(&plugin.name, version).await? {
            Some(found) => {
                for (group, artifact, artifact_version) in found {
                    let dep = Dependency {
                        name: format!("{group}:{artifact}"),
                        version: Some(artifact_version),
                        ecosystem: Ecosystem::Jvm,
                        actual_name: None,
                    };
                    if !artifacts.iter().any(|seen| seen.name == dep.name && seen.version == dep.version) {
                        artifacts.push(dep);
                    }
                }
            }
            None => issues.push(
                Issue::new(&plugin.name, checks::names::EXISTENCE, Severity::Error)
                    .message(format!(
                        "Gradle plugin marker '{}' at {} could not be read to find its implementation artifacts.",
                        plugin.name, version
                    ))
                    .fix("Check the plugin id and version, then rerun sloppy-joe."),
            ),
        }
    }
    if artifacts.is_empty() {
        return Ok(issues);
    }
    let resolution =
        lockfiles::LockfileData::reduced_confidence_from_manifest(&artifacts).resolution;
    let mut found = checks::malicious::check_malicious_with_cache(
        osv_client,
        &artifacts,
        &resolution,
        cache_path,
    )
    .await?;
    for issue in &mut found {
        issue.source = Some("direct".to_string());
    }
    issues.extend(found);
    Ok(issues)
}

#[cfg(test)]
#[path = "gradle_plugin_scan_tests.rs"]
mod tests;
