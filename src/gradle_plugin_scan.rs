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
pub(crate) const TRUSTED_PLUGIN_REPOSITORY_NAME: &str = "gradle-plugins";

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
    Ok(ParsedInput {
        deps: build.deps,
        warnings,
        unlocked_tooling_deps: plugins,
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
    if !(project.unlocked_tooling && project.spec.kind == ProjectInputKind::Gradle) {
        return Ok(None);
    }
    let build = parsers::jvm::parse_gradle_build(&project.spec.manifest_path)?;
    Ok(Some(Box::new(GradlePluginRegistry::new(
        client,
        &build.plugin_repositories,
        &project.deps,
    )?)))
}

#[cfg(test)]
#[path = "gradle_plugin_scan_tests.rs"]
mod tests;
