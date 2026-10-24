//! End-to-end Gradle plugin scanning: plugin markers become an unlocked
//! tooling project checked against the plugin repositories (a local
//! 127.0.0.1 mock here), custom plugin repositories need the out-of-repo
//! allowlist, and look-alikes of well-known plugin ids are flagged.

use super::*;
use crate::checks::malicious::OsvClient;
use crate::registry::gradle_plugins::GradlePluginRegistry;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-gradle-scan-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    dir
}

const LOCKFILE: &str =
    "com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath\nempty=\n";

fn gradle_project(build: &str, extra: &[(&str, &str)]) -> std::path::PathBuf {
    let dir = unique_dir();
    std::fs::write(dir.join("build.gradle"), build).unwrap();
    std::fs::write(dir.join("gradle.lockfile"), LOCKFILE).unwrap();
    for (path, content) in extra {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    dir
}

fn build_with_plugins(plugins: &str) -> String {
    format!(
        "plugins {{\n  id 'java'\n  {plugins}\n}}\nrepositories {{ mavenCentral() }}\ndependencies {{ implementation 'com.google.guava:guava:33.0.0-jre' }}"
    )
}

fn specs(dir: &std::path::Path, config: &config::SloppyJoeConfig) -> Vec<ProjectInputSpec> {
    let specs = detected_project_inputs_with_config(dir, Some("jvm"), config).unwrap();
    assert!(
        specs
            .iter()
            .all(|spec| spec.kind == ProjectInputKind::Gradle),
        "{specs:#?}"
    );
    specs
}

fn opts(cache: &std::path::Path) -> ScanOptions<'_> {
    ScanOptions {
        no_cache: true,
        disable_osv_disk_cache: true,
        cache_dir: Some(cache),
        ..Default::default()
    }
}

fn trusting(url: &str) -> config::SloppyJoeConfig {
    let mut config = config::SloppyJoeConfig::default();
    config.trusted_registries.insert(
        "jvm".to_string(),
        vec![config::TrustedRegistry {
            name: "gradle-plugins".to_string(),
            source: url.to_string(),
        }],
    );
    config
}

struct NoAdvisories;

#[async_trait::async_trait]
impl OsvClient for NoAdvisories {
    async fn query(&self, _: &str, _: &str, _: Option<&str>) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

async fn plugin_portal_mock(published: &[(&str, &str)]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut routes: HashMap<String, String> = HashMap::new();
    for (id, version) in published {
        let dir = format!("/m2/{}/{id}.gradle.plugin", id.replace('.', "/"));
        routes.insert(
            format!("{dir}/maven-metadata.xml"),
            format!("<metadata><versioning><versions><version>{version}</version></versions><lastUpdated>20240101000000</lastUpdated></versioning></metadata>"),
        );
        routes.insert(
            format!("{dir}/{version}/{id}.gradle.plugin-{version}.pom"),
            "<project/>".to_string(),
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let (status, body) = match routes.get(&path) {
                    Some(body) => (200, body.clone()),
                    None => (404, String::new()),
                };
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nLast-Modified: Mon, 01 Jan 2024 00:00:00 GMT\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
            });
        }
    });
    format!("{origin}/m2/")
}

fn errors(report: &ScanReport) -> Vec<String> {
    report
        .issues
        .iter()
        .filter(|issue| issue.severity == Severity::Error)
        .map(|issue| format!("{} {}", issue.check, issue.package))
        .collect()
}

#[test]
fn plugin_markers_are_scanned_as_a_separate_unlocked_tooling_project() {
    let dir = gradle_project(
        &build_with_plugins(
            "id 'com.diffplug.spotless' version '6.25.0'\n  alias(libs.plugins.detekt)",
        ),
        &[(
            "gradle/libs.versions.toml",
            "[plugins]\ndetekt = { id = \"io.gitlab.arturbosch.detekt\", version = \"1.23.6\" }",
        )],
    );
    let config = config::SloppyJoeConfig::default();
    let cache = unique_dir();
    let specs = specs(&dir, &config);
    let warnings = preflight_project_inputs_with_options(&dir, &specs, &config, &opts(&cache))
        .expect("pinned public plugins pass preflight");
    assert!(
        warnings
            .iter()
            .all(|issue| issue.severity != Severity::Error),
        "{warnings:?}"
    );

    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &opts(&cache)).unwrap();
    let main = projects
        .iter()
        .find(|project| !project.unlocked_tooling)
        .unwrap();
    let names: Vec<&str> = main.deps.iter().map(|dep| dep.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["com.google.guava:guava"],
        "markers never reach gradle.lockfile checks"
    );

    let tooling = projects
        .iter()
        .find(|project| project.unlocked_tooling)
        .unwrap();
    let mut markers: Vec<String> = tooling
        .deps
        .iter()
        .map(|dep| format!("{}@{}", dep.name, dep.version.as_deref().unwrap_or("")))
        .collect();
    markers.sort();
    assert_eq!(
        markers,
        vec![
            "com.diffplug.spotless:com.diffplug.spotless.gradle.plugin@6.25.0",
            "io.gitlab.arturbosch.detekt:io.gitlab.arturbosch.detekt.gradle.plugin@1.23.6",
        ]
    );

    let client = registry::http_client();
    // Through the trait: the engine only ever reaches the plugin repository client this way.
    assert!(
        crate::ecosystems::scan_registry(main, client.clone())
            .unwrap()
            .is_none()
    );
    let registry = crate::ecosystems::scan_registry(tooling, client)
        .unwrap()
        .expect("plugin projects use the plugin repository client");
    assert_eq!(registry.ecosystem(), "jvm");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cache);
}

#[tokio::test]
async fn published_plugins_pass_and_unpublished_plugins_block() {
    let base = plugin_portal_mock(&[("com.diffplug.spotless", "6.25.0")]).await;
    let config = config::SloppyJoeConfig::default();
    let cache = unique_dir();

    for (plugin, expect_block) in [
        ("id 'com.diffplug.spotless' version '6.25.0'", false),
        ("id 'com.diffplug.spotless' version '9.9.9'", true),
        ("id 'com.example.hallucinated' version '1.0.0'", true),
    ] {
        let dir = gradle_project(&build_with_plugins(plugin), &[]);
        let specs = specs(&dir, &config);
        let projects =
            parse_project_inputs_with_options(&dir, &specs, &config, &opts(&cache)).unwrap();
        let tooling = projects
            .iter()
            .find(|project| project.unlocked_tooling)
            .unwrap();
        let registry = GradlePluginRegistry::with_base_urls(
            registry::http_client(),
            vec![base.clone()],
            &tooling.deps,
        );
        let report = scan_parsed_project(
            tooling,
            config.clone(),
            &registry,
            &NoAdvisories,
            &opts(&cache),
        )
        .await
        .unwrap();
        let errors = errors(&report);
        if expect_block {
            assert!(
                errors
                    .iter()
                    .any(|error| error.starts_with(checks::names::EXISTENCE)),
                "{plugin}: {errors:?}"
            );
        } else {
            assert!(errors.is_empty(), "{plugin}: {errors:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    let _ = std::fs::remove_dir_all(&cache);
}

#[test]
fn dynamic_plugin_versions_block_the_project() {
    let dir = gradle_project(
        &build_with_plugins("id 'com.diffplug.spotless' version '6.+'"),
        &[],
    );
    let config = config::SloppyJoeConfig::default();
    let cache = unique_dir();
    let err =
        preflight_project_inputs_with_options(&dir, &specs(&dir, &config), &config, &opts(&cache))
            .expect_err("dynamic plugin versions cannot be vetted");
    assert!(err.to_string().contains("Gradle plugin"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cache);
}

fn corp_repo_project() -> std::path::PathBuf {
    gradle_project(
        &build_with_plugins("id 'com.corp.convention' version '1.0.0'"),
        &[(
            "settings.gradle",
            "pluginManagement { repositories { maven { url 'https://plugins.corp.example/m2' }\n gradlePluginPortal() } }",
        )],
    )
}

#[test]
fn custom_plugin_repositories_block_unless_allowlisted() {
    let dir = corp_repo_project();
    let cache = unique_dir();
    let config = config::SloppyJoeConfig::default();
    let err =
        preflight_project_inputs_with_options(&dir, &specs(&dir, &config), &config, &opts(&cache))
            .expect_err("a repository-controlled plugin repository must not be trusted implicitly");
    assert!(err.to_string().contains("trusted_registries.jvm"), "{err}");

    // An allowlist for a different URL does not help.
    let config = trusting("https://other.example/m2");
    assert!(
        preflight_project_inputs_with_options(&dir, &specs(&dir, &config), &config, &opts(&cache))
            .is_err()
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cache);
}

#[test]
fn allowlisted_plugin_repositories_report_plugins_as_unvetted_instead_of_public_checks() {
    let dir = corp_repo_project();
    let cache = unique_dir();
    let config = trusting("https://PLUGINS.corp.example/m2/");
    let specs = specs(&dir, &config);
    let warnings = preflight_project_inputs_with_options(&dir, &specs, &config, &opts(&cache))
        .expect("an allowlisted plugin repository passes preflight");
    let unvetted: Vec<&Issue> = warnings
        .iter()
        .filter(|issue| issue.check == checks::names::RESOLUTION_PRIVATE_REGISTRY_UNVETTED)
        .collect();
    assert_eq!(unvetted.len(), 1, "{warnings:?}");
    assert_eq!(unvetted[0].severity, Severity::Warning);
    assert_eq!(
        unvetted[0].package,
        "com.corp.convention:com.corp.convention.gradle.plugin"
    );
    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &opts(&cache)).unwrap();
    assert!(
        projects.iter().all(|project| !project.unlocked_tooling),
        "plugins from a private repository are never checked against a public one"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cache);
}

#[test]
fn lookalikes_of_well_known_plugin_ids_are_flagged() {
    let cache = unique_dir();
    for (plugin, expected) in [
        (
            "id 'com.diffplug.spotles' version '6.25.0'",
            "com.diffplug.spotless:com.diffplug.spotless.gradle.plugin",
        ),
        (
            "id 'org.jetbrains.kotlin.jvn' version '2.0.0'",
            "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin",
        ),
        (
            "id 'org.springframework-boot' version '3.3.0'",
            "org.springframework.boot:org.springframework.boot.gradle.plugin",
        ),
    ] {
        let dir = gradle_project(&build_with_plugins(plugin), &[]);
        let config = config::SloppyJoeConfig::default();
        let warnings = preflight_project_inputs_with_options(
            &dir,
            &specs(&dir, &config),
            &config,
            &opts(&cache),
        )
        .unwrap();
        let flagged: Vec<&Issue> = warnings
            .iter()
            .filter(|issue| issue.check.starts_with("similarity/"))
            .collect();
        assert_eq!(flagged.len(), 1, "{plugin}: {warnings:?}");
        assert_eq!(flagged[0].severity, Severity::Error);
        assert_eq!(flagged[0].suggestion.as_deref(), Some(expected), "{plugin}");

        // An explicit allowlist entry suppresses the finding.
        let mut config = config::SloppyJoeConfig::default();
        config
            .allowed
            .insert("jvm".to_string(), vec![flagged[0].package.clone()]);
        let warnings = preflight_project_inputs_with_options(
            &dir,
            &specs(&dir, &config),
            &config,
            &opts(&cache),
        )
        .unwrap();
        assert!(
            warnings
                .iter()
                .all(|issue| !issue.check.starts_with("similarity/")),
            "{warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Well-known ids themselves and unrelated ids are not flagged.
    for plugin in [
        "id 'com.diffplug.spotless' version '6.25.0'",
        "id 'org.jetbrains.kotlin.js' version '1.9.0'",
        "id 'com.acme.internal-conventions' version '1.0.0'",
    ] {
        let dir = gradle_project(&build_with_plugins(plugin), &[]);
        let config = config::SloppyJoeConfig::default();
        let warnings = preflight_project_inputs_with_options(
            &dir,
            &specs(&dir, &config),
            &config,
            &opts(&cache),
        )
        .unwrap();
        assert!(
            warnings
                .iter()
                .all(|issue| !issue.check.starts_with("similarity/")),
            "{plugin}: {warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    let _ = std::fs::remove_dir_all(&cache);
}

#[tokio::test]
async fn implementation_checks_run_through_the_trait_for_plugin_projects_only() {
    let dir = gradle_project(
        &build_with_plugins("id 'com.diffplug.spotless' version '6.25.0'"),
        &[],
    );
    let config = config::SloppyJoeConfig::default();
    let cache = unique_dir();
    let specs = specs(&dir, &config);
    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &opts(&cache)).unwrap();
    let main = projects.iter().find(|p| !p.unlocked_tooling).unwrap();
    let tooling = projects.iter().find(|p| p.unlocked_tooling).unwrap();
    let client = registry::http_client();

    // A project without plugin markers has nothing to check.
    let none = crate::ecosystems::implementation_issues(
        main,
        client.clone(),
        &NoAdvisories,
        &opts(&cache),
    )
    .await
    .unwrap();
    assert!(none.is_empty(), "{none:?}");

    // A plugin project is checked: a plugin repository added after parsing is rejected when the
    // check builds its repository client, so the block proves the check ran.
    std::fs::write(
        dir.join("settings.gradle"),
        "pluginManagement { repositories { maven { url 'https://plugins.corp.example/m2' } } }",
    )
    .unwrap();
    let err =
        crate::ecosystems::implementation_issues(tooling, client, &NoAdvisories, &opts(&cache))
            .await
            .expect_err("plugin implementation checks must run for plugin projects");
    assert!(
        err.to_string()
            .contains("cannot be checked as a public registry"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cache);
}
