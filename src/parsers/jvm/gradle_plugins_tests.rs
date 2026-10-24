//! Gradle `plugins {}` requests resolve to plugin marker artifacts
//! (`<id>:<id>.gradle.plugin`) that are checked against the plugin
//! repositories. Anything whose id, version, or repository cannot be pinned
//! down statically must fail closed.

use crate::Dependency;
use crate::config::PluginRepository;
use crate::parsers::jvm::{parse, parse_gradle_build};
use crate::parsers::test_utils::{cleanup, empty_test_dir};
use std::path::{Path, PathBuf};

/// A temp git repository (so ancestor settings/build scripts are in scope)
/// populated with `files` (relative path, content).
fn repo(files: &[(&str, &str)]) -> PathBuf {
    let root = empty_test_dir("gradle-plugins");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    for (path, content) in files {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    root
}

fn coords(deps: &[Dependency]) -> Vec<String> {
    let mut coords: Vec<String> = deps
        .iter()
        .map(|dep| format!("{}@{}", dep.name, dep.version.as_deref().unwrap_or("-")))
        .collect();
    coords.sort();
    coords
}

fn marker(id: &str, version: &str) -> String {
    format!("{id}:{id}.gradle.plugin@{version}")
}

fn expect_plugin_error(root: &Path, build: &str) -> String {
    let err = parse_gradle_build(&root.join(build))
        .expect_err("must fail closed")
        .to_string();
    assert!(err.contains("Gradle plugin"), "unexpected error: {err}");
    err
}

#[test]
fn pinned_third_party_plugins_become_marker_dependencies() {
    let root = repo(&[(
        "build.gradle",
        "plugins {\n  id 'java'\n  id 'com.diffplug.spotless' version '6.25.0'\n  id 'org.springframework.boot' version '3.3.0' apply false\n}\nrepositories { mavenCentral() }\ndependencies { implementation 'com.google.guava:guava:33.0.0-jre' }",
    )]);
    let build = parse_gradle_build(&root.join("build.gradle")).unwrap();
    assert_eq!(
        coords(&build.deps),
        vec!["com.google.guava:guava@33.0.0-jre"]
    );
    assert_eq!(
        coords(&build.plugins),
        vec![
            marker("com.diffplug.spotless", "6.25.0"),
            marker("org.springframework.boot", "3.3.0"),
        ]
    );
    assert_eq!(
        build.plugin_repositories,
        vec![PluginRepository::GradlePluginPortal],
        "without pluginManagement repositories Gradle resolves plugins from the Plugin Portal"
    );
    // The public parse API keeps plugins visible instead of dropping them.
    assert_eq!(coords(&parse(&root).unwrap()).len(), 3);
    cleanup(&root);
}

#[test]
fn kotlin_dsl_plugin_forms_resolve_to_literal_ids() {
    let root = repo(&[(
        "build.gradle.kts",
        "plugins {\n  `java-library`\n  kotlin(\"jvm\") version \"2.0.0\"\n  id(\"io.gitlab.arturbosch.detekt\").version(\"1.23.6\")\n  id(\"com.diffplug.spotless\") version \"6.25.0\" apply false\n}",
    )]);
    let build = parse_gradle_build(&root.join("build.gradle.kts")).unwrap();
    assert_eq!(
        coords(&build.plugins),
        vec![
            marker("com.diffplug.spotless", "6.25.0"),
            marker("io.gitlab.arturbosch.detekt", "1.23.6"),
            marker("org.jetbrains.kotlin.jvm", "2.0.0"),
        ]
    );
    cleanup(&root);
}

#[test]
fn dynamic_missing_or_computed_plugin_versions_block() {
    for plugins in [
        "id 'com.example.plugin' version '1.+'",
        "id 'com.example.plugin' version '+'",
        "id 'com.example.plugin' version 'latest.release'",
        "id 'com.example.plugin' version '[1.0,2.0)'",
        "id 'com.example.plugin' version '1.0-SNAPSHOT'",
        "id 'com.example.plugin' version \"${pluginVersion}\"",
        "id 'com.example.plugin' version pluginVersion",
        "id 'com.example.plugin' version libs.versions.example.get()",
        "id 'com.example.plugin'",
        "id 'com.example.plugin' version ''",
    ] {
        let root = repo(&[("build.gradle", &format!("plugins {{ {plugins} }}"))]);
        expect_plugin_error(&root, "build.gradle");
        cleanup(&root);
    }
}

#[test]
fn computed_plugin_ids_block() {
    for plugins in [
        "id \"${evilPlugin}\" version '1.0.0'",
        "id(pluginId) version \"1.0.0\"",
        "kotlin(\"${evil}\") version \"1.0.0\"",
        "alias(other.plugins.example)",
        "id 'com.example.plugin' version '1.0.0' version '2.0.0'",
        "version '1.0.0'",
    ] {
        let root = repo(&[("build.gradle.kts", &format!("plugins {{ {plugins} }}"))]);
        expect_plugin_error(&root, "build.gradle.kts");
        cleanup(&root);
    }
}

const CATALOG: &str = r#"
[versions]
kotlin = "2.0.0"
rich = { strictly = "1.0.0" }
dynamic = "1.+"

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
spotless = { id = "com.diffplug.spotless", version = "6.25.0" }
detekt = "io.gitlab.arturbosch.detekt:1.23.6"
rich-version = { id = "com.example.rich", version.ref = "rich" }
strict-inline = { id = "com.example.strict", version = { strictly = "1.0.0" } }
dynamic-ref = { id = "com.example.dynamic", version.ref = "dynamic" }
missing-ref = { id = "com.example.missing", version.ref = "nope" }
no-version = { id = "com.example.noversion" }
"#;

#[test]
fn version_catalog_plugin_aliases_resolve_to_literal_ids_and_versions() {
    let root = repo(&[
        ("settings.gradle.kts", "rootProject.name = \"demo\""),
        ("gradle/libs.versions.toml", CATALOG),
        (
            "build.gradle.kts",
            "plugins {\n  alias(libs.plugins.kotlin.jvm)\n  alias(libs.plugins.spotless) apply false\n  alias(libs.plugins.detekt)\n}",
        ),
    ]);
    let build = parse_gradle_build(&root.join("build.gradle.kts")).unwrap();
    assert_eq!(
        coords(&build.plugins),
        vec![
            marker("com.diffplug.spotless", "6.25.0"),
            marker("io.gitlab.arturbosch.detekt", "1.23.6"),
            marker("org.jetbrains.kotlin.jvm", "2.0.0"),
        ]
    );
    cleanup(&root);
}

#[test]
fn subproject_aliases_use_the_build_root_catalog() {
    let root = repo(&[
        ("settings.gradle", "include 'app'"),
        ("gradle/libs.versions.toml", CATALOG),
        (
            "app/build.gradle",
            "plugins { alias(libs.plugins.spotless) }",
        ),
    ]);
    let build = parse_gradle_build(&root.join("app/build.gradle")).unwrap();
    assert_eq!(
        coords(&build.plugins),
        vec![marker("com.diffplug.spotless", "6.25.0")]
    );
    cleanup(&root);
}

#[test]
fn unresolvable_catalog_aliases_block() {
    for alias in [
        "libs.plugins.unknown",
        "libs.plugins.rich.version",
        "libs.plugins.strict.inline",
        "libs.plugins.dynamic.ref",
        "libs.plugins.missing.ref",
        "libs.plugins.no.version",
    ] {
        let root = repo(&[
            ("gradle/libs.versions.toml", CATALOG),
            ("build.gradle.kts", &format!("plugins {{ alias({alias}) }}")),
        ]);
        expect_plugin_error(&root, "build.gradle.kts");
        cleanup(&root);
    }

    // No catalog at all.
    let root = repo(&[(
        "build.gradle.kts",
        "plugins { alias(libs.plugins.spotless) }",
    )]);
    expect_plugin_error(&root, "build.gradle.kts");
    cleanup(&root);

    // A catalog redefined in settings may not come from gradle/libs.versions.toml.
    let root = repo(&[
        ("gradle/libs.versions.toml", CATALOG),
        (
            "settings.gradle.kts",
            "dependencyResolutionManagement { versionCatalogs { create(\"libs\") { from(files(\"elsewhere.toml\")) } } }",
        ),
        (
            "build.gradle.kts",
            "plugins { alias(libs.plugins.spotless) }",
        ),
    ]);
    expect_plugin_error(&root, "build.gradle.kts");
    cleanup(&root);

    // A malformed catalog fails closed.
    let root = repo(&[
        ("gradle/libs.versions.toml", "[plugins\nbroken"),
        (
            "build.gradle.kts",
            "plugins { alias(libs.plugins.spotless) }",
        ),
    ]);
    expect_plugin_error(&root, "build.gradle.kts");
    cleanup(&root);
}

#[test]
fn versionless_plugins_resolve_from_plugin_management_or_ancestor_builds() {
    let root = repo(&[
        (
            "settings.gradle",
            "pluginManagement { plugins { id 'com.diffplug.spotless' version '6.25.0' } }\ninclude 'app'",
        ),
        (
            "build.gradle",
            "plugins { id 'org.springframework.boot' version '3.3.0' apply false }",
        ),
        (
            "app/build.gradle",
            "plugins {\n  id 'com.diffplug.spotless'\n  id 'org.springframework.boot'\n}",
        ),
    ]);
    let build = parse_gradle_build(&root.join("app/build.gradle")).unwrap();
    assert_eq!(
        coords(&build.plugins),
        vec![
            marker("com.diffplug.spotless", "6.25.0"),
            marker("org.springframework.boot", "3.3.0"),
        ]
    );
    cleanup(&root);
}

#[test]
fn versionless_plugin_with_dynamic_managed_version_blocks() {
    let root = repo(&[
        (
            "settings.gradle",
            "pluginManagement { plugins { id 'com.diffplug.spotless' version '6.+' } }",
        ),
        ("build.gradle", "plugins { id 'com.diffplug.spotless' }"),
    ]);
    expect_plugin_error(&root, "build.gradle");
    cleanup(&root);
}

#[test]
fn settings_plugins_are_scanned_with_the_build() {
    let root = repo(&[
        (
            "settings.gradle.kts",
            "plugins { id(\"org.gradle.toolchains.foojay-resolver-convention\") version \"0.8.0\" }",
        ),
        (
            "build.gradle.kts",
            "dependencies { implementation(\"com.example:lib:1.0.0\") }",
        ),
    ]);
    let build = parse_gradle_build(&root.join("build.gradle.kts")).unwrap();
    assert_eq!(
        coords(&build.plugins),
        vec![marker(
            "org.gradle.toolchains.foojay-resolver-convention",
            "0.8.0"
        )]
    );
    cleanup(&root);

    let root = repo(&[
        ("settings.gradle", "plugins { id 'com.example.settings' }"),
        ("build.gradle", "dependencies {}"),
    ]);
    let err = parse_gradle_build(&root.join("build.gradle"))
        .expect_err("a version-less settings plugin cannot be vetted")
        .to_string();
    assert!(err.contains("settings.gradle"), "{err}");
    cleanup(&root);
}

#[test]
fn plugin_repositories_follow_plugin_management_order() {
    let root = repo(&[
        (
            "settings.gradle",
            "pluginManagement {\n  repositories {\n    mavenCentral()\n    gradlePluginPortal()\n  }\n}",
        ),
        (
            "build.gradle",
            "plugins { id 'com.diffplug.spotless' version '6.25.0' }",
        ),
    ]);
    let build = parse_gradle_build(&root.join("build.gradle")).unwrap();
    assert_eq!(
        build.plugin_repositories,
        vec![
            PluginRepository::MavenCentral,
            PluginRepository::GradlePluginPortal
        ]
    );
    cleanup(&root);
}

#[test]
fn custom_plugin_repositories_are_captured_and_block_the_plain_parse_api() {
    for repository in [
        "maven { url = uri(\"https://plugins.corp.example/m2\") }",
        "maven { url 'https://plugins.corp.example/m2' }",
        "maven { url = \"https://plugins.corp.example/m2\" }",
        "maven(\"https://plugins.corp.example/m2\")",
        "maven(url = \"https://plugins.corp.example/m2\")",
        "maven { setUrl(\"https://plugins.corp.example/m2\") }",
        "maven {\n  name = \"corp\"\n  url = uri(\"https://plugins.corp.example/m2\")\n  credentials {\n    username = providers.gradleProperty(\"corpUser\").get()\n  }\n}",
    ] {
        let root = repo(&[
            (
                "settings.gradle.kts",
                &format!(
                    "pluginManagement {{ repositories {{ {repository}\n gradlePluginPortal() }} }}"
                ),
            ),
            (
                "build.gradle.kts",
                "plugins { id(\"com.corp.convention\") version \"1.0.0\" }",
            ),
        ]);
        let build = parse_gradle_build(&root.join("build.gradle.kts"))
            .unwrap_or_else(|err| panic!("{repository}: {err}"));
        assert_eq!(
            build.plugin_repositories,
            vec![
                PluginRepository::Custom("https://plugins.corp.example/m2".to_string()),
                PluginRepository::GradlePluginPortal
            ],
            "{repository}"
        );
        let err = parse(&root).expect_err("custom plugin repositories need an allowlist");
        assert!(
            err.to_string().contains("plugin repository"),
            "{repository}: {err}"
        );
        cleanup(&root);
    }
}

#[test]
fn unsupported_plugin_repository_declarations_block() {
    for repository in [
        "google()",
        "mavenLocal()",
        "ivy { url = uri(\"https://ivy.example\") }",
        "flatDir { dirs(\"libs\") }",
        "maven { url = uri(corpUrl) }",
        "maven { url = \"${corpBase}/m2\" }",
        "maven { url = uri(\"https://a.example\"); url = uri(\"https://b.example\") }",
        "maven { content { includeGroup(\"com.corp\") } }",
        "exclusiveContent { forRepository { gradlePluginPortal() } }",
        "gradlePluginPortal { content { includeGroup(\"com.corp\") } }",
    ] {
        let root = repo(&[
            (
                "settings.gradle.kts",
                &format!("pluginManagement {{ repositories {{ {repository} }} }}"),
            ),
            ("build.gradle.kts", "dependencies {}"),
        ]);
        assert!(
            parse_gradle_build(&root.join("build.gradle.kts")).is_err(),
            "must fail closed: {repository}"
        );
        cleanup(&root);
    }
}

#[test]
fn project_repositories_keep_the_maven_central_only_policy() {
    let root = repo(&[(
        "build.gradle",
        "repositories { gradlePluginPortal() }\ndependencies {}",
    )]);
    assert!(parse_gradle_build(&root.join("build.gradle")).is_err());
    cleanup(&root);
}

#[test]
fn plugin_management_outside_settings_blocks() {
    let root = repo(&[(
        "build.gradle",
        "pluginManagement { repositories { gradlePluginPortal() } }",
    )]);
    assert!(parse_gradle_build(&root.join("build.gradle")).is_err());
    cleanup(&root);
}
