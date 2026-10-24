use super::*;
use crate::parsers::test_utils::*;

fn setup_gradle(content: &str) -> std::path::PathBuf {
    setup_test_dir("jvm", "build.gradle", content)
}

fn setup_pom(content: &str) -> std::path::PathBuf {
    setup_test_dir("jvm", "pom.xml", content)
}

#[test]
fn pinned_third_party_gradle_plugins_are_scanned_as_marker_artifacts() {
    for (file, body, marker) in [
        (
            "build.gradle",
            "plugins {\n    id 'java'\n    id 'com.evil.gradle-plugin' version '1.0.0'\n}\nrepositories { mavenCentral() }\ndependencies { implementation 'com.google.guava:guava:31.1-jre' }",
            "com.evil.gradle-plugin:com.evil.gradle-plugin.gradle.plugin",
        ),
        (
            "build.gradle.kts",
            "plugins {\n    `java-library`\n    id(\"com.evil.gradle-plugin\") version \"1.0.0\"\n}",
            "com.evil.gradle-plugin:com.evil.gradle-plugin.gradle.plugin",
        ),
        (
            "build.gradle.kts",
            "plugins { kotlin(\"jvm\") version \"1.0.0\" }",
            "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin",
        ),
    ] {
        let dir = setup_test_dir("jvm", file, body);
        let deps = parse(&dir).unwrap_or_else(|err| panic!("{body}: {err}"));
        let plugin = deps
            .iter()
            .find(|dep| dep.name == marker)
            .unwrap_or_else(|| panic!("plugin marker must be scanned for {body}: {deps:?}"));
        assert_eq!(plugin.version.as_deref(), Some("1.0.0"));
        cleanup(&dir);
    }
}

#[test]
fn reject_unverifiable_gradle_plugins_in_build_scripts() {
    for (file, body) in [
        ("build.gradle.kts", "plugins { alias(libs.plugins.evil) }"),
        ("build.gradle", "plugins { id 'com.evil.gradle-plugin' }"),
        ("build.gradle", "plugins { id \"${evilPlugin}\" }"),
        (
            "build.gradle",
            "plugins { id 'com.evil.gradle-plugin' version '1.+' }",
        ),
    ] {
        let dir = setup_test_dir("jvm", file, body);
        let err = parse(&dir).expect_err(&format!(
            "unverifiable Gradle plugins must fail closed: {body}"
        ));
        assert!(
            err.to_string().contains("Gradle plugin"),
            "unexpected error for {body}: {err}"
        );
        cleanup(&dir);
    }
}

#[test]
fn reject_repository_expressions_outside_literal_blocks() {
    for body in [
        "repositories.maven { url 'https://evil.example' }\ndependencies {}",
        "pluginManagement.repositories.maven { url 'https://evil.example' }",
    ] {
        let dir = setup_gradle("dependencies {}");
        std::fs::write(dir.join("settings.gradle"), body).unwrap();
        assert!(parse(&dir).is_err(), "must fail closed: {body}");
        cleanup(&dir);
    }
}

#[test]
fn reject_unverifiable_gradle_plugins_in_settings() {
    for (settings, body) in [
        (
            "settings.gradle",
            "pluginManagement { plugins { id 'com.evil.settings' version '1.0.0' } }\nplugins { id 'com.evil.settings' version '1.+' }",
        ),
        (
            "settings.gradle.kts",
            "plugins { id(\"com.evil.settings\") }",
        ),
        (
            "settings.gradle",
            "pluginManagement { resolutionStrategy { eachPlugin { useModule('com.evil:x:1.0.0') } } }",
        ),
    ] {
        let dir = setup_gradle("dependencies { implementation 'com.example:lib:1.0.0' }");
        std::fs::write(dir.join(settings), body).unwrap();
        let err = parse(&dir).expect_err(&format!(
            "settings plugin declarations must fail closed: {body}"
        ));
        assert!(err.to_string().contains(settings), "{err}");
        cleanup(&dir);
    }
}

#[test]
fn accept_core_gradle_plugins() {
    for (file, body) in [
        (
            "build.gradle",
            "plugins {\n    id 'java'\n    id 'maven-publish'\n    id 'org.gradle.application'\n}\ndependencies { implementation 'com.example:lib:1.0.0' }",
        ),
        (
            "build.gradle.kts",
            "plugins {\n    `java-library`\n    java\n    id(\"jacoco\") apply false\n}\ndependencies { implementation(\"com.example:lib:1.0.0\") }",
        ),
    ] {
        let dir = setup_test_dir("jvm", file, body);
        let deps = parse(&dir).unwrap_or_else(|err| panic!("core plugins are built in: {err}"));
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.example:lib");
        cleanup(&dir);
    }
}

#[test]
fn reject_gradle_resolution_strategy_overrides() {
    let dir = setup_gradle(
        "configurations.all { resolutionStrategy.force 'com.evil:payload:1.0.0' }\ndependencies { implementation 'com.example:lib:1.0.0' }",
    );
    assert!(
        parse(&dir).is_err(),
        "resolutionStrategy can rewrite resolved versions and must fail closed"
    );
    cleanup(&dir);
}

#[test]
fn parse_gradle_implementation() {
    let dir = setup_gradle("implementation 'com.google.guava:guava:31.1-jre'");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "com.google.guava:guava");
    assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
    assert_eq!(deps[0].ecosystem, crate::Ecosystem::Jvm);
    cleanup(&dir);
}

#[test]
fn parse_gradle_api_double_quotes() {
    let dir = setup_gradle("api \"org.slf4j:slf4j-api:2.0.0\"");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "org.slf4j:slf4j-api");
    cleanup(&dir);
}

#[test]
fn reject_unmodeled_gradle_script_sources() {
    for expression in [
        "apply from: 'dependencies.gradle'",
        "apply(from = \"dependencies.gradle.kts\")",
        "includeBuild('../payload')",
    ] {
        let dir = setup_gradle(&format!("{expression}\ndependencies {{}}"));
        assert!(
            parse(&dir).is_err(),
            "unmodeled script sources must fail closed: {expression}"
        );
        cleanup(&dir);
    }
}

#[test]
fn reject_custom_sources_in_gradle_settings() {
    for settings in ["settings.gradle", "settings.gradle.kts"] {
        let dir = setup_gradle("dependencies { implementation 'com.example:lib:1.0.0' }");
        std::fs::write(dir.join(settings), "dependencyResolutionManagement { repositories { maven { url = uri(\"https://attacker.example\") } } }").unwrap();
        let err = parse(&dir).expect_err("settings repositories must obey the same source policy");
        assert!(err.to_string().contains(settings));
        cleanup(&dir);
    }
}

#[test]
fn reject_unmodeled_gradle_dependency_expressions() {
    for expression in [
        "add(\"implementation\", \"com.example:payload:1.0.0\")",
        "customConfiguration(\"com.example:payload:1.0.0\")",
        "implementation(libs.payload)",
    ] {
        let dir = setup_gradle(&format!("dependencies {{ {expression} }}"));
        assert!(
            parse(&dir).is_err(),
            "unmodeled expression must fail closed: {expression}"
        );
        cleanup(&dir);
    }
    let dir = setup_gradle("dependencies.add(\"implementation\", \"com.example:payload:1.0.0\")");
    assert!(
        parse(&dir).is_err(),
        "qualified dependency mutations must fail closed"
    );
    cleanup(&dir);
}

#[test]
fn parse_inline_and_multiline_gradle_dependencies() {
    for body in [
        "dependencies { implementation 'com.example:lib:1.0.0'; testImplementation(\"com.example:test:2.0.0\") }",
        "dependencies {\n implementation(\n \"com.example:lib:1.0.0\"\n )\n testImplementation(\"com.example:test:2.0.0\")\n}",
    ] {
        let dir = setup_gradle(body);
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "com.example:lib");
        assert_eq!(deps[1].version.as_deref(), Some("2.0.0"));
        cleanup(&dir);
    }
}

#[test]
fn parse_gradle_multiple_configs() {
    let dir = setup_gradle(
        "implementation 'com.google.guava:guava:31.1-jre'\ntestImplementation 'junit:junit:4.13'",
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    cleanup(&dir);
}

#[test]
fn reject_unmodeled_maven_dependency_tags() {
    for open in [
        "m:dependency",
        "dependency xmlns=\"http://maven.apache.org/POM/4.0.0\"",
    ] {
        let close = open.split_whitespace().next().unwrap();
        let dir = setup_pom(&format!(
            "<project xmlns:m=\"http://maven.apache.org/POM/4.0.0\"><dependencies><{open}><groupId>com.example</groupId><artifactId>payload</artifactId><version>1.0.0</version></{close}></dependencies></project>"
        ));
        assert!(
            parse(&dir).is_err(),
            "unmodeled dependency tags must fail closed: {open}"
        );
        cleanup(&dir);
    }
}

fn names(deps: &[Dependency]) -> Vec<String> {
    let mut names: Vec<String> = deps.iter().map(|dep| dep.name.clone()).collect();
    names.sort();
    names
}

#[test]
fn parse_maven_parent_plugins_and_extensions() {
    let dir = setup_pom(
        r#"<project>
  <parent>
<groupId>com.evil</groupId>
<artifactId>evil-parent</artifactId>
<version>1.0.0</version>
  </parent>
  <build>
<plugins>
  <plugin>
    <groupId>com.evil</groupId>
    <artifactId>evil-maven-plugin</artifactId>
    <version>1.0.0</version>
  </plugin>
</plugins>
<extensions>
  <extension>
    <groupId>com.evil</groupId>
    <artifactId>evil-extension</artifactId>
    <version>1.0.0</version>
  </extension>
</extensions>
  </build>
  <dependencies>
<dependency>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <version>31.1-jre</version>
</dependency>
  </dependencies>
</project>"#,
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(
        names(&deps),
        vec![
            "com.evil:evil-extension",
            "com.evil:evil-maven-plugin",
            "com.evil:evil-parent",
            "com.google.guava:guava",
        ]
    );
    let parent = deps
        .iter()
        .find(|dep| dep.name == "com.evil:evil-parent")
        .unwrap();
    assert_eq!(parent.version.as_deref(), Some("1.0.0"));
    cleanup(&dir);
}

#[test]
fn maven_plugin_uses_default_group_and_ignores_nested_coordinates() {
    let dir = setup_pom(
        r#"<project><build><pluginManagement><plugins>
  <plugin>
<artifactId>maven-dependency-plugin</artifactId>
<version>3.6.0</version>
<extensions>true</extensions>
<configuration>
  <artifactItems><artifactItem><groupId>com.config</groupId><artifactId>item</artifactId></artifactItem></artifactItems>
</configuration>
<dependencies>
  <dependency><groupId>com.nested</groupId><artifactId>plugin-dep</artifactId><version>2.0.0</version></dependency>
</dependencies>
  </plugin>
</plugins></pluginManagement></build></project>"#,
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(
        names(&deps),
        vec![
            "com.nested:plugin-dep",
            "org.apache.maven.plugins:maven-dependency-plugin",
        ]
    );
    cleanup(&dir);
}

#[test]
fn maven_local_reactor_parent_is_not_a_registry_dependency() {
    let root = empty_test_dir("jvm");
    std::fs::write(
        root.join("pom.xml"),
        "<project><groupId>com.acme</groupId><artifactId>acme-parent</artifactId><version>1.0.0</version><dependencies><dependency><groupId>com.other</groupId><artifactId>x</artifactId></dependency></dependencies></project>",
    )
    .unwrap();
    let child = root.join("child");
    std::fs::create_dir_all(&child).unwrap();
    let child_pom = "<project><parent><groupId>com.acme</groupId><artifactId>acme-parent</artifactId><version>1.0.0</version>{rel}</parent><artifactId>child</artifactId></project>";
    std::fs::write(child.join("pom.xml"), child_pom.replace("{rel}", "")).unwrap();
    assert!(
        parse(&child).unwrap().is_empty(),
        "parent resolved from ../pom.xml is part of the local reactor"
    );

    // An explicitly empty relativePath forces repository resolution.
    std::fs::write(
        child.join("pom.xml"),
        child_pom.replace("{rel}", "<relativePath/>"),
    )
    .unwrap();
    assert_eq!(names(&parse(&child).unwrap()), vec!["com.acme:acme-parent"]);

    // A local pom with different coordinates does not satisfy the parent.
    std::fs::write(
        child.join("pom.xml"),
        child_pom
            .replace("acme-parent", "evil-parent")
            .replace("{rel}", ""),
    )
    .unwrap();
    assert_eq!(names(&parse(&child).unwrap()), vec!["com.acme:evil-parent"]);
    cleanup(&root);
}

#[test]
fn reject_maven_build_coordinates_without_artifact_or_with_unmodeled_tags() {
    for body in [
        "<parent><groupId>com.evil</groupId><version>1</version></parent>",
        "<parent><artifactId>evil</artifactId><version>1</version></parent>",
        "<build><extensions><extension><artifactId>evil</artifactId></extension></extensions></build>",
        "<build><plugins><plugin><groupId>com.evil</groupId></plugin></plugins></build>",
        "<build><plugins><m:plugin><groupId>com.evil</groupId><artifactId>x</artifactId></m:plugin></plugins></build>",
        "<build><plugins><plugin combine.self=\"override\"><groupId>com.evil</groupId><artifactId>x</artifactId></plugin></plugins></build>",
        "<parent xmlns=\"x\"><groupId>com.evil</groupId><artifactId>x</artifactId></parent>",
    ] {
        let dir = setup_pom(&format!(
            "<project xmlns:m=\"http://maven.apache.org/POM/4.0.0\">{body}</project>"
        ));
        assert!(parse(&dir).is_err(), "must fail closed: {body}");
        cleanup(&dir);
    }
}

#[test]
fn parse_compact_maven_dependencies() {
    let dir = setup_pom(
        "<project><dependencies><dependency><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.0.0</version></dependency><dependency><groupId>com.example</groupId><artifactId>other</artifactId><version>2.0.0</version></dependency></dependencies></project>",
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    assert_eq!(deps[0].name, "com.example:lib");
    assert_eq!(deps[1].version.as_deref(), Some("2.0.0"));
    cleanup(&dir);
}

#[test]
fn parse_pom_xml_dependency() {
    let dir = setup_pom(
        r#"
<project>
  <dependencies>
<dependency>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <version>31.1-jre</version>
</dependency>
  </dependencies>
</project>
"#,
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "com.google.guava:guava");
    assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
    cleanup(&dir);
}

#[test]
fn parse_pom_multiple_dependencies() {
    let dir = setup_pom(
        r#"
<project>
  <dependencies>
<dependency>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <version>31.1</version>
</dependency>
<dependency>
  <groupId>junit</groupId>
  <artifactId>junit</artifactId>
  <version>4.13</version>
</dependency>
  </dependencies>
</project>
"#,
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    cleanup(&dir);
}

#[test]
fn gradle_takes_priority_over_pom() {
    let dir = setup_gradle("implementation 'a:b:1.0'");
    std::fs::write(
        dir.join("pom.xml"),
        "<project><dependencies><dependency><groupId>c</groupId><artifactId>d</artifactId></dependency></dependencies></project>",
    ).unwrap();
    let deps = parse(&dir).unwrap();
    // Should parse gradle, not pom
    assert_eq!(deps[0].name, "a:b");
    cleanup(&dir);
}

#[test]
fn extract_gradle_dep_no_version() {
    let dep = extract_gradle_dep(
        "implementation 'com.example:lib'",
        Path::new("build.gradle"),
    );
    assert!(dep.is_ok());
    let dep = dep.unwrap().unwrap();
    assert_eq!(dep.name, "com.example:lib");
    assert_eq!(dep.version, None);
}

#[test]
fn parse_gradle_kts() {
    let dir = setup_test_dir(
        "jvm",
        "build.gradle.kts",
        "implementation(\"com.google.guava:guava:31.1-jre\")",
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "com.google.guava:guava");
    assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
    cleanup(&dir);
}

#[test]
fn reject_gradle_classifier_coordinates() {
    let dir = setup_gradle("implementation 'org.example:foo:1.2.3:tests'");
    let err = parse(&dir).expect_err("classifier-bearing Gradle coords must fail closed");
    assert!(err.to_string().contains("classifier-bearing coordinates"));
    cleanup(&dir);
}

#[test]
fn plain_google_repository_is_supported_and_flagged() {
    let dir = setup_gradle(
        "repositories {\n    google()\n    mavenCentral()\n}\ndependencies { implementation 'androidx.core:core:1.12.0' }",
    );
    let build = parse_gradle_build(&dir.join("build.gradle")).unwrap();
    assert!(build.uses_google_maven);
    assert_eq!(build.deps[0].name, "androidx.core:core");
    cleanup(&dir);
    let dir = setup_gradle(
        "repositories { mavenCentral() }\ndependencies { implementation 'a.b:c:1.0' }",
    );
    assert!(
        !parse_gradle_build(&dir.join("build.gradle"))
            .unwrap()
            .uses_google_maven
    );
    cleanup(&dir);
}

#[test]
fn buildscript_classpath_with_exact_versions_is_scanned() {
    let dir = setup_gradle(
        "buildscript {\n    repositories {\n        google()\n        mavenCentral()\n    }\n    dependencies {\n        classpath 'com.android.tools.build:gradle:8.1.0'\n        classpath(\"org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.0\")\n    }\n}\nrepositories { mavenCentral() }\ndependencies { implementation 'a.b:c:1.0' }",
    );
    let build = parse_gradle_build(&dir.join("build.gradle")).unwrap();
    let names: Vec<_> = build.classpath.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "com.android.tools.build:gradle",
            "org.jetbrains.kotlin:kotlin-gradle-plugin"
        ]
    );
    assert!(build.classpath_uses_google_maven);
    assert!(
        !build.uses_google_maven,
        "project repositories are separate"
    );
    assert_eq!(build.deps.len(), 1);
    cleanup(&dir);
}

#[test]
fn unpinned_or_dynamic_buildscript_classpath_blocks() {
    for dep in [
        "classpath 'com.android.tools.build:gradle'",
        "classpath 'com.android.tools.build:gradle:8.+'",
        "classpath 'com.android.tools.build:gradle:[8.0,9.0)'",
        "classpath 'com.android.tools.build:gradle:latest.release'",
        "classpath 'com.android.tools.build:gradle:+'",
        "classpath files('x.jar')",
        "classpath project(':tool')",
        "classpath platform('a:b:1')",
        "classpath libs.agp",
    ] {
        let dir = setup_gradle(&format!(
            "buildscript {{\n repositories {{ mavenCentral() }}\n dependencies {{ {dep} }}\n}}"
        ));
        assert!(
            parse_gradle_build(&dir.join("build.gradle")).is_err(),
            "{dep}"
        );
        cleanup(&dir);
    }
}

#[test]
fn buildscript_custom_repositories_still_block() {
    let dir = setup_gradle(
        "buildscript {\n repositories { maven { url 'https://x.example' } }\n dependencies { classpath 'a:b:1.0' }\n}",
    );
    assert!(parse_gradle_build(&dir.join("build.gradle")).is_err());
    cleanup(&dir);
}

#[test]
fn google_repository_with_options_still_blocks() {
    for repo in [
        "google { content { includeGroup 'x' } }",
        "google() { content { includeGroup 'x' } }",
        "google('https://evil.example')",
    ] {
        let dir = setup_gradle(&format!("repositories {{ mavenCentral()\n {repo} }}"));
        assert!(
            parse_gradle_build(&dir.join("build.gradle")).is_err(),
            "{repo}"
        );
        cleanup(&dir);
    }
}

#[test]
fn reject_multiline_gradle_custom_repository_blocks() {
    let dir = setup_gradle(
        r#"
repositories
{
mavenCentral()
maven
{
    url = uri("https://repo.example.com/maven")
}
}
"#,
    );
    let err = parse(&dir).expect_err("custom Gradle repositories must fail closed");
    assert!(err.to_string().contains("Unsupported Gradle repository"));
    cleanup(&dir);
}

#[test]
fn reject_multiline_gradle_local_project_dependencies() {
    let dir = setup_gradle(
        r#"
dependencies {
implementation(
    project(":shared")
)
}
"#,
    );
    let err = parse(&dir).expect_err("local Gradle project deps must fail closed");
    assert!(
        err.to_string()
            .contains("Unsupported Gradle dependency source")
    );
    cleanup(&dir);
}

#[test]
fn reject_namespaced_maven_repository_tags() {
    let dir = setup_pom(
        r#"
<project xmlns:m="https://maven.apache.org/POM/4.0.0">
  <m:repositories>
<m:repository>
  <m:id>internal</m:id>
  <m:url>https://repo.example.com/maven</m:url>
</m:repository>
  </m:repositories>
</project>
"#,
    );
    let err = parse(&dir).expect_err("namespaced Maven repositories must fail closed");
    assert!(
        err.to_string()
            .contains("Unsupported Maven repository declaration")
    );
    cleanup(&dir);
}

#[test]
fn reject_namespaced_maven_system_path_dependencies() {
    let dir = setup_pom(
        r#"
<project xmlns:m="https://maven.apache.org/POM/4.0.0">
  <dependencies>
<dependency>
  <groupId>com.example</groupId>
  <artifactId>local</artifactId>
  <version>1.0.0</version>
  <m:systemPath>/tmp/local.jar</m:systemPath>
</dependency>
  </dependencies>
</project>
"#,
    );
    let err = parse(&dir).expect_err("namespaced Maven systemPath must fail closed");
    assert!(err.to_string().contains("systemPath"));
    cleanup(&dir);
}

#[test]
fn maven_core_extensions_block_the_project() {
    let dir = setup_pom(
        "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies></project>",
    );
    assert!(parse(&dir).is_ok());
    std::fs::create_dir_all(dir.join(".mvn")).unwrap();
    std::fs::write(
        dir.join(".mvn/extensions.xml"),
        "<extensions><extension><groupId>evil</groupId><artifactId>ext</artifactId><version>1</version></extension></extensions>",
    )
    .unwrap();
    let err = parse(&dir).unwrap_err().to_string();
    assert!(err.contains("core extensions"), "{err}");
    cleanup(&dir);
}
