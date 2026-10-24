//! Repository files Gradle and Maven read beside a JVM project.

use crate::ProjectInputKind;
use crate::ecosystems::ambient::{AmbientInput as Row, Disposition::*, Scope::*};

const GRADLE: &[ProjectInputKind] = &[ProjectInputKind::Gradle];
const MAVEN: &[ProjectInputKind] = &[ProjectInputKind::Maven];

pub(super) const AMBIENT: &[Row] = &[
    // Gradle
    Row::new(
        "gradle.properties",
        ProjectDir,
        ModeledElsewhere("parsers::jvm surfaces (gradle.properties allowlist, sysprops), with config_key_allow"),
    )
    .only(GRADLE),
    Row::new(
        "gradle/wrapper/gradle-wrapper.properties",
        ProjectDir,
        ModeledElsewhere("parsers::jvm::reject_untrusted_gradle_wrapper"),
    )
    .only(GRADLE),
    Row::new(
        "gradle/gradle-daemon-jvm.properties",
        ProjectDir,
        ModeledElsewhere("parsers::jvm surfaces (toolchainUrl.* is denied), with config_key_allow"),
    )
    .only(GRADLE),
    Row::new(
        "settings.gradle",
        ProjectDir,
        ModeledElsewhere("parsers::jvm::gradle_scan (plugin management, buildCache, includeBuild)"),
    )
    .only(GRADLE),
    Row::new(
        "settings.gradle.kts",
        ProjectDir,
        ModeledElsewhere("parsers::jvm::gradle_scan (plugin management, buildCache, includeBuild)"),
    )
    .only(GRADLE),
    Row::new(
        "buildSrc",
        ProjectDir,
        ModeledElsewhere("parsers::jvm::reject_buildsrc_without_script; its build script is scanned"),
    )
    .only(GRADLE),
    Row::new(
        "gradle/verification-metadata.xml",
        ProjectDir,
        Irrelevant("only adds checksum and signature checks to Gradle's own downloads; it cannot name a source, and the scan does not rely on it"),
    )
    .only(GRADLE),
    // Maven
    Row::new(
        ".mvn/extensions.xml",
        AncestorsToRepoRoot,
        Blocked("core extensions loaded by Maven itself are not scanned"),
    )
    .only(MAVEN),
    Row::new(
        ".mvn/settings.xml",
        AncestorsToRepoRoot,
        Blocked("project settings can redirect every repository through a mirror"),
    )
    .only(MAVEN),
    Row::new(
        ".mvn/toolchains.xml",
        AncestorsToRepoRoot,
        Blocked("toolchains select build tools that are not scanned"),
    )
    .only(MAVEN),
    Row::new(
        ".mvn/maven-build-cache-config.xml",
        AncestorsToRepoRoot,
        Blocked("a local or remote build cache supplies build outputs the scan cannot verify"),
    )
    .only(MAVEN),
    Row::new(
        ".mvn/maven.config",
        AncestorsToRepoRoot,
        ModeledElsewhere("parsers::jvm::surfaces maven.config allowlist, with config_key_allow"),
    )
    .only(MAVEN),
    Row::new(
        ".mvn/jvm.config",
        AncestorsToRepoRoot,
        ModeledElsewhere("parsers::jvm::surfaces jvm.config allowlist, with config_key_allow"),
    )
    .only(MAVEN),
    Row::new(
        ".mvn/wrapper/maven-wrapper.properties",
        AncestorsToRepoRoot,
        ModeledElsewhere("parsers::jvm::pom check_mvn_dir (wrapper URLs must be Maven Central)"),
    )
    .only(MAVEN),
];
