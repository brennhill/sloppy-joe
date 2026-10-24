//! Repository files Gradle and Maven read beside a JVM project.

use crate::ProjectInputKind;
use crate::ecosystems::ambient::{AmbientInput as Row, Disposition::*, Scope::*};

const GRADLE: &[ProjectInputKind] = &[ProjectInputKind::Gradle];
const INIT_WHY: &str = "a Gradle init script can add repositories and dependencies the scan never reads. Fix: do not commit init scripts; pass trusted ones from CI configuration outside the repository.";
const MAVEN: &[ProjectInputKind] = &[ProjectInputKind::Maven];

pub(super) const AMBIENT: &[Row] = &[
    // Gradle
    Row::new(
        "gradle.properties",
        ProjectDir,
        ModeledElsewhere(
            "parsers::jvm surfaces (gradle.properties allowlist, sysprops), with config_key_allow",
        ),
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
        ModeledElsewhere(
            "parsers::jvm::reject_buildsrc_without_script; its build script is scanned",
        ),
    )
    .only(GRADLE),
    Row::new(
        "gradle/verification-metadata.xml",
        ProjectDir,
        Modeled(crate::parsers::jvm::reject_weakened_verification_metadata),
    )
    .only(GRADLE),
    Row::new(
        "gradle/*.versions.toml",
        ProjectDir,
        Modeled(crate::parsers::jvm::reject_unreadable_version_catalog),
    )
    .only(GRADLE),
    // A script passed with `-I` (or placed in a user's init.d) can add repositories and
    // dependencies to every build; the scan only reads the project's own scripts.
    Row::new("init.gradle", ProjectDir, BlockedIfTracked(INIT_WHY)).only(GRADLE),
    Row::new("init.gradle.kts", ProjectDir, BlockedIfTracked(INIT_WHY)).only(GRADLE),
    Row::new("init.d/*", ProjectDir, BlockedIfTracked(INIT_WHY)).only(GRADLE),
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
