//! Allowlists for the repo-controlled files that steer Gradle's and Maven's own JVM and command
//! line: `gradle.properties`, `gradle/gradle-daemon-jvm.properties`, `.mvn/maven.config` and
//! `.mvn/jvm.config`. An entry that is not listed blocks; the operator can allow one exact entry
//! through `config_key_allow` (file ids `gradle.properties`, `gradle-daemon-jvm.properties`,
//! `maven.config`, `jvm.config`). See docs/specs/untrusted-input-hardening.md.
//!
//! Decisions:
//! - **Denied** (never allowable): agents, class path and module path overrides, argument files,
//!   debug and `-XX` options that run commands, system properties that redirect fetching or
//!   trust (trust store, proxy, home, local repository, build cache, Plugin Portal), cache and
//!   Java-home relocation, a Maven settings/toolchains/project file option, lax checksums.
//! - **Allowed**: memory and GC tuning, daemon and parallelism switches, logging, `-D` system
//!   properties outside the redirecting set, Maven build selection flags.
//! - **Value-restricted**: `org.gradle.dependency.verification` may not be `off`;
//!   `org.gradle.java.installations.auto-download` may only be `false`.
//! - Gradle project properties (keys outside `org.gradle.` and `systemProp.`) pass: they are
//!   ordinary build parameters and the build scripts that read them are scanned.

use super::sysprops::redirecting_props;
use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_flat, rule,
};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

const TRUE_FALSE: &[&str] = &["true", "false"];

fn is_count(value: &str) -> bool {
    value.trim().parse::<u32>().is_ok()
}

/// JVM options that load code or change what the JVM trusts or runs, for any file that hands
/// arguments to Gradle's or Maven's JVM.
macro_rules! jvm_denies {
    ($($extra:literal),*) => {
        redirecting_props!("-D"; "-javaagent", "-agentpath", "-agentlib", "-Xbootclasspath", "-Xrun",
            "-Xdebug", "-XX:OnError", "-XX:OnOutOfMemoryError", "-XX:Flags", "-XX:VMOptionsFile",
            "-cp", "-classpath", "--class-path", "--module-path", "--patch-module",
            "--upgrade-module-path", "-jar", "@" $(, $extra)*)
    };
}

const JVM_ARG_DENY: &[&str] = jvm_denies!();

const JVM_ARG_ALLOW: &[KeyRule] = &[
    rule("-D*", Any),
    rule("-Xmx*", Any),
    rule("-Xms*", Any),
    rule("-Xss*", Any),
    rule("-Xmn*", Any),
    rule("=-Xshare:auto", Any),
    rule("=-Xshare:off", Any),
    rule("=-ea", Any),
    rule("=-da", Any),
    rule("--add-opens", Any),
    rule("--add-exports", Any),
    rule("--add-reads", Any),
    rule("--add-modules", Any),
    rule("=-XX:+UseG1GC", Any),
    rule("=-XX:+UseParallelGC", Any),
    rule("=-XX:+UseSerialGC", Any),
    rule("=-XX:+UseZGC", Any),
    rule("=-XX:+UseShenandoahGC", Any),
    rule("=-XX:-UseGCOverheadLimit", Any),
    rule("=-XX:+HeapDumpOnOutOfMemoryError", Any),
    rule("=-XX:+UseStringDeduplication", Any),
    rule("=-XX:+UseContainerSupport", Any),
    rule("=-XX:+TieredCompilation", Any),
    rule("=-XX:-TieredCompilation", Any),
    rule("=-XX:-OmitStackTraceInFastThrow", Any),
    rule("=-XX:MaxMetaspaceSize", Any),
    rule("=-XX:MetaspaceSize", Any),
    rule("=-XX:ReservedCodeCacheSize", Any),
    rule("=-XX:TieredStopAtLevel", Any),
    rule("=-XX:MaxRAMPercentage", Any),
    rule("=-XX:InitialRAMPercentage", Any),
    rule("=-XX:MinRAMPercentage", Any),
    rule("=-XX:ParallelGCThreads", Any),
    rule("=-XX:ConcGCThreads", Any),
    rule("=-XX:CICompilerCount", Any),
];

/// JVM options that take the next token as their value.
const JVM_ARG_WITH_VALUE: &[&str] = &[
    "--add-opens",
    "--add-exports",
    "--add-reads",
    "--add-modules",
];

/// `-Dname=value` becomes the key `-Dname`; a flag with a separate value keeps the value with it.
fn jvm_arg_entries(args: &str) -> Vec<(String, Value)> {
    let mut tokens = args
        .split(|c: char| c.is_whitespace() || c == '\u{0c}')
        .filter(|token| !token.is_empty());
    let mut entries = Vec::new();
    while let Some(token) = tokens.next() {
        let (name, value) = token.split_once('=').unwrap_or((token, ""));
        let mut value = value.to_string();
        if JVM_ARG_WITH_VALUE.contains(&name) && !token.contains('=') {
            value = tokens.next().unwrap_or_default().to_string();
        }
        entries.push((name.to_string(), Value::String(value)));
    }
    entries
}

const GRADLE_DENY: &[&str] = redirecting_props!("systemProp."; "org.gradle.java.home",
    "org.gradle.cache.", "org.gradle.projectcachedir", "org.gradle.internal.");

const GRADLE_ALLOW: &[KeyRule] = &[
    rule("org.gradle.jvmargs", Str),
    rule("org.gradle.daemon", OneOf(TRUE_FALSE)),
    rule(
        "org.gradle.daemon.idletimeout",
        StrWhere(is_count, "a number"),
    ),
    rule("org.gradle.parallel", OneOf(TRUE_FALSE)),
    rule("org.gradle.workers.max", StrWhere(is_count, "a number")),
    rule("org.gradle.configureondemand", OneOf(TRUE_FALSE)),
    rule("org.gradle.caching", OneOf(TRUE_FALSE)),
    rule("org.gradle.vfs.watch", OneOf(TRUE_FALSE)),
    rule("org.gradle.vfs.verbose", OneOf(TRUE_FALSE)),
    rule("org.gradle.priority", OneOf(&["normal", "low"])),
    rule(
        "org.gradle.console",
        OneOf(&["auto", "plain", "rich", "verbose"]),
    ),
    rule(
        "org.gradle.logging.level",
        OneOf(&["quiet", "warn", "lifecycle", "info", "debug"]),
    ),
    rule(
        "org.gradle.warning.mode",
        OneOf(&["all", "summary", "fail", "none"]),
    ),
    rule("org.gradle.welcome", OneOf(&["once", "never"])),
    rule("org.gradle.problems.report", OneOf(TRUE_FALSE)),
    rule(
        "org.gradle.dependency.verification",
        OneOf(&["strict", "lenient"]),
    ),
    rule(
        "org.gradle.java.installations.auto-download",
        OneOf(&["false"]),
    ),
    rule("systemProp.*", Any),
];

const GRADLE_PROPERTIES: Surface = Surface {
    id: "gradle.properties",
    subject: "Gradle property",
    why: "it changes the JVM, trust store, proxy, caches or repository endpoints Gradle uses in ways the scan cannot verify",
    allow: GRADLE_ALLOW,
    deny: GRADLE_DENY,
    deny_under: &[],
    scope: &["org.gradle.", "systemProp."],
};

const GRADLE_JVM_ARGS: Surface = Surface {
    id: "gradle.properties",
    subject: "Gradle property (an org.gradle.jvmargs option)",
    why: "it loads code into Gradle's JVM or changes the trust store, proxy or repository endpoints it uses",
    allow: JVM_ARG_ALLOW,
    deny: JVM_ARG_DENY,
    deny_under: &[],
    scope: &[],
};

const DAEMON_JVM: Surface = Surface {
    id: "gradle-daemon-jvm.properties",
    subject: "Gradle daemon JVM property",
    why: "Gradle would download and run a JDK from a URL the scan cannot verify",
    allow: &[
        rule("toolchainVersion", Str),
        rule("toolchainVendor", Str),
        rule("toolchainImplementation", Str),
    ],
    deny: &["toolchainUrl"],
    deny_under: &[],
    scope: &[],
};

const MAVEN_JVM_ARGS: Surface = Surface {
    id: "jvm.config",
    subject: "Maven JVM option",
    why: "it loads code into Maven's JVM or changes the repository, settings, trust store or proxy it uses",
    allow: JVM_ARG_ALLOW,
    deny: jvm_denies!("-Djava.system.class.loader"),
    deny_under: &[],
    scope: &[],
};

const MAVEN_CONFIG: Surface = Surface {
    id: "maven.config",
    subject: "Maven option",
    why: "it changes the settings, toolchains, project file, repository or extensions Maven uses",
    allow: &[
        rule("-D*", Any),
        rule("=-B", Any),
        rule("=--batch-mode", Any),
        rule("=-e", Any),
        rule("=--errors", Any),
        rule("=-q", Any),
        rule("=--quiet", Any),
        rule("=-X", Any),
        rule("=--debug", Any),
        rule("=-V", Any),
        rule("=--show-version", Any),
        rule("=-U", Any),
        rule("=--update-snapshots", Any),
        rule("=-o", Any),
        rule("=--offline", Any),
        rule("=-N", Any),
        rule("=--non-recursive", Any),
        rule("=-fae", Any),
        rule("=--fail-at-end", Any),
        rule("=-ff", Any),
        rule("=--fail-fast", Any),
        rule("=-fn", Any),
        rule("=--fail-never", Any),
        rule("=-nsu", Any),
        rule("=--no-snapshot-updates", Any),
        rule("=-ntp", Any),
        rule("=--no-transfer-progress", Any),
        rule("=-am", Any),
        rule("=--also-make", Any),
        rule("=-amd", Any),
        rule("=--also-make-dependents", Any),
        rule("=-C", Any),
        rule("=--strict-checksums", Any),
        rule("=-T", Any),
        rule("=--threads", Any),
        rule("=-P", Any),
        rule("=--activate-profiles", Any),
        rule("=-pl", Any),
        rule("=--projects", Any),
        rule("=-rf", Any),
        rule("=--resume-from", Any),
        rule("=-b", Any),
        rule("=--builder", Any),
    ],
    deny: jvm_denies!(
        "=-s",
        "=--settings",
        "=-gs",
        "=--global-settings",
        "=-t",
        "=--toolchains",
        "=-gt",
        "=--global-toolchains",
        "=-f",
        "=--file",
        "=-c",
        "=--lax-checksums"
    ),
    deny_under: &[],
    scope: &[],
};

/// Maven long options (for abbreviation matching) and the options that take a value.
const MAVEN_LONG: &[&str] = &[
    "--batch-mode",
    "--errors",
    "--quiet",
    "--debug",
    "--show-version",
    "--update-snapshots",
    "--offline",
    "--non-recursive",
    "--fail-at-end",
    "--fail-fast",
    "--fail-never",
    "--no-snapshot-updates",
    "--no-transfer-progress",
    "--also-make",
    "--also-make-dependents",
    "--strict-checksums",
    "--lax-checksums",
    "--threads",
    "--activate-profiles",
    "--projects",
    "--resume-from",
    "--builder",
    "--settings",
    "--global-settings",
    "--toolchains",
    "--global-toolchains",
    "--file",
    "--define",
];
const MAVEN_LONG_WITH_VALUE: &[&str] = &[
    "--threads",
    "--activate-profiles",
    "--projects",
    "--resume-from",
    "--builder",
    "--settings",
    "--global-settings",
    "--toolchains",
    "--global-toolchains",
    "--file",
];
/// Short options that take a value, longest first so `-gs` is not read as `-g` + `s`.
const MAVEN_SHORT_WITH_VALUE: &[&str] = &[
    "-gs", "-gt", "-pl", "-rf", "-T", "-P", "-b", "-s", "-t", "-f",
];
const MAVEN_SHORT: &[&str] = &[
    "-B", "-e", "-q", "-X", "-V", "-U", "-o", "-N", "-fae", "-ff", "-fn", "-nsu", "-ntp", "-am",
    "-amd", "-C", "-c", "-v", "-h",
];

/// commons-cli accepts an unambiguous prefix of a long option.
fn canonical_long(name: &str) -> String {
    if MAVEN_LONG.contains(&name) {
        return name.to_string();
    }
    let matches: Vec<&&str> = MAVEN_LONG
        .iter()
        .filter(|option| option.starts_with(name))
        .collect();
    match matches.as_slice() {
        [one] if name.len() >= 3 => (**one).to_string(),
        _ => name.to_string(),
    }
}

/// One key per option: `-Dname`, the canonical long name, or the short flag. A value that
/// belongs to an option (`-T 4`, `-s=file`, `-sfile`) rides along as the entry's value.
fn maven_entries(config: &str) -> Vec<(String, Value)> {
    let mut tokens = config
        .split(|c: char| c.is_whitespace() || c == '\u{0c}')
        .filter(|token| !token.is_empty());
    let mut entries = Vec::new();
    while let Some(token) = tokens.next() {
        let (key, mut value) = if let Some(long) = token.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(n, v)| (n, Some(v)));
            let canonical = canonical_long(&format!("--{name}"));
            if canonical == "--define" {
                (
                    format!(
                        "-D{}",
                        attached
                            .unwrap_or_default()
                            .split('=')
                            .next()
                            .unwrap_or_default()
                    ),
                    String::new(),
                )
            } else {
                (canonical, attached.unwrap_or_default().to_string())
            }
        } else if let Some(define) = token.strip_prefix("-D") {
            let (name, value) = define.split_once('=').unwrap_or((define, ""));
            (format!("-D{name}"), value.to_string())
        } else if MAVEN_SHORT.contains(&token) || MAVEN_SHORT_WITH_VALUE.contains(&token) {
            (token.to_string(), String::new())
        } else if let Some(flag) = MAVEN_SHORT_WITH_VALUE
            .iter()
            .find(|flag| token.starts_with(**flag))
        {
            (
                (*flag).to_string(),
                token[flag.len()..].trim_start_matches('=').to_string(),
            )
        } else {
            (token.to_string(), String::new())
        };
        let takes_value = MAVEN_LONG_WITH_VALUE.contains(&key.as_str())
            || MAVEN_SHORT_WITH_VALUE.contains(&key.as_str());
        if takes_value && value.is_empty() {
            value = tokens.next().unwrap_or_default().to_string();
        }
        entries.push((key, Value::String(value)));
    }
    entries
}

fn read_entries(path: &Path) -> Result<Option<Vec<(String, String)>>> {
    if std::fs::symlink_metadata(path).is_err() {
        return Ok(None);
    }
    crate::untrusted::read_properties(path).map(Some)
}

/// `gradle.properties` in `dir`, if any: its keys and its `org.gradle.jvmargs` options.
pub(super) fn check_gradle_properties(
    dir: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let path = dir.join("gradle.properties");
    let Some(pairs) = read_entries(&path)? else {
        return Ok(Vec::new());
    };
    let entries: Vec<(String, Value)> = pairs
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    let mut applied = check_flat(&GRADLE_PROPERTIES, &entries, &path, allows)?;
    for (key, value) in &pairs {
        if key == "org.gradle.jvmargs" {
            applied.extend(check_flat(
                &GRADLE_JVM_ARGS,
                &jvm_arg_entries(value),
                &path,
                allows,
            )?);
        }
    }
    Ok(applied)
}

/// `gradle/gradle-daemon-jvm.properties` in `dir`, if any.
pub(super) fn check_gradle_daemon_jvm(
    dir: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let path = dir.join("gradle/gradle-daemon-jvm.properties");
    let Some(pairs) = read_entries(&path)? else {
        return Ok(Vec::new());
    };
    let entries: Vec<(String, Value)> = pairs
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect();
    check_flat(&DAEMON_JVM, &entries, &path, allows)
}

/// `maven.config` and `jvm.config` in a `.mvn` directory.
pub(super) fn check_maven_options(mvn: &Path, allows: &[KeyAllow]) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    for (name, surface, entries) in [
        (
            "maven.config",
            &MAVEN_CONFIG,
            maven_entries as fn(&str) -> Vec<(String, Value)>,
        ),
        ("jvm.config", &MAVEN_JVM_ARGS, jvm_arg_entries),
    ] {
        let path = mvn.join(name);
        if std::fs::symlink_metadata(&path).is_err() {
            continue;
        }
        let text = crate::untrusted::read_text(
            &path,
            crate::untrusted::Format::Script,
            crate::fsutil::MAX_MANIFEST_BYTES,
        )?;
        applied.extend(check_flat(surface, &entries(&text), &path, allows)?);
    }
    Ok(applied)
}

#[cfg(test)]
mod tests;
