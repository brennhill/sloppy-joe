use super::*;
use crate::config_surface::KNOWN_SURFACES;

fn dir_with(files: &[(&str, &str)]) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-jvm-surface-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    for (name, content) in files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    dir
}

fn allow(file: &str, key: &str) -> KeyAllow {
    KeyAllow {
        file: file.into(),
        key: key.into(),
    }
}

#[test]
fn every_surface_id_is_known() {
    for surface in [
        &GRADLE_PROPERTIES,
        &GRADLE_JVM_ARGS,
        &DAEMON_JVM,
        &MAVEN_JVM_ARGS,
        &MAVEN_CONFIG,
    ] {
        assert!(KNOWN_SURFACES.contains(&surface.id), "{}", surface.id);
    }
}

#[test]
fn ordinary_gradle_properties_pass() {
    let dir = dir_with(&[(
        "gradle.properties",
        "org.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=512m -Dfile.encoding=UTF-8 -XX:+UseParallelGC\n\
         org.gradle.parallel=true\norg.gradle.caching=false\nandroid.useAndroidX=true\nversion=1.0\n\
         systemProp.file.encoding=UTF-8\norg.gradle.dependency.verification=strict\n",
    )]);
    assert!(check_gradle_properties(&dir, &[]).unwrap().is_empty());
}

#[test]
fn redirecting_gradle_properties_block_even_when_allowed() {
    for (line, key) in [
        ("org.gradle.java.home=/opt/evil", "org.gradle.java.home"),
        ("org.gradle.cache.dir=cache", "org.gradle.cache.dir"),
        (
            "systemProp.javax.net.ssl.trustStore=certs/store.jks",
            "systemProp.javax.net.ssl.trustStore",
        ),
        (
            "systemProp.https.proxyHost=proxy.invalid",
            "systemProp.https.proxyHost",
        ),
        (
            "systemProp.org.gradle.internal.plugins.portal.url.override=https://p.invalid/m2",
            "systemProp.org.gradle.internal.plugins.portal.url.override",
        ),
        (
            "org.gradle.dependency.verification=off",
            "org.gradle.dependency.verification",
        ),
        (
            "org.gradle.java.installations.auto-download=true",
            "org.gradle.java.installations.auto-download",
        ),
    ] {
        let dir = dir_with(&[("gradle.properties", &format!("{line}\n"))]);
        assert!(check_gradle_properties(&dir, &[]).is_err(), "{line}");
        assert!(
            check_gradle_properties(&dir, &[allow("gradle.properties", key)]).is_err(),
            "allowed: {line}"
        );
    }
}

#[test]
fn unknown_gradle_properties_block_until_the_exact_key_is_allowed() {
    let dir = dir_with(&[("gradle.properties", "org.gradle.configuration-cache=true\n")]);
    let err = check_gradle_properties(&dir, &[]).unwrap_err().to_string();
    assert!(err.contains("org.gradle.configuration-cache"), "{err}");
    let applied = check_gradle_properties(
        &dir,
        &[allow("gradle.properties", "org.gradle.configuration-cache")],
    )
    .unwrap();
    assert_eq!(applied.len(), 1);
}

#[test]
fn gradle_jvmargs_are_judged_option_by_option() {
    for args in [
        "-javaagent:agent.jar",
        "-Xbootclasspath/p:evil.jar",
        "-Djavax.net.ssl.trustStore=a.jks",
        "-Xmx1g -Dhttps.proxyHost=p.invalid",
        "-XX:OnOutOfMemoryError=cmd",
        "@argfile",
        "-cp evil.jar",
    ] {
        let dir = dir_with(&[("gradle.properties", &format!("org.gradle.jvmargs={args}\n"))]);
        assert!(check_gradle_properties(&dir, &[]).is_err(), "{args}");
    }
    let dir = dir_with(&[(
        "gradle.properties",
        "org.gradle.jvmargs=-Xmx1g -XX:+UseLargePages\n",
    )]);
    assert!(
        check_gradle_properties(&dir, &[]).is_err(),
        "unlisted GC option"
    );
    let applied =
        check_gradle_properties(&dir, &[allow("gradle.properties", "-XX:+UseLargePages")]);
    assert!(applied.is_ok());
}

#[test]
fn daemon_jvm_download_urls_block_and_versions_pass() {
    let ok = dir_with(&[(
        "gradle/gradle-daemon-jvm.properties",
        "toolchainVersion=21\ntoolchainVendor=ADOPTIUM\n",
    )]);
    assert!(check_gradle_daemon_jvm(&ok, &[]).unwrap().is_empty());
    let bad = dir_with(&[(
        "gradle/gradle-daemon-jvm.properties",
        "toolchainVersion=21\ntoolchainUrl.MAC_OS.AARCH64=https\\://jdk.invalid/jdk.tgz\n",
    )]);
    assert!(
        check_gradle_daemon_jvm(
            &bad,
            &[allow(
                "gradle-daemon-jvm.properties",
                "toolchainUrl.MAC_OS.AARCH64"
            )]
        )
        .is_err()
    );
    let other = dir_with(&[("gradle/gradle-daemon-jvm.properties", "somethingNew=1\n")]);
    assert!(check_gradle_daemon_jvm(&other, &[]).is_err());
}

fn maven(config: &str) -> anyhow::Result<usize> {
    let dir = dir_with(&[(".mvn/maven.config", config)]);
    check_maven_options(&dir.join(".mvn"), &[]).map(|applied| applied.len())
}

#[test]
fn ordinary_maven_options_pass() {
    assert!(
        maven("-B -T 1C -Pdev -pl a,b -DskipTests -Drevision=1.2.3 --no-transfer-progress -ntp\n")
            .is_ok()
    );
    assert!(maven("--batch-mode\n--threads=4\n-fae\n").is_ok());
}

#[test]
fn settings_toolchains_file_and_property_redirects_block() {
    for config in [
        "-s settings.xml",
        "-ssettings.xml",
        "-gs=g.xml",
        "--settings=s.xml",
        "--sett s.xml",
        "--global-toolchains t.xml",
        "-t toolchains.xml",
        "-f other/pom.xml",
        "-fother.xml",
        "-c",
        "--lax-checksums",
        "-Dmaven.repo.local=.m2",
        "-Djavax.net.ssl.trustStore=a.jks",
        "-Daether.connector.https.securityMode=insecure",
        "-Dmaven.repo.central=https://r.invalid",
        "-Dorg.apache.maven.user-settings=s.xml",
        "--define=maven.repo.local=x",
    ] {
        let dir = dir_with(&[(".mvn/maven.config", config)]);
        assert!(
            check_maven_options(&dir.join(".mvn"), &[]).is_err(),
            "{config}"
        );
        let key = config.split_whitespace().next().unwrap();
        assert!(
            check_maven_options(&dir.join(".mvn"), &[allow("maven.config", key)]).is_err(),
            "allowed: {config}"
        );
    }
}

#[test]
fn unknown_maven_options_block_until_allowed() {
    let dir = dir_with(&[(".mvn/maven.config", "-emp\n")]);
    assert!(check_maven_options(&dir.join(".mvn"), &[]).is_err());
    let applied = check_maven_options(&dir.join(".mvn"), &[allow("maven.config", "-emp")]).unwrap();
    assert_eq!(applied.len(), 1);
}

#[test]
fn maven_jvm_config_blocks_agents_and_redirects() {
    for args in [
        "-javaagent:a.jar",
        "-Dmaven.repo.local=.m2repo",
        "-Duser.home=.",
        "-Djavax.net.ssl.trustStore=certs/store.jks",
        "-Djava.system.class.loader=x.Loader",
        "-Dmaven.ext.class.path=ext.jar",
        "-Xbootclasspath/a:x.jar",
    ] {
        let dir = dir_with(&[(".mvn/jvm.config", args)]);
        assert!(
            check_maven_options(&dir.join(".mvn"), &[]).is_err(),
            "{args}"
        );
    }
    let ok = dir_with(&[(".mvn/jvm.config", "-Xmx1g -Dfile.encoding=UTF-8\n")]);
    assert!(
        check_maven_options(&ok.join(".mvn"), &[])
            .unwrap()
            .is_empty()
    );
}
