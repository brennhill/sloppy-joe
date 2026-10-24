use super::*;
use crate::parsers::test_utils::*;

const GRADLE_BUILD: &str =
    "repositories { mavenCentral() }\ndependencies { implementation 'a:b:1' }\n";
const POM: &str = "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies></project>";

fn gradle_with(file: &str, content: &str) -> std::path::PathBuf {
    let dir = setup_test_dir("jvm-redirect", "build.gradle", GRADLE_BUILD);
    let path = dir.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
    dir
}

fn maven_with(file: &str, content: &str) -> std::path::PathBuf {
    let dir = setup_test_dir("jvm-redirect", "pom.xml", POM);
    let path = dir.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
    dir
}

#[test]
fn gradle_properties_that_redirect_fetching_or_trust_block() {
    for content in [
        "systemProp.org.gradle.internal.plugins.portal.url.override=https://plugins.example.invalid/m2\n",
        "systemProp.javax.net.ssl.trustStore=certs/store.jks\n",
        "systemProp.https.proxyHost=proxy.example.invalid\n",
        "systemProp.http.proxyPort=8080\n",
        "systemProp.http.nonProxyHosts=*\n",
        "org.gradle.jvmargs=-Xmx1g -Djavax.net.ssl.trustStore=certs/store.jks\n",
        "org.gradle.jvmargs=-Duser.home=.\n",
    ] {
        let dir = gradle_with("gradle.properties", content);
        let err = parse_manifest(&dir.join("build.gradle"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Unsupported Gradle property"),
            "{content}: {err}"
        );
        cleanup(&dir);
    }
    let dir = gradle_with(
        "gradle.properties",
        "org.gradle.jvmargs=-Xmx2g -Dfile.encoding=UTF-8\nsystemProp.file.encoding=UTF-8\n",
    );
    assert!(parse_manifest(&dir.join("build.gradle")).is_ok());
    cleanup(&dir);
}

#[test]
fn a_gradle_daemon_jvm_download_url_blocks() {
    let dir = gradle_with(
        "gradle/gradle-daemon-jvm.properties",
        "toolchainVersion=21\ntoolchainUrl.MAC_OS.AARCH64=https\\://jdk.example.invalid/jdk.tgz\n",
    );
    let err = parse_manifest(&dir.join("build.gradle"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("toolchainUrl"), "{err}");
    cleanup(&dir);
    let dir = gradle_with(
        "gradle/gradle-daemon-jvm.properties",
        "toolchainVersion=21\n",
    );
    assert!(parse_manifest(&dir.join("build.gradle")).is_ok());
    cleanup(&dir);
}

#[test]
fn a_gradle_build_cache_block_is_unsupported() {
    for script in [
        "buildCache { local { directory = file('build-cache') } }\n",
        "buildCache { remote(HttpBuildCache) { url = 'https://cache.example.invalid/' } }\n",
        "getBuildCache().local { directory = file('c') }\n",
    ] {
        let dir = gradle_with("settings.gradle", script);
        let err = parse_manifest(&dir.join("build.gradle"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("build cache") || err.contains("getBuildCache"),
            "{script}: {err}"
        );
        cleanup(&dir);
    }
}

#[test]
fn maven_config_and_jvm_config_redirects_block() {
    for (file, content) in [
        (".mvn/jvm.config", "-Dmaven.repo.local=.m2repo\n"),
        (".mvn/jvm.config", "-Duser.home=.\n"),
        (
            ".mvn/jvm.config",
            "-Djavax.net.ssl.trustStore=certs/store.jks\n",
        ),
        (
            ".mvn/jvm.config",
            "-Dhttps.proxyHost=proxy.example.invalid\n",
        ),
        (
            ".mvn/maven.config",
            "-Djavax.net.ssl.trustStore=certs/store.jks\n",
        ),
        (
            ".mvn/maven.config",
            "-Daether.connector.https.securityMode=insecure\n",
        ),
        (
            ".mvn/maven.config",
            "-Dmaven.repo.central=https://repo.example.invalid/m2\n",
        ),
        (
            ".mvn/maven.config",
            "-Dorg.apache.maven.user-settings=conf/settings.xml\n",
        ),
        (".mvn/maven.config", "-Djava.home=tools/jdk\n"),
        (".mvn/maven.config", "-Dmaven.build.cache.enabled=true\n"),
    ] {
        let dir = maven_with(file, content);
        assert!(
            parse_manifest(&dir.join("pom.xml")).is_err(),
            "{file}: {content}"
        );
        cleanup(&dir);
    }
    let dir = maven_with(
        ".mvn/maven.config",
        "-Dmaven.test.skip=true\n--batch-mode\n",
    );
    assert!(parse_manifest(&dir.join("pom.xml")).is_ok());
    cleanup(&dir);
}

#[test]
fn a_maven_build_cache_config_blocks() {
    let dir = maven_with(
        ".mvn/maven-build-cache-config.xml",
        "<cache><remote enabled=\"true\"><url>https://cache.example.invalid/</url></remote></cache>",
    );
    let err = parse_manifest(&dir.join("pom.xml"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("build cache"), "{err}");
    cleanup(&dir);
}
