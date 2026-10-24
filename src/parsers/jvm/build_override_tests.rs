use super::*;
use crate::parsers::test_utils::*;

fn setup_gradle(content: &str) -> std::path::PathBuf {
    setup_test_dir("jvm-overrides", "build.gradle", content)
}

fn setup_pom(content: &str) -> std::path::PathBuf {
    setup_test_dir("jvm-overrides", "pom.xml", content)
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

#[test]
fn gradle_locking_is_only_strict_when_the_build_turns_it_on() {
    use crate::parsers::jvm::{GradleLocking, gradle_locking};
    for (script, expected) in [
        (
            "dependencies { implementation 'a:b:1' }",
            GradleLocking::Off,
        ),
        (
            "dependencyLocking { lockAllConfigurations() }",
            GradleLocking::Strict,
        ),
        (
            "dependencyLocking { lockAllConfigurations()\n lockMode = LockMode.LENIENT }",
            GradleLocking::Lenient,
        ),
    ] {
        let dir = setup_gradle(script);
        assert_eq!(gradle_locking(&dir.join("build.gradle")).unwrap(), expected);
        cleanup(&dir);
    }
}

#[test]
fn a_parent_settings_script_is_found_without_a_git_checkout() {
    let dir = setup_test_dir(
        "jvm-nogit",
        "settings.gradle",
        "dependencyResolutionManagement { repositories { maven { url 'https://evil.example/maven2' } } }",
    );
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(
        dir.join("app/build.gradle"),
        "dependencies { implementation 'a:b:1' }",
    )
    .unwrap();
    let err = parse_manifest(&dir.join("app/build.gradle")).map(|_| ());
    assert!(err.is_err(), "the parent settings repository must be seen");
    cleanup(&dir);
}

fn write_in(dir: &std::path::Path, path: &str, content: &str) {
    let full = dir.join(path);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, content).unwrap();
}

#[test]
fn maven_build_overrides_under_mvn_block() {
    let pom = "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies></project>";
    for (path, content) in [
        (".mvn/settings.xml", "<settings/>"),
        (".mvn/maven.config", "-B\n-s .mvn/settings.xml\n"),
        (".mvn/maven.config", "--settings=evil.xml\n"),
        (".mvn/jvm.config", "-Xmx1g -javaagent:/tmp/a.jar\n"),
        (
            ".mvn/wrapper/maven-wrapper.properties",
            "distributionUrl=https\\://evil.example/apache-maven-3.9.6-bin.zip\n",
        ),
    ] {
        let dir = setup_pom(pom);
        write_in(&dir, path, content);
        assert!(parse(&dir).is_err(), "{path}: {content}");
        cleanup(&dir);
    }
    let dir = setup_pom(pom);
    write_in(&dir, ".mvn/maven.config", "-B\n-Dfoo=bar\n");
    write_in(
        &dir,
        ".mvn/wrapper/maven-wrapper.properties",
        "distributionUrl=https\\://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip\n",
    );
    assert!(parse(&dir).is_ok());
    cleanup(&dir);
}

#[test]
fn an_untrusted_gradle_wrapper_distribution_blocks() {
    let dir = setup_gradle("dependencies { implementation 'a:b:1' }");
    write_in(
        &dir,
        "gradle/wrapper/gradle-wrapper.properties",
        "distributionUrl=https\\://evil.example/gradle-8.10-bin.zip\n",
    );
    assert!(parse(&dir).is_err());
    write_in(
        &dir,
        "gradle/wrapper/gradle-wrapper.properties",
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.10-bin.zip\n",
    );
    assert!(parse(&dir).is_ok());
    cleanup(&dir);
}

#[test]
fn wrapper_and_maven_config_forms_the_first_checks_missed_still_block() {
    let pom = "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies></project>";
    for (path, content) in [
        (
            ".mvn/maven.config",
            "-sother-settings.xml\n".as_bytes().to_vec(),
        ),
        (".mvn/maven.config", b"--sett=evil.xml\n".to_vec()),
        (".mvn/maven.config", b"-Dmaven.repo.local=/tmp/r\n".to_vec()),
        (".mvn/maven.config", b"-B\r-s evil.xml\n".to_vec()),
        (
            ".mvn/wrapper/maven-wrapper.properties",
            b"# \xe9\ndistributionUrl:https\\://evil.example/m.zip\n".to_vec(),
        ),
    ] {
        let dir = setup_pom(pom);
        write_in(&dir, path, &String::from_utf8_lossy(&content));
        std::fs::write(dir.join(path), &content).unwrap();
        assert!(parse(&dir).is_err(), "{path}: {content:?}");
        cleanup(&dir);
    }
    let dir = setup_gradle("dependencies { implementation 'a:b:1' }");
    for content in [
        b"distributionUrl:https\\://evil.example/g.zip\n".to_vec(),
        b"# \xe9\ndistributionUrl=https\\://evil.example/g.zip\n".to_vec(),
        b"distributionUrl   https\\://evil.example/g.zip\n".to_vec(),
        b"# c\rdistributionUrl=https\\://evil.example/g.zip\n".to_vec(),
    ] {
        write_in(&dir, "gradle/wrapper/gradle-wrapper.properties", "");
        std::fs::write(
            dir.join("gradle/wrapper/gradle-wrapper.properties"),
            &content,
        )
        .unwrap();
        assert!(parse(&dir).is_err(), "{content:?}");
    }
    cleanup(&dir);
}

#[test]
fn gradle_properties_that_load_agents_block() {
    let dir = setup_gradle("dependencies { implementation 'a:b:1' }");
    write_in(
        &dir,
        "gradle.properties",
        "org.gradle.jvmargs=-Xmx2g -javaagent:/tmp/a.jar\n",
    );
    assert!(parse(&dir).is_err());
    write_in(
        &dir,
        "gradle.properties",
        "org.gradle.jvmargs=-Xmx2g\norg.gradle.parallel=true\n",
    );
    assert!(parse(&dir).is_ok());
    cleanup(&dir);
}
