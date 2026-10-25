use super::*;
use crate::parsers::test_utils::*;

/// A root build (`settings.gradle` including `app`) with `root_build` as the
/// root build script and a plain `app/build.gradle`.
fn multi_project(root_build: &str, with_settings: bool) -> PathBuf {
    let dir = setup_test_dir("jvm-parent-build", "build.gradle", root_build);
    if with_settings {
        std::fs::write(
            dir.join("settings.gradle"),
            "rootProject.name = 'root'\ninclude 'app'\n",
        )
        .unwrap();
    }
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(
        dir.join("app/build.gradle"),
        "dependencies { implementation 'org.slf4j:slf4j-api:2.0.13' }",
    )
    .unwrap();
    dir
}

fn names(deps: &[Dependency]) -> Vec<&str> {
    deps.iter().map(|dep| dep.name.as_str()).collect()
}

#[test]
fn parent_repositories_for_subprojects_are_verified() {
    for root in [
        "subprojects { repositories { maven { url 'https://evil.example.com/m2' } } }",
        "allprojects { repositories { maven { url 'https://evil.example.com/m2' } } }",
    ] {
        let dir = multi_project(root, true);
        let err = parse_gradle_build(&dir.join("app/build.gradle"))
            .map(|_| ())
            .expect_err(root)
            .to_string();
        assert!(
            err.contains("Unsupported Gradle repository"),
            "{root}: {err}"
        );
        cleanup(&dir);
    }
}

#[test]
fn parent_dependencies_for_subprojects_are_scanned() {
    for root in [
        "subprojects { dependencies { implementation 'com.evil:payload:1.0.0' } }",
        "allprojects { dependencies { implementation 'com.evil:payload:1.0.0' } }",
    ] {
        let dir = multi_project(root, true);
        let build = parse_gradle_build(&dir.join("app/build.gradle")).unwrap();
        assert_eq!(
            names(&build.deps),
            ["org.slf4j:slf4j-api", "com.evil:payload"],
            "{root}"
        );
        cleanup(&dir);
    }
}

#[test]
fn the_root_projects_own_dependencies_stay_with_it() {
    let dir = multi_project(
        "dependencies { implementation 'com.root:only:1.0.0' }",
        true,
    );
    let build = parse_gradle_build(&dir.join("app/build.gradle")).unwrap();
    assert_eq!(names(&build.deps), ["org.slf4j:slf4j-api"]);
    cleanup(&dir);
}

#[test]
fn dependencies_aimed_at_a_named_project_are_rejected() {
    for root in [
        "project(':app') { dependencies { implementation 'com.evil:payload:1.0.0' } }",
        "configure(subprojects) { dependencies { implementation 'com.evil:payload:1.0.0' } }",
    ] {
        let dir = multi_project(root, true);
        let err = parse_gradle_build(&dir.join("app/build.gradle"))
            .map(|_| ())
            .expect_err(root)
            .to_string();
        assert!(err.contains("cross-project dependency"), "{root}: {err}");
        cleanup(&dir);
    }
}

#[test]
fn parent_buildscript_classpath_runs_in_the_subproject_build() {
    let dir = multi_project(
        "buildscript { repositories { mavenCentral() }\n dependencies { classpath 'com.tool:plugin:1.0.0' } }",
        true,
    );
    let build = parse_gradle_build(&dir.join("app/build.gradle")).unwrap();
    assert_eq!(names(&build.classpath), ["com.tool:plugin"]);
    cleanup(&dir);
}

#[test]
fn without_an_enclosing_settings_script_the_project_is_its_own_build() {
    let dir = multi_project(
        "subprojects { dependencies { implementation 'com.evil:payload:1.0.0' } }",
        false,
    );
    let build = parse_gradle_build(&dir.join("app/build.gradle")).unwrap();
    assert_eq!(names(&build.deps), ["org.slf4j:slf4j-api"]);
    cleanup(&dir);
}
