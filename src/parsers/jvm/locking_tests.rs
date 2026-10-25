use super::*;
use crate::parsers::test_utils::*;

fn locking_of(script: &str) -> Result<GradleLocking> {
    let dir = setup_test_dir("jvm-locking", "build.gradle", script);
    let result = gradle_locking(&dir.join("build.gradle"));
    cleanup(&dir);
    result
}

#[test]
fn settings_that_weaken_or_redirect_locking_are_rejected() {
    for script in [
        "dependencyLocking { lockAllConfigurations()\n unlockAllConfigurations() }",
        "dependencyLocking { lockAllConfigurations()\n lockFile = file(\"$projectDir/locks/real.lockfile\") }",
        "dependencyLocking { lockAllConfigurations()\n lockFile.set(file('x.lockfile')) }",
        "dependencyLocking { lockAllConfigurations()\n ignoredDependencies.add('com.evil:*') }",
        "dependencyLocking { lockAllConfigurations()\n lockMode = someMode }",
        "dependencyLocking { lockAllConfigurations() }\nconfigurations.compileClasspath { deactivateDependencyLocking() }",
        "dependencyLocking { lockAllConfigurations() }\ndependencyLocking.unlockAllConfigurations()",
        "dependencyLocking.lockAllConfigurations()",
        "project(':a') { dependencyLocking { lockAllConfigurations() } }",
    ] {
        let err = locking_of(script).expect_err(script).to_string();
        assert!(
            err.contains("Unsupported Gradle dependency locking"),
            "{script}: {err}"
        );
    }
}

#[test]
fn locking_words_in_comments_and_strings_change_nothing() {
    for script in [
        "/* dependencyLocking { lockAllConfigurations() } */\ndependencies { implementation 'a:b:1' }",
        "// lockAllConfigurations()\ndependencies { implementation 'a:b:1' }",
        "def note = 'lockAllConfigurations()'\n",
    ] {
        assert_eq!(locking_of(script).unwrap(), GradleLocking::Off, "{script}");
    }
}

#[test]
fn understood_forms_still_parse() {
    for (script, expected) in [
        (
            "import org.gradle.api.artifacts.dsl.LockMode\ndependencyLocking {\n lockAllConfigurations()\n lockMode.set(LockMode.STRICT)\n}",
            GradleLocking::Strict,
        ),
        (
            "allprojects { dependencyLocking { lockAllConfigurations() } }",
            GradleLocking::Strict,
        ),
        (
            "subprojects { dependencyLocking { lockAllConfigurations() } }",
            GradleLocking::Off,
        ),
        (
            "buildscript { dependencyLocking { lockAllConfigurations() } }",
            GradleLocking::Off,
        ),
        (
            "dependencyLocking { lockAllConfigurations(); lockMode = org.gradle.api.artifacts.dsl.LockMode.LENIENT }",
            GradleLocking::Lenient,
        ),
    ] {
        assert_eq!(locking_of(script).unwrap(), expected, "{script}");
    }
}

#[test]
fn a_parent_build_locks_subprojects_only_through_allprojects_or_subprojects() {
    for (parent, expected) in [
        (
            "subprojects { dependencyLocking { lockAllConfigurations() } }",
            GradleLocking::Strict,
        ),
        (
            "allprojects { dependencyLocking { lockAllConfigurations() } }",
            GradleLocking::Strict,
        ),
        // The root project's own block does not configure its subprojects.
        (
            "dependencyLocking { lockAllConfigurations() }",
            GradleLocking::Off,
        ),
    ] {
        let dir = setup_test_dir("jvm-locking-parent", "build.gradle", parent);
        std::fs::create_dir_all(dir.join("app")).unwrap();
        std::fs::write(
            dir.join("app/build.gradle"),
            "dependencies { implementation 'a:b:1' }",
        )
        .unwrap();
        assert_eq!(
            gradle_locking(&dir.join("app/build.gradle")).unwrap(),
            expected,
            "{parent}"
        );
        cleanup(&dir);
    }
}

#[test]
fn a_parent_build_that_unlocks_subprojects_is_rejected() {
    let dir = setup_test_dir(
        "jvm-locking-parent-unlock",
        "build.gradle",
        "subprojects { dependencyLocking { unlockAllConfigurations() } }",
    );
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(
        dir.join("app/build.gradle"),
        "dependencyLocking { lockAllConfigurations() }",
    )
    .unwrap();
    assert!(gradle_locking(&dir.join("app/build.gradle")).is_err());
    cleanup(&dir);
}
