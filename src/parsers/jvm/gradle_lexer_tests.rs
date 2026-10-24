use super::*;

fn scan(content: &str) -> Result<gradle_plugins::GradleScript> {
    scan_gradle_script(content, Path::new("build.gradle"))
}

const EVIL: &str = "repositories { maven { url = uri('https://127.0.0.1:9/evil-repo') } }";

#[test]
fn a_lone_cr_ends_a_line_comment_like_groovy_does() {
    let err = scan(&format!(
        "// mirror\r{EVIL}\nrepositories {{ mavenCentral() }}\n"
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("Unsupported Gradle repository"),
        "{err}"
    );
}

#[test]
fn an_apostrophe_inside_a_triple_quoted_string_does_not_hide_later_repositories() {
    for text in [
        "def note = '''don't'''",
        "def note = \"\"\"say \"hi\" don't\"\"\"",
    ] {
        let err = scan(&format!("{text}\n{EVIL}\n")).unwrap_err();
        assert!(
            err.to_string().contains("Unsupported Gradle repository"),
            "{text}: {err}"
        );
    }
}

#[test]
fn quotes_inside_interpolation_and_slashy_strings_do_not_desync_the_lexer() {
    for text in [
        "def a = \"${ \"x\" + 'y' }\"",
        "def a = \"x ${ \"}\" } y\"",
        "def a = /it's \\/ here/",
        "def a = $/it's \" here/$",
        "def b = 4 / 2; def a = 6 / 3",
    ] {
        let err = scan(&format!("{text}\n{EVIL}\n")).unwrap_err();
        assert!(
            err.to_string().contains("Unsupported Gradle repository"),
            "{text}: {err}"
        );
    }
}

#[test]
fn getter_forms_of_the_guarded_models_are_rejected() {
    for text in [
        "getRepositories().maven { url = uri('https://127.0.0.1:9/e') }",
        "project.getRepositories().maven { }",
        "getDependencies().add('implementation', 'a:b:1')",
        "getBuildscript().getRepositories()",
        "getPluginManagement()",
    ] {
        assert!(scan(text).is_err(), "{text}");
    }
}

#[test]
fn ordinary_scripts_still_scan() {
    let script = "def x = '''multi\nline'''\nrepositories { mavenCentral() }\ndependencies { implementation 'a:b:1' }\n// a/b\nint half = 8 / 2\n";
    assert!(scan(script).is_ok());
}
