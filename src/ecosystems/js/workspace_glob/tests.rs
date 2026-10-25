use super::*;

fn globs(patterns: &[&str], negation: Negation) -> WorkspaceGlobs {
    let patterns = patterns.iter().map(|p| p.to_string()).collect::<Vec<_>>();
    WorkspaceGlobs::compile(&patterns, negation).unwrap()
}

fn member(globs: &WorkspaceGlobs, path: &str) -> bool {
    globs.matches(Path::new("/w"), &Path::new("/w").join(path))
}

#[test]
fn stars_globstars_and_single_characters() {
    let g = globs(&["packages/*", "apps/**", "tools/?"], Negation::Ordered);
    assert!(member(&g, "packages/a"));
    assert!(!member(&g, "packages/a/b"));
    assert!(member(&g, "apps"));
    assert!(member(&g, "apps/x/y"));
    assert!(member(&g, "tools/x"));
    assert!(!member(&g, "tools/xy"));
    assert!(!member(&g, ""), "the root is never its own member");
    let g = globs(&["./pkg-*-js/", "**/svc"], Negation::Ordered);
    assert!(member(&g, "pkg-a-js"));
    assert!(member(&g, "pkg--js"));
    assert!(!member(&g, "pkg-a-ts"));
    assert!(member(&g, "deep/er/svc"));
    assert!(member(&g, "svc"));
}

#[test]
fn character_classes() {
    let g = globs(
        &["p/[a-c]", "q/[!x]", "r/[^x]", "s/[]x]"],
        Negation::Ordered,
    );
    assert!(member(&g, "p/b"));
    assert!(!member(&g, "p/d"));
    assert!(member(&g, "q/y"));
    assert!(!member(&g, "q/x"));
    assert!(member(&g, "r/y"));
    assert!(member(&g, "s/]"));
    assert!(member(&g, "s/x"));
}

#[test]
fn brace_alternatives_nesting_and_ranges() {
    let g = globs(
        &[
            "packages/{a,b}",
            "{apps,services/{x,y}}/*",
            "n/{1..3}",
            "z/{01..10..3}",
            "l/{c..a}",
            "e/{,pre-}core",
        ],
        Negation::Ordered,
    );
    for yes in [
        "packages/a",
        "packages/b",
        "apps/web",
        "services/x/one",
        "services/y/two",
        "n/1",
        "n/3",
        "z/01",
        "z/04",
        "z/10",
        "l/b",
        "e/core",
        "e/pre-core",
    ] {
        assert!(member(&g, yes), "{yes}");
    }
    for no in ["packages/c", "services/z/one", "n/4", "z/02", "l/d"] {
        assert!(!member(&g, no), "{no}");
    }
}

#[test]
fn positive_patterns_ignore_case_and_negated_ones_do_not() {
    let g = globs(&["Packages/A", "q/[!b]"], Negation::Ordered);
    assert!(member(&g, "packages/a"));
    assert!(
        member(&g, "q/B"),
        "npm on a case-sensitive system matches B"
    );
    let g = globs(&["packages/*", "!Packages/A"], Negation::Global);
    assert!(member(&g, "packages/a"), "only an exact negation excludes");
    assert!(!member(&g, "Packages/A"));
}

#[test]
fn ordered_negation_lets_a_later_pattern_add_a_member_back() {
    let g = globs(&["packages/*", "!packages/b"], Negation::Ordered);
    assert!(member(&g, "packages/a"));
    assert!(!member(&g, "packages/b"));
    let g = globs(&["!packages/b", "packages/*"], Negation::Ordered);
    assert!(member(&g, "packages/b"));
    let g = globs(
        &["packages/*", "!packages/*", "packages/b"],
        Negation::Ordered,
    );
    assert!(!member(&g, "packages/a"));
    assert!(member(&g, "packages/b"));
}

#[test]
fn global_negation_excludes_whatever_the_order() {
    let g = globs(&["!packages/b", "packages/*"], Negation::Global);
    assert!(member(&g, "packages/a"));
    assert!(!member(&g, "packages/b"));
    let g = globs(&["packages/**", "!**/test/**"], Negation::Global);
    assert!(member(&g, "packages/a"));
    assert!(!member(&g, "packages/test"));
    assert!(!member(&g, "packages/a/test/fixture"));
}

#[test]
fn unmodeled_syntax_is_an_error_naming_the_pattern() {
    for pattern in [
        "packages/@(a|b)",
        "packages/+(a)",
        "packages/!(a)",
        "packages/(a|b)",
        "packages/\\*",
        "packages/[[:alpha:]]",
        "packages/{a",
        "packages/a}",
        "packages/{a}",
        "packages/{1..x}",
        "packages/[a",
        "packages/[z-a]",
        "../outside/*",
        "/abs/*",
        "!!packages/a",
        "!",
        "{0..5000}",
        "{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}",
    ] {
        let err = WorkspaceGlobs::compile(&[pattern.to_string()], Negation::Ordered)
            .expect_err(pattern)
            .to_string();
        assert!(err.contains("Unsupported workspace pattern"), "{err}");
    }
}

#[test]
fn many_globstars_stay_cheap() {
    let pattern = "**/".repeat(200) + "x";
    let g = globs(&[pattern.as_str()], Negation::Ordered);
    let deep = (0..15).map(|_| "d").collect::<Vec<_>>().join("/") + "/y";
    assert!(!member(&g, &deep));
    let stars = "*a".repeat(100);
    let g = globs(&[stars.as_str()], Negation::Ordered);
    assert!(!member(&g, &"a".repeat(99)));
}
