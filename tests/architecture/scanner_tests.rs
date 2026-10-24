//! The scanner measures what it claims.

use super::*;

#[test]
fn scanner_ignores_comments_and_literals() {
    let code = strip("fn a() { // if if if\n let s = \"if && ||\"; let c = '{'; /* for */ }");
    let f = function_complexities(&code);
    assert_eq!(f, vec![("a".to_string(), 1)]);
}

#[test]
fn scanner_counts_branches_boolean_operators_and_match_arms() {
    let code = strip(
        "fn a(x: i32) -> i32 { if x > 0 && x < 9 || x == 20 { 1 } else if x < 0 { 2 } else { \
         match x { 1 => 1, 2 => 2, _ => 3 } } }",
    );
    // 1 + if + && + || + else-if + (3 arms - 1)
    assert_eq!(function_complexities(&code), vec![("a".to_string(), 7)]);
}

#[test]
fn scanner_does_not_count_closures_or_reference_types_as_operators() {
    let code = strip("fn a(v: &&str) { let f = || 1; let g = move || 2; let h = |&&x| x; }");
    assert_eq!(function_complexities(&code), vec![("a".to_string(), 1)]);
}

#[test]
fn scanner_finds_crate_targets_in_paths_and_groups() {
    let targets = crate_targets(
        "use crate::registry::Registry; use crate::{checks::x, cache}; crate::Dependency",
    );
    assert_eq!(targets, vec!["registry", "checks", "cache", "Dependency"]);
}

#[test]
fn cfg_test_items_are_cut_and_production_code_around_them_is_kept() {
    let code = cut_inline_tests("fn a() {}\n#[cfg(test)]\nmod tests { fn b() {} }");
    assert!(code.contains("fn a") && !code.contains("fn b"));
    let kept = cut_inline_tests("#[cfg(test)]\n#[path = \"x\"]\nmod x;\nfn c() {}");
    assert!(kept.contains("fn c") && !kept.contains("mod x"));
    let after = cut_inline_tests(
        "fn a() {}\n#[cfg(test)]\npub(crate) mod t { fn b() { if x { } } }\nfn c() {}",
    );
    assert!(after.contains("fn a") && after.contains("fn c") && !after.contains("fn b"));
    // Functions, `use`, and constants with `;` inside brackets end where the item ends.
    let items = cut_inline_tests(
        "#[cfg(test)]\nuse a::{b, c};\nfn keep1() {}\n#[cfg(test)]\npub(crate) fn t(x: [u8; 4]) -> u8 { 1 }\nfn keep2() {}\n#[cfg(test)]\nconst N: [u8; 2] = [0; 2];\nfn keep3() {}",
    );
    assert!(
        ["keep1", "keep2", "keep3"]
            .iter()
            .all(|f| items.contains(f))
            && !items.contains("fn t")
            && !items.contains("const N"),
        "{items}"
    );
    // `cfg(not(test))` is production code.
    assert!(cut_inline_tests("#[cfg(not(test))]\nfn p() {}").contains("fn p"));
}

#[test]
fn cfg_test_fields_and_variants_do_not_blind_the_scan_of_what_follows() {
    for code in [
        "struct P { a: u8, #[cfg(test)] b: u8 }\nfn after() {}",
        "struct P { a: u8, #[cfg(test)] b: u8, c: u8 }\nfn after() {}",
        "enum E { A, #[cfg(test)] B }\nfn after() {}",
        "enum E { A, #[cfg(test)] B(u8) }\nfn after() {}",
        "struct P { #[cfg(test)] b: std::collections::HashMap<String, u8> }\nfn after() {}",
        "fn f() { #[cfg(test)] let x = 1; y(); }\nfn after() {}",
        "fn f() { match v { #[cfg(test)] A => 1, B => 2 } }\nfn after() {}",
    ] {
        let cut = cut_inline_tests(code);
        assert!(cut.contains("fn after"), "{code} -> {cut}");
    }
    let cut = cut_inline_tests("struct P { a: u8, #[cfg(test)] b: u8, c: u8 }");
    assert!(
        cut.contains("a: u8") && cut.contains("c: u8") && !cut.contains("b: u8"),
        "{cut}"
    );
}
