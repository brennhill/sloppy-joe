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

fn src(rel: &str, code: &str) -> (String, String) {
    (rel.to_string(), code.to_string())
}

#[test]
fn test_status_comes_from_the_cfg_test_declaration_not_the_file_name() {
    let tests = test_files::test_only_files(&[
        src(
            "src/engine/mod.rs",
            "#[cfg(test)]\nmod real_tests;\nmod leak_tests;\n// #[cfg(test)]\n// mod fake_tests;\nmod fake_tests;\n",
        ),
        src("src/engine/real_tests.rs", "mod nested;\n"),
        src("src/engine/real_tests/nested.rs", ""),
        src(
            "src/ecosystems/mod.rs",
            "#[cfg(test)]\n#[path = \"tests/registry.rs\"]\nmod registry;\n#[cfg(test)]\npub(crate) mod helpers;\n",
        ),
    ]);
    assert!(tests.contains("src/engine/real_tests.rs"));
    assert!(
        tests.contains("src/engine/real_tests/nested.rs"),
        "children of test files are test files"
    );
    assert!(tests.contains("src/ecosystems/tests/registry.rs"));
    assert!(tests.contains("src/ecosystems/helpers.rs"));
    assert!(
        !tests.contains("src/engine/leak_tests.rs"),
        "a plain `mod` is production"
    );
    assert!(
        !tests.contains("src/engine/fake_tests.rs"),
        "comments declare nothing"
    );
}

#[test]
fn the_real_tree_test_files_are_found_and_production_files_are_not() {
    let files = load_sources();
    let is_test = |rel: &str| files.iter().find(|f| f.rel == rel).map(|f| f.is_test);
    assert_eq!(is_test("src/parsers/tests.rs"), Some(true));
    assert_eq!(is_test("src/ecosystems/tests/registry.rs"), Some(true));
    assert_eq!(is_test("src/engine/scan.rs"), Some(false));
    assert_eq!(is_test("src/ecosystems/php/provenance.rs"), Some(false));
    assert!(files.iter().filter(|f| f.is_test).count() > 20);
}

#[test]
fn root_reexports_count_as_uses_of_the_module_that_defines_them() {
    let files = load_sources();
    let exports = roots::root_export_modules(&files);
    assert_eq!(
        exports.get("walk_project_tree"),
        None,
        "the walk lives below the engine now"
    );
    assert_eq!(
        exports.get("scan_one_project").map(String::as_str),
        Some("engine")
    );
    assert_eq!(
        exports.get("selected_lockfile_path").map(String::as_str),
        Some("ecosystems")
    );
    // A call through the crate root, a bare call via a glob import, and `super::engine` from a
    // module root all reach the engine.
    let modules: Vec<String> = files.iter().map(|f| f.module.clone()).collect();
    assert!(crate_targets("crate::scan_one_project(x)").contains(&"scan_one_project".to_string()));
    assert_eq!(
        roots::bare_root_uses("fn f() { scan_one_project(x); }", &exports),
        vec!["engine".to_string()]
    );
    assert!(roots::bare_root_uses("fn scan_one_project() {}", &exports).is_empty());
    assert!(roots::bare_root_uses("fn f() { x.scan_one_project(); }", &exports).is_empty());
    assert_eq!(
        roots::super_root_targets("src/parsers/mod.rs", "super::engine::f()", &modules),
        vec!["engine".to_string()]
    );
    assert!(
        roots::super_root_targets("src/parsers/jvm/pom.rs", "super::engine::f()", &modules)
            .is_empty()
    );
}

/// The same calls injected into real lower-layer files fail the layer check.
#[test]
fn engine_calls_injected_into_lower_layers_fail_the_layer_check() {
    for (target, injected) in [
        (
            "src/checks/pipeline.rs",
            "\nfn leak() { crate::scan_one_project(x); }\n",
        ),
        (
            "src/ecosystems/js/binding.rs",
            "\nfn leak() { scan_one_project(x); }\n",
        ),
        (
            "src/parsers/mod.rs",
            "\nfn leak() { super::engine::f(); }\n",
        ),
    ] {
        let mut files = load_sources();
        let entry = files.iter_mut().find(|f| f.rel == target).unwrap();
        entry.code.push_str(injected);
        let edges = roots::layer_edges_of(&files);
        assert!(
            edges
                .iter()
                .any(|edge| edge.starts_with(target) && edge.ends_with("engine")),
            "{target}: {edges:?}"
        );
    }
}
