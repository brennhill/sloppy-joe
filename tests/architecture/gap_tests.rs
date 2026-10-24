//! Round-14 bypasses of the guardrails themselves: names the crate root imports privately,
//! `super` chains from nested files, exotic line separators and complexity outside `fn` bodies.

use super::*;

fn inject(target: &str, code: &str) -> Vec<String> {
    let mut files = load_sources();
    let entry = files
        .iter_mut()
        .find(|f| f.rel == target)
        .unwrap_or_else(|| panic!("{target} is not a source file"));
    entry.code.push_str(code);
    roots::layer_edges_of(&files)
}

#[test]
fn private_lib_imports_count_as_uses_of_their_module() {
    let exports = roots::root_export_modules(&load_sources());
    assert_eq!(
        exports.get("Registry").map(String::as_str),
        Some("registry")
    );
    assert_eq!(exports.get("Check").map(String::as_str), Some("checks"));
    for (target, code, module) in [
        (
            "src/parsers/nuget_config.rs",
            "\nfn leak(_r: &dyn crate::Registry) {}\n",
            "registry",
        ),
        (
            "src/registry/nuget.rs",
            "\nfn leak<C: crate::Check>(_c: &C) {}\n",
            "checks",
        ),
    ] {
        let edges = inject(target, code);
        assert!(
            edges
                .iter()
                .any(|e| e.starts_with(target) && e.ends_with(module)),
            "{target}: {edges:?}"
        );
    }
}

#[test]
fn lib_imports_handle_groups_renames_and_attributes() {
    let modules = vec!["report".to_string(), "checks".to_string()];
    let imports = lib_imports_for_test(
        "#[allow(unused)]\nuse report::{Issue, ScanReport as Sr};\nuse anyhow::Result;\nuse checks::malicious::OsvClient",
        &modules,
    );
    assert!(imports.contains(&("Issue".into(), "report".into())));
    assert!(imports.contains(&("Sr".into(), "report".into())));
    assert!(imports.contains(&("OsvClient".into(), "checks".into())));
    assert!(!imports.iter().any(|(name, _)| name == "Result"));
}

fn lib_imports_for_test(code: &str, modules: &[String]) -> Vec<(String, String)> {
    let file = SourceFile {
        rel: "src/lib.rs".into(),
        module: "lib".into(),
        raw_lines: 0,
        is_test: false,
        code: code.into(),
    };
    let mut files: Vec<SourceFile> = modules
        .iter()
        .map(|module| SourceFile {
            rel: format!("src/{module}.rs"),
            module: module.clone(),
            raw_lines: 0,
            is_test: false,
            code: String::new(),
        })
        .collect();
    files.push(file);
    roots::root_export_modules(&files).into_iter().collect()
}

#[test]
fn super_chains_from_nested_files_reach_the_crate_root() {
    let modules: Vec<String> = ["registry", "checks", "parsers"]
        .map(str::to_string)
        .to_vec();
    let targets = |rel, code| roots::super_root_targets(rel, code, &modules);
    assert_eq!(
        targets(
            "src/parsers/jvm/pom.rs",
            "super::super::super::registry::Registry"
        ),
        vec!["registry"]
    );
    assert_eq!(
        targets("src/parsers/jvm/mod.rs", "super::super::registry::R"),
        vec!["registry"]
    );
    assert_eq!(
        targets(
            "src/parsers/jvm/pom.rs",
            "super::super::{checks::X, parsers::Y}"
        ),
        Vec::<String>::new(),
        "two climbs from jvm/pom.rs stay inside parsers"
    );
    assert_eq!(
        targets("src/parsers/mod.rs", "super::{checks::X, parsers::Y}"),
        vec!["checks", "parsers"]
    );
    assert!(targets("src/parsers/jvm/pom.rs", "super::registry::R").is_empty());

    let edges = inject(
        "src/parsers/jvm/pom.rs",
        "\nfn leak(_r: &dyn super::super::super::registry::Registry) {}\n",
    );
    assert!(
        edges
            .iter()
            .any(|e| e.starts_with("src/parsers/jvm/pom.rs") && e.ends_with("registry")),
        "{edges:?}"
    );
}

#[test]
fn exotic_line_separators_do_not_hide_lines_from_the_size_cap() {
    assert_eq!(count_lines("a\nb\n"), 2);
    assert_eq!(count_lines("a\r\nb"), 2);
    assert_eq!(count_lines("a\rb\rc"), 3);
    assert_eq!(count_lines(&"x\u{2028}".repeat(1600)), 1600);
    assert_eq!(count_lines("a\u{2029}b\u{85}c\u{b}d\u{c}e"), 5);
    assert_eq!(count_lines(""), 0);
}

#[test]
fn closures_in_statics_consts_and_macros_count_toward_the_complexity_cap() {
    let ifs = "if x { 1 } else ".repeat(20);
    for code in [
        format!(
            "static RT: LazyLock<Box<dyn Fn(&str) -> usize + Send + Sync>> = LazyLock::new(|| Box::new(|x| {{ {ifs} 0 }}));"
        ),
        format!("const RT: fn(bool) -> usize = |x| {{ {ifs} 0 }};"),
        format!("macro_rules! rt {{ ($x:expr) => {{ {ifs} 0 }} }}"),
        format!("impl A {{ const RT: fn(bool) -> usize = |x| {{ {ifs} 0 }}; }}"),
    ] {
        let found = function_complexities(&strip(&code));
        assert!(
            found.iter().any(|(_, n)| *n > MAX_COMPLEXITY),
            "{code}: {found:?}"
        );
    }
    // A const generic parameter and a `const fn` are not initializers and swallow nothing.
    let code =
        strip("fn f<const N: usize>(x: [u8; N]) { if a {} }\nconst fn g() {}\nconst K: u8 = 1;");
    let found = function_complexities(&code);
    assert!(found.iter().all(|(_, n)| *n <= 2), "{found:?}");
    assert!(found.iter().any(|(name, _)| name == "K"));
}
