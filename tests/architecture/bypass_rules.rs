//! Path-hiding tricks that keep a plugin reference out of the isolation scan: renaming the
//! registry, `super` or `crate` so a later path no longer spells the module, and macros that
//! assemble a path from their arguments. Plus tests that inject each into the real tree.

use super::isolation::{plugin_names, renames, tight};
use super::*;

/// The brace-matched bodies of every `macro_rules!` in `code`.
fn macro_bodies(code: &str) -> Vec<&str> {
    let mut bodies = Vec::new();
    for (at, _) in code.match_indices("macro_rules!") {
        let Some(open) = code[at..].find('{') else {
            continue;
        };
        let start = at + open;
        let mut depth = 0;
        for (offset, c) in code[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        bodies.push(&code[start..start + offset + 1]);
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    bodies
}

fn is_orchestration_or_plugin(rel: &str) -> bool {
    let inside = rel.trim_start_matches("src/");
    let module = match inside.split_once('/') {
        Some((dir, _)) => dir,
        None => inside.trim_end_matches(".rs"),
    };
    module == "ecosystems" || ORCHESTRATION.contains(&module)
}

/// Violations among `(relative path, code)` pairs:
/// - `use crate::ecosystems as reg;` (outside the plugins) and `use super as up;` / `crate as c`
///   hide which module a later path reaches;
/// - `macro_rules!` in the engine, `lib` or the plugins can build a path from an argument, and a
///   macro anywhere whose body names the registry, a plugin or a `super::$x` / `crate::$x` path.
pub(crate) fn bypass_violations(files: &[(String, String)], plugins: &[String]) -> Vec<String> {
    let mut violations = Vec::new();
    for (rel, code) in files {
        let code = &tight(code);
        let in_plugins = rel.starts_with("src/ecosystems/");
        let mut aliased = Vec::new();
        for module in ["super", "crate", "self"] {
            if renames(code, module) {
                aliased.push(module);
            }
        }
        if !in_plugins && renames(code, "ecosystems") {
            aliased.push("ecosystems");
        }
        for module in aliased {
            violations.push(format!(
                "{rel} renames `{module}`; name modules directly so isolation can be checked"
            ));
        }
        let bodies = macro_bodies(code);
        if !bodies.is_empty() && is_orchestration_or_plugin(rel) {
            violations.push(format!(
                "{rel} defines a macro; macros here can assemble module paths the isolation scan cannot see"
            ));
        }
        for body in bodies {
            let builds_path = ["super::$", "crate::$", "self::$", "ecosystems::$"]
                .iter()
                .any(|needle| body.contains(needle));
            let names_plugin = plugins
                .iter()
                .any(|plugin| body.contains(&format!("{plugin}::")))
                || body.contains("ecosystems::");
            if builds_path || names_plugin {
                violations.push(format!(
                    "{rel} defines a macro that builds or names a module path (`{}`)",
                    body.chars().take(40).collect::<String>().trim()
                ));
            }
        }
    }
    violations
}

fn real_files() -> Vec<(String, String)> {
    load_sources()
        .into_iter()
        .filter(|f| !f.is_test)
        .map(|f| (f.rel, f.code))
        .collect()
}

#[test]
fn the_real_tree_has_no_hidden_module_paths() {
    let violations = bypass_violations(&real_files(), &plugin_names());
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn aliases_and_macros_are_flagged() {
    let plugins = vec!["cargo".to_string(), "go".to_string()];
    let file = |rel: &str, code: &str| vec![(rel.to_string(), code.to_string())];
    let count = |rel: &str, code: &str| bypass_violations(&file(rel, code), &plugins).len();
    assert_eq!(count("src/engine/a.rs", "use crate::ecosystems as reg;"), 1);
    assert_eq!(
        count("src/engine/a.rs", "use crate::{ecosystems as reg};"),
        1
    );
    assert_eq!(count("src/ecosystems/js/a.rs", "use super as up;"), 1);
    assert_eq!(count("src/checks/a.rs", "use crate as c;"), 1);
    // A macro building a path from its argument, in a plugin and in the registry layer.
    assert_eq!(
        count(
            "src/ecosystems/js/a.rs",
            "macro_rules! sib { ($m:ident) => { super::$m::f() }; }"
        ),
        2
    );
    assert_eq!(
        count(
            "src/registry/a.rs",
            "macro_rules! sib { ($m:ident) => { super::$m::f() }; }"
        ),
        1
    );
    assert_eq!(
        count(
            "src/registry/a.rs",
            "macro_rules! ok { ($n:ident) => { struct $n; }; }"
        ),
        0
    );
    assert_eq!(count("src/engine/a.rs", "use crate::ecosystems;"), 0);
}

/// Each bypass injected into a real file is flagged by exactly the rule meant for it.
#[test]
fn bypasses_injected_into_the_real_tree_are_flagged() {
    let plugins = plugin_names();
    for (target, injected) in [
        ("src/engine/scan.rs", "\nuse crate::ecosystems as reg;\n"),
        (
            "src/ecosystems/js/workspace.rs",
            "\nmacro_rules! sib { ($m:ident) => { super::$m::f() }; }\n",
        ),
        ("src/checks/pipeline.rs", "\nuse crate as root;\n"),
    ] {
        let mut files = real_files();
        let entry = files
            .iter_mut()
            .find(|(rel, _)| rel == target)
            .unwrap_or_else(|| panic!("{target} missing"));
        entry.1.push_str(injected);
        let violations = bypass_violations(&files, &plugins);
        assert!(
            violations.iter().any(|v| v.starts_with(target)),
            "{target}: {violations:?}"
        );
    }
}

#[test]
fn engine_name_conversions_are_flagged() {
    let file = |code: &str| vec![("src/engine/a.rs".to_string(), code.to_string())];
    for code in [
        "fn f(s: &str) { let _ = s.parse::<Ecosystem>(); }",
        "fn f(e: E) -> bool { e.to_string() == \"\" }",
        "fn f(e: E) -> bool { \"\" == e.to_string() }",
    ] {
        let found = super::isolation::engine_ecosystem_violations(&file(code));
        assert_eq!(found.len(), 1, "{code}: {found:?}");
    }
    let ok = file("fn f(n: u8) -> String { n.to_string() }");
    assert!(super::isolation::engine_ecosystem_violations(&ok).is_empty());
}
