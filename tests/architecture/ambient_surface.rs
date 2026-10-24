//! Every ecosystem plugin must state which repository files its tool reads implicitly.
//! `EcosystemSupport::ambient_inputs` has no default body, so a new plugin cannot compile
//! without a table; this rule also keeps the table from being an empty list.

use super::*;
use isolation::{plugin_names, tight};

/// Plugin source text: the file or directory under `src/ecosystems/` that carries its name.
fn plugin_code(files: &[(String, String)], plugin: &str) -> String {
    let single = format!("src/ecosystems/{plugin}.rs");
    let dir = format!("src/ecosystems/{plugin}/");
    files
        .iter()
        .filter(|(rel, _)| *rel == single || rel.starts_with(&dir))
        .map(|(_, code)| code.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn trait_violations(files: &[(String, String)]) -> Vec<String> {
    let decl = files
        .iter()
        .find(|(rel, _)| rel == "src/ecosystems/mod.rs")
        .map(|(_, code)| code.as_str())
        .unwrap_or_default();
    let Some(at) = decl.find("fn ambient_inputs") else {
        return vec!["EcosystemSupport declares no `fn ambient_inputs`".to_string()];
    };
    let rest = &decl[at..];
    let end = rest.find(['{', ';']).unwrap_or(rest.len());
    if rest[end..].starts_with('{') {
        return vec![
            "`EcosystemSupport::ambient_inputs` must be required: it has a default body"
                .to_string(),
        ];
    }
    Vec::new()
}

fn ambient_violations(files: &[(String, String)], plugins: &[String]) -> Vec<String> {
    let mut violations = trait_violations(files);
    for plugin in plugins {
        let code = plugin_code(files, plugin);
        // Directories of shared test helpers are not plugins.
        if !code.contains("impl EcosystemSupport for") {
            continue;
        }
        if !code.contains("fn ambient_inputs") {
            violations.push(format!(
                "plugin `{plugin}` does not implement `ambient_inputs`"
            ));
        } else if tight(&code).contains("AMBIENT:&[Row]=&[];") {
            violations.push(format!(
                "plugin `{plugin}` states an empty ambient-input table"
            ));
        }
    }
    violations
}

fn scanned() -> Vec<(String, String)> {
    load_sources()
        .into_iter()
        .filter(|f| !f.is_test)
        .map(|f| (f.rel, f.code))
        .collect()
}

#[test]
fn every_plugin_implements_a_required_ambient_inputs() {
    let plugins = plugin_names();
    assert!(plugins.len() >= 8, "found plugins {plugins:?}");
    let violations = ambient_violations(&scanned(), &plugins);
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn ambient_rule_flags_a_default_body_and_a_missing_table() {
    let plugins = plugin_names();
    let mut files = scanned();
    assert!(ambient_violations(&files, &plugins).is_empty());
    for (rel, code) in files.iter_mut() {
        if rel == "src/ecosystems/mod.rs" {
            *code = code.replace(
                "fn ambient_inputs(&self) -> &'static [ambient::AmbientInput];",
                "fn ambient_inputs(&self) -> &'static [ambient::AmbientInput] { &[] }",
            );
        }
    }
    assert!(
        ambient_violations(&files, &plugins)
            .iter()
            .any(|v| v.contains("default body"))
    );
    let mut files = scanned();
    for (rel, code) in files.iter_mut() {
        if rel == "src/ecosystems/ruby.rs" {
            *code = code.replace("fn ambient_inputs", "fn other_inputs");
        }
    }
    assert!(
        ambient_violations(&files, &plugins)
            .iter()
            .any(|v| v.contains("`ruby`"))
    );
}
