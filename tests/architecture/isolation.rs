//! Ecosystem plugin isolation and placement rules (docs/specs/architecture-guardrails.md).

use super::*;

/// The ecosystem plugin modules: every `src/ecosystems/<name>.rs` or `src/ecosystems/<name>/`
/// except the shared helpers.
fn plugin_names() -> Vec<String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(repo_root().join("src").join("ecosystems")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        if !["mod", "common", "tests"].contains(&name.as_str()) {
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Whether `code` contains `path` followed by a non-identifier character.
fn mentions_path(code: &str, path: &str) -> bool {
    code.match_indices(path).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + path.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Whether `code` starts a path at `name::` (a bare module path such as `cargo::parse(..)`), as
/// opposed to continuing one (`crate::cargo::`, `super::cargo::`) or naming a longer identifier.
fn mentions_bare_path(code: &str, name: &str) -> bool {
    let needle = format!("{name}::");
    code.match_indices(&needle).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        !before.is_some_and(|c| is_ident(c) || c == ':')
    })
}

/// The text of every `use ...;` statement in `code`.
fn use_statements(code: &str) -> Vec<&str> {
    let mut statements = Vec::new();
    for (at, _) in code.match_indices("use ") {
        if code[..at].chars().next_back().is_some_and(is_ident) {
            continue;
        }
        if let Some(end) = code[at..].find(';') {
            statements.push(&code[at..at + end]);
        }
    }
    statements
}

/// Isolation violations among `(relative path, code)` pairs: code outside `src/ecosystems/`
/// naming a concrete plugin, a plugin reaching a sibling plugin by any path (absolute, relative
/// or bare through a glob import), and the registry re-exporting or importing plugin items
/// (every plugin sees the registry's imports through `use super::*`).
fn isolation_violations(files: &[(String, String)], plugins: &[String]) -> Vec<String> {
    let mut violations = Vec::new();
    for (rel, code) in files {
        let owner = rel
            .strip_prefix("src/ecosystems/")
            .map(|rest| rest.split(['/', '.']).next().unwrap().to_string());
        if rel == "src/ecosystems/mod.rs" {
            // The registry names every plugin as a module and in its table, but it must not
            // `use` plugin items: that would hand them to every plugin and the engine.
            for statement in use_statements(code) {
                for plugin in plugins {
                    if mentions_bare_path(statement, plugin)
                        || mentions_path(statement, &format!("self::{plugin}"))
                        || mentions_path(statement, &format!("ecosystems::{plugin}"))
                    {
                        violations.push(format!(
                            "{rel} imports from ecosystem {plugin} (`{}`); the registry may declare plugins but not re-export their items",
                            statement.trim()
                        ));
                    }
                }
            }
            continue;
        }
        for plugin in plugins {
            let reaches_in = mentions_path(code, &format!("ecosystems::{plugin}"));
            match owner.as_deref() {
                None if reaches_in => violations.push(format!(
                    "{rel} reaches into ecosystems::{plugin}; go through the EcosystemSupport trait"
                )),
                Some(own) if own != plugin => {
                    let sibling = reaches_in
                        || mentions_path(code, &format!("super::super::{plugin}"))
                        || mentions_bare_path(code, plugin)
                        || (rel.matches('/').count() == 2
                            && mentions_path(code, &format!("super::{plugin}")));
                    if sibling {
                        violations.push(format!(
                            "{rel} (ecosystem {own}) imports ecosystem {plugin}; share code through ecosystems::common"
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    violations
}

/// `ProjectInputKind` variants must be named only in the kind table and the plugins. Renaming the
/// type (`use ... as K`, `type K = ...`) would hide `K::Cargo` from the placement count.
fn kind_alias_violations(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (rel, code) in files {
        if rel == "src/project.rs" || rel.starts_with("src/ecosystems/") {
            continue;
        }
        let compact: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
        for pattern in ["ProjectInputKind as ", "= ProjectInputKind;"] {
            if compact.contains(pattern) {
                violations.push(format!(
                    "{rel} renames ProjectInputKind (`{pattern}`); name it directly so placement can be checked"
                ));
            }
        }
    }
    violations
}

/// Module-path tricks that would pull a file into another module's namespace without a path the
/// scan can see: `#[path = ".."]` on anything but a test module, and `include!`.
fn module_redirect_violations(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (rel, code) in files {
        for (at, _) in code.match_indices("#[path") {
            if !code[..at].trim_end().ends_with("#[cfg(test)]") {
                violations.push(format!(
                    "{rel} redirects a module with #[path]; module files must sit where the module tree says"
                ));
            }
        }
        if mentions_path(code, "include!") {
            violations.push(format!(
                "{rel} uses include!; the scan cannot see included code"
            ));
        }
    }
    violations
}

fn scanned_sources() -> Vec<(String, String)> {
    load_sources()
        .into_iter()
        .filter(|f| !f.is_test)
        .map(|f| (f.rel, f.code))
        .collect()
}

#[test]
fn ecosystem_plugins_are_isolated() {
    let plugins = plugin_names();
    assert!(plugins.len() >= 8, "found plugins {plugins:?}");
    let files = scanned_sources();
    let mut violations = isolation_violations(&files, &plugins);
    violations.extend(kind_alias_violations(&files));
    violations.extend(module_redirect_violations(&files));
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn isolation_rule_flags_engine_and_sibling_imports() {
    let plugins = vec!["cargo".to_string(), "go".to_string()];
    let files = vec![
        (
            "src/engine/scan.rs".to_string(),
            "use crate::ecosystems::cargo::Cargo;".to_string(),
        ),
        (
            "src/ecosystems/go.rs".to_string(),
            "use super::cargo::helper;".to_string(),
        ),
        (
            "src/ecosystems/go/inner.rs".to_string(),
            "use super::super::cargo::helper;".to_string(),
        ),
        (
            "src/ecosystems/cargo/mod.rs".to_string(),
            "use super::common::x; use crate::ecosystems::first_existing_lockfile;".to_string(),
        ),
        (
            "src/engine/ok.rs".to_string(),
            "use crate::ecosystems::bind;".to_string(),
        ),
    ];
    let violations = isolation_violations(&files, &plugins);
    assert_eq!(violations.len(), 3, "{violations:?}");
    assert!(violations[0].contains("src/engine/scan.rs"));
}

/// The rule run over the real source tree with a violation injected into real files: an engine
/// file importing a concrete plugin and a plugin file importing a sibling must both be flagged,
/// and nothing else may be.
#[test]
fn isolation_rule_catches_violations_injected_into_the_real_tree() {
    let plugins = plugin_names();
    let mut files: Vec<(String, String)> = load_sources()
        .into_iter()
        .filter(|f| !f.is_test)
        .map(|f| (f.rel, f.code))
        .collect();
    assert!(isolation_violations(&files, &plugins).is_empty());
    for (rel, code) in files.iter_mut() {
        if rel == "src/engine/scan.rs" {
            code.push_str("\nuse crate::ecosystems::cargo::Cargo;\n");
        }
        if rel == "src/ecosystems/go.rs" {
            code.push_str("\nuse super::cargo::Cargo;\n");
        }
    }
    let violations = isolation_violations(&files, &plugins);
    assert_eq!(violations.len(), 2, "{violations:?}");
    assert!(
        violations
            .iter()
            .any(|v| v.starts_with("src/engine/scan.rs"))
    );
    assert!(
        violations
            .iter()
            .any(|v| v.starts_with("src/ecosystems/go.rs"))
    );
}

#[test]
fn scanner_finds_whole_path_mentions() {
    assert!(mentions_path("use a::js;", "a::js"));
    assert!(!mentions_path("use a::json;", "a::js"));
    assert!(!mentions_path("use xa::js;", "a::js"));
}

#[test]
fn isolation_rule_flags_the_red_team_bypasses() {
    let plugins = vec!["cargo".to_string(), "go".to_string()];
    let file = |rel: &str, code: &str| vec![(rel.to_string(), code.to_string())];

    // A bare sibling path reached through `use super::*`.
    let v = isolation_violations(
        &file(
            "src/ecosystems/go.rs",
            "fn f() { cargo::parse_dependencies(); }",
        ),
        &plugins,
    );
    assert_eq!(v.len(), 1, "{v:?}");
    // The plugin's own name, longer identifiers and continued paths are not siblings.
    assert!(
        isolation_violations(
            &file(
                "src/ecosystems/go.rs",
                "fn f() { go::x(); my_cargo::y(); a::cargo::z(); }"
            ),
            &plugins
        )
        .is_empty()
    );

    // The registry re-exporting or importing a plugin item, any visibility.
    for statement in [
        "pub(crate) use cargo::Helper as Exposed;",
        "use cargo::Helper;",
        "pub use self::go::Thing;",
        "use {cargo::A, common::B};",
    ] {
        let v = isolation_violations(&file("src/ecosystems/mod.rs", statement), &plugins);
        assert_eq!(v.len(), 1, "{statement}: {v:?}");
    }
    // Declaring and tabulating plugins is what the registry is for.
    assert!(
        isolation_violations(
            &file(
                "src/ecosystems/mod.rs",
                "mod cargo; use common::*; static P: [&dyn S; 1] = [&cargo::Cargo];"
            ),
            &plugins
        )
        .is_empty()
    );

    // Renaming ProjectInputKind hides its variants from the placement count.
    for code in [
        "use crate::project::ProjectInputKind as K; fn f() { K::Cargo; }",
        "type K = ProjectInputKind;",
    ] {
        let v = kind_alias_violations(&file("src/engine/scan.rs", code));
        assert_eq!(v.len(), 1, "{code}: {v:?}");
    }
    assert!(
        kind_alias_violations(&file("src/project.rs", "use x::ProjectInputKind as K;")).is_empty()
    );
    assert!(
        kind_alias_violations(&file("src/engine/scan.rs", "fn f(k: ProjectInputKind) {}"))
            .is_empty()
    );

    // Module redirection and include! evade path scanning.
    assert_eq!(
        module_redirect_violations(&file(
            "src/engine/x.rs",
            "#[path = \"../ecosystems/go.rs\"]\nmod g;"
        ))
        .len(),
        1
    );
    assert_eq!(
        module_redirect_violations(&file("src/engine/x.rs", "include!(\"y.rs\");")).len(),
        1
    );
    assert!(
        module_redirect_violations(&file(
            "src/engine/x.rs",
            "#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod tests;"
        ))
        .is_empty()
    );
}

/// The same bypasses injected into the real tree are each flagged exactly once.
#[test]
fn red_team_bypasses_are_caught_in_the_real_tree() {
    let plugins = plugin_names();
    let clean = scanned_sources();
    assert!(isolation_violations(&clean, &plugins).is_empty());
    assert!(kind_alias_violations(&clean).is_empty());
    assert!(module_redirect_violations(&clean).is_empty());

    let inject = |rel: &str, extra: &str| {
        let mut files = clean.clone();
        let entry = files
            .iter_mut()
            .find(|(path, _)| path == rel)
            .unwrap_or_else(|| panic!("{rel} not found"));
        entry.1.push_str(extra);
        files
    };

    let files = inject(
        "src/ecosystems/go.rs",
        "\nfn leak() { cargo::parse_cargo_project_dependencies(); }\n",
    );
    assert_eq!(isolation_violations(&files, &plugins).len(), 1);

    let files = inject(
        "src/ecosystems/mod.rs",
        "\npub(crate) use cargo::parse_cargo_project_dependencies as Y;\n",
    );
    assert_eq!(isolation_violations(&files, &plugins).len(), 1);

    let files = inject(
        "src/engine/scan.rs",
        "\nuse crate::project::ProjectInputKind as K;\n",
    );
    assert_eq!(kind_alias_violations(&files).len(), 1);

    let files = inject(
        "src/engine/scan.rs",
        "\n#[path = \"../ecosystems/cargo/mod.rs\"]\nmod sneaky;\n",
    );
    assert_eq!(module_redirect_violations(&files).len(), 1);

    let files = inject(
        "src/engine/scan.rs",
        "\ninclude!(\"../ecosystems/go.rs\");\n",
    );
    assert_eq!(module_redirect_violations(&files).len(), 1);
}
