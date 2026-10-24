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

/// `code` with the whitespace around every `::` removed, so `crate :: Ecosystem :: Npm` and
/// `super\n::cargo` read like their tight forms.
fn tight(code: &str) -> String {
    let chars: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ':' && chars.get(i + 1) == Some(&':') {
            while out.ends_with(char::is_whitespace) {
                out.pop();
            }
            out.push_str("::");
            i += 2;
            while chars.get(i).is_some_and(|c| c.is_whitespace()) {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
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

/// Whether `code` reaches `plugin` through `prefix`, either as a plain path (`prefix::plugin`) or
/// inside a brace group (`prefix::{other, plugin as renamed}`), which a plain path search misses.
fn reaches_via(code: &str, prefix: &str, plugin: &str) -> bool {
    if mentions_path(code, &format!("{prefix}::{plugin}")) {
        return true;
    }
    let open = format!("{prefix}::{{");
    code.match_indices(&open).any(|(at, _)| {
        let start = at + open.len();
        let mut depth = 1;
        let mut end = code.len();
        for (offset, c) in code[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        group_elements(&code[start..end]).iter().any(|element| {
            element.starts_with(plugin)
                && !element[plugin.len()..].chars().next().is_some_and(is_ident)
        })
    })
}

/// The top-level, comma-separated elements of a `use` brace group, trimmed.
fn group_elements(group: &str) -> Vec<&str> {
    let mut elements = Vec::new();
    let (mut depth, mut from) = (0, 0);
    for (at, c) in group.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                elements.push(group[from..at].trim());
                from = at + 1;
            }
            _ => {}
        }
    }
    elements.push(group[from..].trim());
    elements
}

/// Whether `code` gives `name` another name: `name as Other` or `= path::name;`.
fn renames(code: &str, name: &str) -> bool {
    code.match_indices(name).any(|(at, _)| {
        let before = &code[..at];
        let after = &code[at + name.len()..];
        if before.chars().next_back().is_some_and(is_ident)
            || after.chars().next().is_some_and(is_ident)
        {
            return false;
        }
        let rest = after.trim_start();
        if rest.starts_with("as") && rest[2..].chars().next().is_some_and(char::is_whitespace) {
            return true;
        }
        // `type K = crate::path::Name;`: strip the leading path segments, then expect `=`.
        let mut head = before.trim_end();
        while let Some(path) = head.strip_suffix("::") {
            let path = path.trim_end();
            head = path[..path.rfind(|c| !is_ident(c)).map_or(0, |i| i + 1)].trim_end();
        }
        head.ends_with('=') && rest.starts_with(';')
    })
}

/// The text of every `use ...;` statement in `code`.
fn use_statements(code: &str) -> Vec<&str> {
    let mut statements = Vec::new();
    for (at, _) in code.match_indices("use") {
        if code[..at].chars().next_back().is_some_and(is_ident)
            || !code[at + 3..]
                .chars()
                .next()
                .is_some_and(char::is_whitespace)
        {
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
        let code = &tight(code);
        let owner = rel
            .strip_prefix("src/ecosystems/")
            .map(|rest| rest.split(['/', '.']).next().unwrap().to_string());
        if rel == "src/ecosystems/mod.rs" {
            // The registry names every plugin as a module and in its table, but it must not
            // `use` plugin items (every plugin sees its imports through `use super::*`) and must
            // keep the plugin modules private.
            for statement in use_statements(code) {
                for plugin in plugins {
                    if mentions_bare_path(statement, plugin)
                        || reaches_via(statement, "self", plugin)
                        || reaches_via(statement, "ecosystems", plugin)
                        || reaches_via(statement, "super", plugin)
                    {
                        violations.push(format!(
                            "{rel} imports from ecosystem {plugin} (`{}`); the registry may declare plugins but not re-export their items",
                            statement.trim()
                        ));
                    }
                }
            }
            for plugin in plugins {
                let compact: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
                let declared_public =
                    compact
                        .match_indices(&format!("mod {plugin}"))
                        .any(|(at, _)| {
                            let before = compact[..at].trim_end();
                            before.ends_with("pub") || before.ends_with(')')
                        });
                if declared_public {
                    violations.push(format!(
                        "{rel} makes plugin module {plugin} visible outside the registry; keep it private"
                    ));
                }
            }
            continue;
        }
        // `super::<plugin>` resolves through the registry's imports at any depth: a nested file
        // sees them via its parent's `use super::*`.
        let supers: Vec<String> = (1..=4).map(|n| vec!["super"; n].join("::")).collect();
        for plugin in plugins {
            let reaches_in = reaches_via(code, "ecosystems", plugin);
            match owner.as_deref() {
                None if reaches_in => violations.push(format!(
                    "{rel} reaches into ecosystems::{plugin}; go through the EcosystemSupport trait"
                )),
                Some(own) if own != plugin => {
                    let sibling = reaches_in
                        || supers
                            .iter()
                            .any(|prefix| reaches_via(code, prefix, plugin))
                        || mentions_bare_path(code, plugin);
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
        let mut found = Vec::new();
        if renames(code, "ProjectInputKind") {
            found.push("a rename");
        }
        // `<ProjectInputKind>::X` and `Self::X` inside an impl hide the variant path.
        if compact.contains("<ProjectInputKind>")
            || compact.contains("impl ProjectInputKind")
            || compact.contains("for ProjectInputKind")
        {
            found.push("an impl or qualified path");
        }
        for what in found {
            violations.push(format!(
                "{rel} hides ProjectInputKind behind {what}; name it directly so placement can be checked"
            ));
        }
    }
    violations
}

/// Module-path tricks that would pull a file into another module's namespace without a path the
/// scan can see: `#[path = ".."]` on anything but a test module, and `include!`.
fn module_redirect_violations(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (rel, code) in files {
        let c: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        for (at, _) in c.match_indices("#[path") {
            if !c[..at].ends_with("#[cfg(test)]") {
                violations.push(format!(
                    "{rel} redirects a module with #[path]; module files must sit where the module tree says"
                ));
            }
        }
        // `#[cfg_attr(cond, path = "..")]` redirects just the same.
        for (at, _) in c.match_indices("#[cfg_attr(") {
            let attribute = &c[at..c[at..].find(']').map_or(c.len(), |end| at + end)];
            if attribute.contains("path=") {
                violations.push(format!("{rel} redirects a module with cfg_attr(path)"));
            }
        }
        let includes = c.contains("include!")
            || ["::include", "{include", ",include"].iter().any(|needle| {
                c.match_indices(needle).any(|(at, _)| {
                    let rest = &c[at + needle.len()..];
                    rest.starts_with("as") || !rest.chars().next().is_some_and(is_ident)
                })
            });
        if includes {
            violations.push(format!(
                "{rel} uses include!; the scan cannot see included code"
            ));
        }
    }
    violations
}

/// Whether `code` compares `as_str()` or a descriptor's `project_type` with a string literal
/// (literal contents are already stripped, leaving `""`), which is how a name-based ecosystem
/// branch would avoid mentioning a variant.
fn compares_ecosystem_name(code: &str) -> bool {
    let flat: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    ["as_str()", "project_type"].iter().any(|subject| {
        flat.match_indices(subject).any(|(at, _)| {
            let after = &flat[at + subject.len()..];
            let before = &flat[..at];
            after.starts_with("==\"")
                || after.starts_with("!=\"")
                || after.starts_with(",\"")
                    && before
                        .rfind("matches!(")
                        .is_some_and(|m| !before[m..].contains(';'))
                || before.ends_with("\"==")
                || before.ends_with("\"!=")
                || (after.starts_with('{') && before.ends_with("match")
                    || before[before.len().saturating_sub(40)..].contains("match")
                        && after.starts_with('{'))
        })
    })
}

/// Orchestration code (engine, lib, main, bootstrap) must not name an ecosystem: it asks the
/// plugin registry. `Ecosystem::<Variant>` and `JsPackageManager` are how a per-ecosystem branch
/// would creep back in.
fn engine_ecosystem_violations(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (rel, code) in files {
        let inside = rel.trim_start_matches("src/");
        let module = match inside.split_once('/') {
            Some((dir, _)) => dir,
            None => inside.trim_end_matches(".rs"),
        };
        if !ORCHESTRATION.contains(&module) {
            continue;
        }
        let code = &tight(code);
        if compares_ecosystem_name(code) {
            violations.push(format!(
                "{rel} branches on an ecosystem name string (`as_str()` / `project_type` against a literal); ask the plugin instead"
            ));
        }
        for pattern in ["Ecosystem::", "JsPackageManager"] {
            let named = code.match_indices(pattern).any(|(at, _)| {
                !code[..at].chars().next_back().is_some_and(is_ident)
                    && (pattern.ends_with("::")
                        || !code[at + pattern.len()..]
                            .chars()
                            .next()
                            .is_some_and(is_ident))
            });
            let name = pattern.trim_end_matches("::");
            if named || renames(code, name) {
                violations.push(format!(
                    "{rel} names `{pattern}`; ask the ecosystem plugin (ecosystems::for_ecosystem or the EcosystemSupport trait) instead"
                ));
            }
        }
    }
    violations.sort();
    violations.dedup();
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
    violations.extend(engine_ecosystem_violations(&files));
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

#[test]
fn engine_rule_flags_ecosystem_names_in_orchestration_only() {
    let file = |rel: &str, code: &str| vec![(rel.to_string(), code.to_string())];
    for code in [
        "fn f(e: Ecosystem) -> bool { e == Ecosystem::Npm }",
        "match m { JsPackageManager::Pnpm => 1, _ => 0 }",
    ] {
        assert_eq!(
            engine_ecosystem_violations(&file("src/engine/x.rs", code)).len(),
            1,
            "{code}"
        );
    }
    // The type itself, similarly named identifiers, and lower layers are fine.
    assert!(
        engine_ecosystem_violations(&file(
            "src/engine/x.rs",
            "fn f(e: Ecosystem) { MyEcosystem::Npm; }"
        ))
        .is_empty()
    );
    assert!(engine_ecosystem_violations(&file("src/registry/x.rs", "Ecosystem::Npm")).is_empty());
    assert!(
        engine_ecosystem_violations(&file("src/ecosystems/js/mod.rs", "JsPackageManager::Pnpm"))
            .is_empty()
    );
    assert_eq!(
        engine_ecosystem_violations(&file("src/lib.rs", "Ecosystem::Cargo")).len(),
        1
    );
}

#[test]
fn engine_ecosystem_names_are_caught_in_the_real_tree() {
    let clean = scanned_sources();
    assert!(engine_ecosystem_violations(&clean).is_empty());
    let mut files = clean;
    let entry = files
        .iter_mut()
        .find(|(rel, _)| rel == "src/engine/scan.rs")
        .unwrap();
    entry
        .1
        .push_str("\nfn leak(e: Ecosystem) -> bool { e == Ecosystem::Npm }\n");
    assert_eq!(engine_ecosystem_violations(&files).len(), 1);
}

#[test]
fn isolation_rule_flags_the_second_round_bypasses() {
    let plugins = vec!["cargo".to_string(), "go".to_string(), "ruby".to_string()];
    let file = |rel: &str, code: &str| vec![(rel.to_string(), code.to_string())];
    let isolation = |rel: &str, code: &str| isolation_violations(&file(rel, code), &plugins).len();

    // B1: `super` in a plugin's own mod.rs is the registry, like in a flat plugin file.
    assert_eq!(
        isolation("src/ecosystems/cargo/mod.rs", "use super::go::Go;"),
        1
    );
    // ...and deeper in the plugin it still resolves through the parent's glob import.
    assert_eq!(
        isolation("src/ecosystems/cargo/inner.rs", "use super::go;"),
        1
    );
    // B2/B3: renames inside a brace group.
    assert_eq!(
        isolation("src/ecosystems/ruby.rs", "use super::{common, go as g};"),
        1
    );
    assert_eq!(
        isolation("src/engine/x.rs", "use crate::ecosystems::{cargo as cp};"),
        1
    );
    assert_eq!(
        isolation(
            "src/engine/x.rs",
            "use crate::ecosystems::{common, nested::{cargo}};"
        ),
        0
    );
    // B3: the registry may not expose a plugin module.
    for decl in [
        "pub(crate) mod cargo;",
        "pub mod cargo;",
        "pub(super) mod cargo;",
    ] {
        assert_eq!(isolation("src/ecosystems/mod.rs", decl), 1, "{decl}");
    }
    assert_eq!(isolation("src/ecosystems/mod.rs", "mod cargo;"), 0);
    // B10: `use` followed by a newline.
    assert_eq!(
        isolation(
            "src/ecosystems/mod.rs",
            "pub(crate) use\n    cargo::helper as exposed;"
        ),
        1
    );

    // B4b: aliasing the ecosystem types in orchestration code.
    for code in [
        "use crate::Ecosystem as E; fn f(e: E) -> bool { e == E::Npm }",
        "type E = crate::Ecosystem;",
        "use crate::project::JsPackageManager as M;",
    ] {
        assert_eq!(
            engine_ecosystem_violations(&file("src/engine/x.rs", code)).len(),
            1,
            "{code}"
        );
    }
    // B5b/B6: qualified paths, impl blocks and path-qualified aliases of the kind type.
    for code in [
        "fn f() { <ProjectInputKind>::Npm; }",
        "impl ProjectInputKind { fn x() -> Self { Self::Cargo } }",
        "impl Trait for ProjectInputKind { }",
        "type K = crate::project::ProjectInputKind;",
        "use crate::project::{ProjectInputKind as K};",
    ] {
        assert_eq!(
            kind_alias_violations(&file("src/engine/x.rs", code)).len(),
            1,
            "{code}"
        );
    }
    // B7: cfg_attr and spaced path attributes, and include through an import.
    for code in [
        "#[cfg_attr(all(), path = \"../ecosystems/go.rs\")]\nmod x;",
        "#[ path = \"../ecosystems/go.rs\" ]\nmod x;",
        "#[\n    path = \"../x.rs\"\n]\nmod x;",
        "use std::include as inc; fn f() { inc!(\"f.in\"); }",
        "use std::{include as inc};",
    ] {
        assert_eq!(
            module_redirect_violations(&file("src/engine/x.rs", code)).len(),
            1,
            "{code}"
        );
    }
    assert!(
        module_redirect_violations(&file("src/engine/x.rs", "use std::include_str;")).is_empty()
    );
}

/// The same bypasses injected into real files are caught in the real tree.
#[test]
fn second_round_bypasses_are_caught_in_the_real_tree() {
    let plugins = plugin_names();
    let clean = scanned_sources();
    let inject = |rel: &str, extra: &str| {
        let mut files = clean.clone();
        files
            .iter_mut()
            .find(|(path, _)| path == rel)
            .unwrap_or_else(|| panic!("{rel} not found"))
            .1
            .push_str(extra);
        files
    };
    let files = inject("src/ecosystems/cargo/mod.rs", "\nuse super::go::Go;\n");
    assert_eq!(isolation_violations(&files, &plugins).len(), 1);
    let files = inject("src/ecosystems/ruby.rs", "\nuse super::{go as g};\n");
    assert_eq!(isolation_violations(&files, &plugins).len(), 1);
    let files = inject(
        "src/engine/scan.rs",
        "\nuse crate::ecosystems::{cargo as cp};\n",
    );
    assert_eq!(isolation_violations(&files, &plugins).len(), 1);
    let files = inject("src/engine/scan.rs", "\nuse crate::Ecosystem as E;\n");
    assert_eq!(engine_ecosystem_violations(&files).len(), 1);
    let files = inject(
        "src/engine/scan.rs",
        "\nfn leak() { <ProjectInputKind>::Npm; }\n",
    );
    assert_eq!(kind_alias_violations(&files).len(), 1);
    let files = inject(
        "src/engine/scan.rs",
        "\n#[cfg_attr(all(), path = \"../ecosystems/go.rs\")]\nmod sneaky;\n",
    );
    assert_eq!(module_redirect_violations(&files).len(), 1);
    // A #[cfg(test)] field in a production file must not hide what follows it.
    let files = inject(
        "src/engine/scan.rs",
        "\nstruct Probe { a: u8, #[cfg(test)] b: u8 }\nfn leak(e: Ecosystem) -> bool { e == Ecosystem::Npm }\n",
    );
    let cut: Vec<(String, String)> = files
        .into_iter()
        .map(|(rel, code)| (rel, cut_inline_tests(&code)))
        .collect();
    assert_eq!(engine_ecosystem_violations(&cut).len(), 1);
}

#[test]
fn isolation_rule_flags_the_third_round_bypasses() {
    let plugins = vec!["cargo".to_string(), "go".to_string()];
    let file = |rel: &str, code: &str| vec![(rel.to_string(), code.to_string())];
    // A nested plugin file reaching a sibling through the parent's glob import.
    assert_eq!(
        isolation_violations(
            &file(
                "src/ecosystems/go/workspace.rs",
                "fn f() { super::cargo::normalize(); }"
            ),
            &plugins
        )
        .len(),
        1
    );
    // The registry re-exporting a plugin through a nested module.
    assert_eq!(
        isolation_violations(
            &file(
                "src/ecosystems/mod.rs",
                "pub(crate) mod rt { pub(crate) use super::cargo::*; }"
            ),
            &plugins
        )
        .len(),
        1
    );
    // Whitespace around `::` must not hide a path or a variant.
    assert_eq!(
        isolation_violations(
            &file(
                "src/engine/scan.rs",
                "use crate :: ecosystems :: cargo :: Cargo;"
            ),
            &plugins
        )
        .len(),
        1
    );
    let engine = |code: &str| engine_ecosystem_violations(&file("src/engine/scan.rs", code));
    assert_eq!(engine("fn f() { crate::Ecosystem :: Npm; }").len(), 1);
    // String branching on a name.
    assert_eq!(engine("fn f(e: E) { if e.as_str() == \"\" {} }").len(), 1);
    assert_eq!(
        engine("fn f(s: S) { s.kind.descriptor().project_type == \"\" }").len(),
        1
    );
    assert_eq!(
        engine("fn f(e: E) { match e.as_str() { \"\" => 1, _ => 2 } }").len(),
        1
    );
    // Comparing against a variable (a user's `--type` selection) stays fine.
    assert!(
        engine("fn f(k: K, sel: &str) -> bool { k.descriptor().project_type == sel }").is_empty()
    );
}
