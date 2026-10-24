//! Items that `src/lib.rs` re-exports at the crate root (`pub(crate) use engine::*`) still belong
//! to the module that defines them: `crate::walk_project_tree` is a call into the engine.

use super::*;

/// Names declared at the start of a line as `pub(crate) fn|struct|enum|const|static|type|trait`.
fn top_level_items(code: &str) -> Vec<String> {
    let mut items = Vec::new();
    for line in code.lines() {
        let Some(rest) = line.strip_prefix("pub(crate) ") else {
            continue;
        };
        let rest = rest.strip_prefix("async ").unwrap_or(rest);
        for keyword in [
            "fn ", "struct ", "enum ", "const ", "static ", "type ", "trait ",
        ] {
            if let Some(after) = rest.strip_prefix(keyword) {
                let name: String = after.chars().take_while(|c| is_ident(*c)).collect();
                if !name.is_empty() {
                    items.push(name);
                }
            }
        }
    }
    items
}

/// Root-level name -> the top-level module that defines it, for the glob re-exports of `engine`
/// and `project` and the named re-exports of `ecosystems` in `lib.rs`.
pub(crate) fn root_export_modules(files: &[SourceFile]) -> BTreeMap<String, String> {
    let mut exports = BTreeMap::new();
    for file in files.iter().filter(|file| !file.is_test) {
        if file.module == "engine" || file.rel == "src/project.rs" {
            for name in top_level_items(&file.code) {
                exports.insert(name, file.module.clone());
            }
        }
        if file.rel == "src/lib.rs" {
            for statement in file.code.split(';') {
                if let Some((_, name)) = statement.split_once("pub(crate) use ecosystems::")
                    && !name.contains('*')
                {
                    exports.insert(name.trim().to_string(), "ecosystems".to_string());
                }
            }
        }
    }
    exports
}

/// Root-exported names used bare (`walk_project_tree(..)`) in a file that does not declare them:
/// plugins and other modules reach them through `use super::*` / `use crate::*` globs.
pub(crate) fn bare_root_uses(code: &str, exports: &BTreeMap<String, String>) -> Vec<String> {
    let declared = top_level_items(code);
    let mut owners = Vec::new();
    for (name, owner) in exports {
        if declared.contains(name) || owners.contains(owner) {
            continue;
        }
        let used = code.match_indices(name.as_str()).any(|(at, _)| {
            let before = code[..at].chars().next_back();
            let after = code[at + name.len()..].chars().next();
            !before.is_some_and(|c| is_ident(c) || c == ':' || c == '.' || c == '"')
                && matches!(after, Some('(' | '<' | ':'))
                && !code[..at].trim_end().ends_with("fn")
        });
        if used {
            owners.push(owner.clone());
        }
    }
    owners
}

/// `super::<module>` written in a file that sits directly under `src/` (its `mod.rs` or a flat
/// file) resolves to `crate::<module>`.
pub(crate) fn super_root_targets(rel: &str, code: &str, modules: &[String]) -> Vec<String> {
    let at_root_child = rel.strip_prefix("src/").is_some_and(|rest| {
        !rest.contains('/') || rest.ends_with("/mod.rs") && rest.matches('/').count() == 1
    });
    if !at_root_child {
        return Vec::new();
    }
    let mut targets = Vec::new();
    for (at, _) in code.match_indices("super::") {
        if code[..at]
            .chars()
            .next_back()
            .is_some_and(|c| is_ident(c) || c == ':')
        {
            continue;
        }
        let name: String = code[at + 7..]
            .chars()
            .take_while(|c| is_ident(*c))
            .collect();
        if modules.contains(&name) {
            targets.push(name);
        }
    }
    targets
}

/// `file -> module` for every module `file` depends on against the layer rules.
pub(crate) fn edges_of_file(
    file: &SourceFile,
    from_layer: &str,
    modules: &[String],
    root_exports: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut targets = crate_targets(&file.code);
    targets.extend(super_root_targets(&file.rel, &file.code, modules));
    if layer_of(&file.module) != Some("orchestration") {
        targets.extend(bare_root_uses(&file.code, root_exports));
    }
    let mut edges = Vec::new();
    for target in targets {
        // A root item such as `crate::Dependency` belongs to no layer, but one re-exported from
        // the engine, ecosystems or project is still a use of that module.
        let target = if modules.contains(&target) {
            target
        } else if let Some(owner) = root_exports.get(&target) {
            owner.clone()
        } else {
            continue;
        };
        let Some(to_layer) = layer_of(&target) else {
            continue;
        };
        if !layer_may_depend_on(from_layer, to_layer) {
            let edge = format!("{} -> {}", file.rel, target);
            if !edges.contains(&edge) {
                edges.push(edge);
            }
        }
    }
    edges
}

/// Layer violations over all non-test files, for tests that inject code.
pub(crate) fn layer_edges_of(files: &[SourceFile]) -> Vec<String> {
    let modules: Vec<String> = files
        .iter()
        .filter(|file| !file.is_test)
        .map(|file| file.module.clone())
        .collect();
    let exports = root_export_modules(files);
    files
        .iter()
        .filter(|file| !file.is_test)
        .flat_map(|file| match layer_of(&file.module) {
            Some(layer) => edges_of_file(file, layer, &modules, &exports),
            None => Vec::new(),
        })
        .collect()
}
