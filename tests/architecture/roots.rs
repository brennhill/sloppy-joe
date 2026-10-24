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

/// Names a `use` statement brings into scope: the last segment of each path, the members of a
/// `{..}` group (one level of nesting) and the target of an `as` rename.
fn imported_names(path: &str) -> Vec<String> {
    let last = |item: &str| -> Option<String> {
        let item = item.trim();
        let name = match item.rsplit_once(" as ") {
            Some((_, alias)) => alias.trim(),
            None => item.rsplit("::").next().unwrap_or(item).trim(),
        };
        (!name.is_empty() && name != "*" && name != "self" && name.chars().all(is_ident))
            .then(|| name.to_string())
    };
    match path.split_once('{') {
        Some((_, group)) => group
            .trim_end_matches('}')
            .split(',')
            .filter_map(last)
            .collect(),
        None => last(path).into_iter().collect(),
    }
}

/// `use <module>::..` statements of `src/lib.rs`, public or private: every name they import is
/// a root item that `crate::Name` reaches, owned by the module it comes from.
fn lib_imports(code: &str, modules: &[String]) -> Vec<(String, String)> {
    let mut imports = Vec::new();
    for statement in code.split(';') {
        let kept: Vec<&str> = statement
            .lines()
            .filter(|line| !line.trim_start().starts_with("#["))
            .collect();
        let text = kept.join(" ");
        let text = text.trim();
        let text = ["pub(crate) ", "pub(super) ", "pub "]
            .iter()
            .find_map(|prefix| text.strip_prefix(prefix))
            .unwrap_or(text);
        let Some(path) = text.strip_prefix("use ") else {
            continue;
        };
        let Some((module, _)) = path.split_once("::") else {
            continue;
        };
        if !modules.iter().any(|known| known == module.trim()) {
            continue;
        }
        for name in imported_names(path) {
            imports.push((name, module.trim().to_string()));
        }
    }
    imports
}

/// Root-level name -> the top-level module that defines it, for the glob re-exports of `engine`
/// and `project` and every named `use <module>::..` import of `lib.rs` (re-exported or private:
/// a private import is still reachable as `crate::Name` from every module).
pub(crate) fn root_export_modules(files: &[SourceFile]) -> BTreeMap<String, String> {
    let mut exports = BTreeMap::new();
    let modules: Vec<String> = files.iter().map(|file| file.module.clone()).collect();
    for file in files.iter().filter(|file| !file.is_test) {
        if file.module == "engine" || file.rel == "src/project.rs" {
            for name in top_level_items(&file.code) {
                exports.insert(name, file.module.clone());
            }
        }
        if file.rel == "src/lib.rs" {
            for (name, module) in lib_imports(&file.code, &modules) {
                exports.insert(name, module);
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

/// The module path of a source file: `src/parsers/jvm/pom.rs` is `[parsers, jvm, pom]`, a
/// `mod.rs` stands for its directory, and the crate roots have no path.
fn module_path(rel: &str) -> Vec<String> {
    let inside = rel.trim_start_matches("src/").trim_end_matches(".rs");
    let mut parts: Vec<String> = inside.split('/').map(str::to_string).collect();
    if parts.last().is_some_and(|last| last == "mod") {
        parts.pop();
    }
    if parts.len() == 1 && matches!(parts[0].as_str(), "lib" | "main") {
        parts.clear();
    }
    parts
}

/// First identifiers of a `{a::b, c}` group or a plain path starting at `rest`.
fn path_heads(rest: &str) -> Vec<String> {
    let ident = |text: &str| -> String { text.chars().take_while(|c| is_ident(*c)).collect() };
    let Some(group) = rest.strip_prefix('{') else {
        return vec![ident(rest)];
    };
    let (mut heads, mut depth, mut at_start) = (Vec::new(), 1, true);
    for (offset, c) in group.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            ',' if depth == 1 => at_start = true,
            c if is_ident(c) && at_start && depth == 1 => {
                heads.push(ident(&group[offset..]));
                at_start = false;
            }
            _ => {}
        }
    }
    heads
}

/// `super::super::<module>` and friends: a chain of `super` that climbs to the crate root names
/// `crate::<module>`, however deep the file sits.
pub(crate) fn super_root_targets(rel: &str, code: &str, modules: &[String]) -> Vec<String> {
    let depth = module_path(rel).len();
    if depth == 0 {
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
        let mut rest = &code[at..];
        let mut climbs = 0;
        while let Some(after) = rest.strip_prefix("super::") {
            climbs += 1;
            rest = after;
        }
        if climbs == depth {
            targets.extend(
                path_heads(rest)
                    .into_iter()
                    .filter(|name| modules.contains(name)),
            );
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
