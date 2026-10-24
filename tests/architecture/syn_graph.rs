//! A second, independent check of layer direction. The text scanner in `roots.rs` matches source
//! text; this one parses every production file with `syn` and resolves `use` trees, aliases,
//! `self::`/`super::` chains, globs, crate-root re-exports and macro token streams itself. The
//! baseline lists no layer edge, so both must report none: a bypass has to fool two unrelated
//! implementations.

use super::{layer_may_depend_on, layer_of, repo_root};
use proc_macro2::TokenTree;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use syn::visit::Visit;

/// One production file: where it sits in the module tree and its parsed syntax.
struct Unit {
    rel: String,
    /// `["parsers", "jvm"]` for `src/parsers/jvm.rs`; empty for `lib.rs` and `main.rs`.
    module: Vec<String>,
    /// The crate root itself (`lib` or `main`), whose bare `x::` paths name child modules.
    root_name: Option<String>,
    ast: syn::File,
}

impl Unit {
    fn top(&self) -> String {
        self.module
            .first()
            .cloned()
            .or_else(|| self.root_name.clone())
            .unwrap_or_default()
    }
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| meta.path().is_ident("test"))
    })
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::ExternCrate(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::ForeignMod(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::TraitAlias(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        syn::Item::Union(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

// ------------------------------------------------------------ module tree

/// Parse `src/lib.rs` and `src/main.rs` and every file they reach through `mod x;`, skipping
/// `#[cfg(test)]` modules.
fn load_units(src: &Path) -> Vec<Unit> {
    let mut units = Vec::new();
    for root in ["lib", "main"] {
        let path = src.join(format!("{root}.rs"));
        if path.exists() {
            load_file(src, &path, Vec::new(), Some(root.to_string()), &mut units);
        }
    }
    units
}

fn load_file(
    src: &Path,
    path: &Path,
    module: Vec<String>,
    root_name: Option<String>,
    units: &mut Vec<Unit>,
) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let ast = syn::parse_file(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // `x/mod.rs`, `lib.rs` and `main.rs` own their directory; `x.rs` owns `x/`.
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let dir = if root_name.is_some() || stem == "mod" {
        path.parent().unwrap().to_path_buf()
    } else {
        path.with_extension("")
    };
    let mut children = Vec::new();
    collect_file_mods(&ast.items, &mut Vec::new(), &mut children);
    let rel = path
        .strip_prefix(src.parent().unwrap())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    units.push(Unit {
        rel,
        module: module.clone(),
        root_name,
        ast,
    });
    for (inline_path, name) in children {
        let child_dir = inline_path.iter().fold(dir.clone(), |d, seg| d.join(seg));
        let file = [
            child_dir.join(format!("{name}.rs")),
            child_dir.join(&name).join("mod.rs"),
        ]
        .into_iter()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| panic!("module {name} of {} has no file", path.display()));
        let mut child_module = module.clone();
        child_module.extend(inline_path);
        child_module.push(name);
        load_file(src, &file, child_module, None, units);
    }
}

/// `mod name;` declarations (not `#[cfg(test)]`), with the inline modules enclosing them.
fn collect_file_mods(
    items: &[syn::Item],
    inline: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, String)>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if is_cfg_test(&module.attrs) {
            continue;
        }
        match &module.content {
            None => out.push((inline.clone(), module.ident.to_string())),
            Some((_, inner)) => {
                inline.push(module.ident.to_string());
                collect_file_mods(inner, inline, out);
                inline.pop();
            }
        }
    }
}

// ------------------------------------------------------------ crate root items

/// Names that `crate::Name` reaches without a module segment: items defined in the root file and
/// names the root file imports (`pub(crate) use engine::*` re-exports every item of `engine`).
fn root_items(units: &[Unit], tops: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut owners: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for unit in units {
        owners
            .entry(unit.top())
            .or_default()
            .extend(defined_names(&unit.ast.items));
    }
    let mut exports = BTreeMap::new();
    for unit in units
        .iter()
        .filter(|u| u.root_name.as_deref() == Some("lib"))
    {
        // Items the root file defines (`Dependency`, `ScanOptions`) belong to no layer: they are
        // the shared vocabulary every module may use, so they are not exports of any module.
        for item in &unit.ast.items {
            if let syn::Item::Use(u) = item {
                let mut flat = Vec::new();
                flatten_use(&u.tree, &mut Vec::new(), &mut flat);
                for (alias, path, glob) in flat {
                    let Some(owner) = path.first().filter(|f| tops.contains(*f)) else {
                        continue;
                    };
                    if glob {
                        for name in owners.get(owner).into_iter().flatten() {
                            exports.entry(name.clone()).or_insert(owner.clone());
                        }
                    } else if let Some(alias) = alias {
                        exports.insert(alias, owner.clone());
                    }
                }
            }
        }
    }
    exports
}

fn defined_names(items: &[syn::Item]) -> Vec<String> {
    items
        .iter()
        .filter(|item| !is_cfg_test(item_attrs(item)))
        .filter_map(|item| match item {
            syn::Item::Fn(i) => Some(i.sig.ident.to_string()),
            syn::Item::Struct(i) => Some(i.ident.to_string()),
            syn::Item::Enum(i) => Some(i.ident.to_string()),
            syn::Item::Const(i) => Some(i.ident.to_string()),
            syn::Item::Static(i) => Some(i.ident.to_string()),
            syn::Item::Type(i) => Some(i.ident.to_string()),
            syn::Item::Trait(i) => Some(i.ident.to_string()),
            _ => None,
        })
        .collect()
}

// ------------------------------------------------------------ use trees

/// `(alias, absolute-ish path, is_glob)` for each leaf of a `use` tree. A leaf renamed with `as _`
/// or `use x::{self}` still names its path.
fn flatten_use(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    out: &mut Vec<(Option<String>, Vec<String>, bool)>,
) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            flatten_use(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let ident = n.ident.to_string();
            let mut path = prefix.clone();
            let alias = if ident == "self" {
                prefix.last().cloned()
            } else {
                path.push(ident.clone());
                Some(ident)
            };
            out.push((alias, path, false));
        }
        syn::UseTree::Rename(r) => {
            let mut path = prefix.clone();
            if r.ident != "self" {
                path.push(r.ident.to_string());
            }
            out.push((Some(r.rename.to_string()), path, false));
        }
        syn::UseTree::Glob(_) => out.push((None, prefix.clone(), true)),
        syn::UseTree::Group(g) => {
            for inner in &g.items {
                flatten_use(inner, prefix, out);
            }
        }
    }
}

// ------------------------------------------------------------ resolution

struct Resolver<'a> {
    tops: &'a BTreeSet<String>,
    root_items: &'a BTreeMap<String, String>,
}

struct Scope {
    module: Vec<String>,
    is_root: bool,
    aliases: BTreeMap<String, Vec<String>>,
    /// `use crate::*` or `use super::*` at the crate root: bare root item names are in scope.
    root_glob: bool,
}

impl Resolver<'_> {
    /// The top-level module a path points into, if it points into the crate at all.
    fn resolve(&self, segs: &[String], scope: &Scope, depth: usize) -> Option<String> {
        let first = segs.first()?;
        if depth > 8 {
            return None;
        }
        match first.as_str() {
            "crate" => self.root_target(&segs[1..]),
            "self" => match scope.module.first() {
                Some(top) => Some(top.clone()),
                None => self.root_target(&segs[1..]),
            },
            "super" => {
                let ups = segs.iter().take_while(|s| *s == "super").count();
                let base = scope.module.len().checked_sub(ups)?;
                match scope.module.first().filter(|_| base > 0) {
                    Some(top) => Some(top.clone()),
                    None => self.root_target(&segs[ups..]),
                }
            }
            name => {
                if let Some(target) = scope.aliases.get(name) {
                    let mut full = target.clone();
                    full.extend_from_slice(&segs[1..]);
                    return self.resolve(&full, scope, depth + 1);
                }
                if scope.is_root && self.tops.contains(name) {
                    return Some(name.to_string());
                }
                if scope.root_glob {
                    return self.root_items.get(name).cloned();
                }
                None
            }
        }
    }

    /// `rest` is the part of a `crate::..` path after `crate`.
    fn root_target(&self, rest: &[String]) -> Option<String> {
        let first = rest.first()?;
        if self.tops.contains(first) {
            return Some(first.clone());
        }
        self.root_items.get(first).cloned()
    }
}

// ------------------------------------------------------------ visitor

struct Edges<'a> {
    resolver: &'a Resolver<'a>,
    scope: Scope,
    from: String,
    found: BTreeSet<(String, Vec<String>)>,
}

impl Edges<'_> {
    fn record(&mut self, segs: &[String]) {
        if let Some(target) = self.resolver.resolve(segs, &self.scope, 0)
            && target != self.from
        {
            self.found.insert((target, segs.to_vec()));
        }
    }

    fn scan_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        let flat: Vec<TokenTree> = flatten_tokens(tokens);
        let mut i = 0;
        while i < flat.len() {
            let TokenTree::Ident(first) = &flat[i] else {
                i += 1;
                continue;
            };
            let mut segs = vec![first.to_string()];
            let mut j = i + 1;
            while j + 2 < flat.len()
                && matches!(&flat[j], TokenTree::Punct(p) if p.as_char() == ':')
                && matches!(&flat[j + 1], TokenTree::Punct(p) if p.as_char() == ':')
                && let TokenTree::Ident(next) = &flat[j + 2]
            {
                segs.push(next.to_string());
                j += 3;
            }
            if segs.len() > 1 {
                self.record(&segs);
            }
            i = j.max(i + 1);
        }
    }
}

fn flatten_tokens(tokens: proc_macro2::TokenStream) -> Vec<TokenTree> {
    let mut out = Vec::new();
    for tree in tokens {
        match tree {
            TokenTree::Group(group) => out.extend(flatten_tokens(group.stream())),
            other => out.push(other),
        }
    }
    out
}

impl<'ast> Visit<'ast> for Edges<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !is_cfg_test(item_attrs(item)) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if let Some((_, items)) = &module.content {
            self.scope.module.push(module.ident.to_string());
            for item in items {
                self.visit_item(item);
            }
            self.scope.module.pop();
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut flat = Vec::new();
        flatten_use(&item.tree, &mut Vec::new(), &mut flat);
        for (_, path, _) in &flat {
            self.record(path);
        }
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        // A bare identifier in expression position is a local or a unit value; only a call
        // (`visit_expr_call`) or a type position names a root item.
        if expr.path.segments.len() == 1 && expr.qself.is_none() {
            for segment in &expr.path.segments {
                syn::visit::visit_path_arguments(self, &segment.arguments);
            }
        } else {
            syn::visit::visit_expr_path(self, expr);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(func) = &*call.func
            && func.path.segments.len() == 1
        {
            let segs: Vec<String> = func
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            self.record(&segs);
            for segment in &func.path.segments {
                syn::visit::visit_path_arguments(self, &segment.arguments);
            }
        } else {
            self.visit_expr(&call.func);
        }
        for arg in &call.args {
            self.visit_expr(arg);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.record(&segs);
        syn::visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let segs: Vec<String> = mac
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        self.record(&segs);
        self.scan_tokens(mac.tokens.clone());
    }
}

/// Collect the alias table of a file from every `use` in it (including inside inline modules).
fn scope_of(unit: &Unit) -> Scope {
    struct Uses {
        aliases: BTreeMap<String, Vec<String>>,
        root_glob: bool,
    }
    impl<'ast> Visit<'ast> for Uses {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            if !is_cfg_test(item_attrs(item)) {
                syn::visit::visit_item(self, item);
            }
        }
        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            let mut flat = Vec::new();
            flatten_use(&item.tree, &mut Vec::new(), &mut flat);
            for (alias, path, glob) in flat {
                if glob && path == ["crate"] {
                    self.root_glob = true;
                } else if let Some(alias) = alias.filter(|a| a != "_") {
                    self.aliases.insert(alias, path);
                }
            }
        }
    }
    let mut uses = Uses {
        aliases: BTreeMap::new(),
        root_glob: false,
    };
    uses.visit_file(&unit.ast);
    // `use super::*` in a depth-1 file imports the crate root.
    if unit.module.len() == 1 && has_super_glob(&unit.ast) {
        uses.root_glob = true;
    }
    Scope {
        module: unit.module.clone(),
        is_root: unit.root_name.is_some(),
        aliases: uses.aliases,
        root_glob: uses.root_glob || unit.root_name.is_some(),
    }
}

fn has_super_glob(file: &syn::File) -> bool {
    file.items.iter().any(|item| {
        let syn::Item::Use(u) = item else {
            return false;
        };
        let mut flat = Vec::new();
        flatten_use(&u.tree, &mut Vec::new(), &mut flat);
        flat.iter()
            .any(|(_, path, glob)| *glob && *path == ["super"])
    })
}

// ------------------------------------------------------------ analysis

/// `file -> target (path)` for every cross-module reference the layer table forbids.
fn violations(units: &[Unit]) -> Vec<String> {
    let tops: BTreeSet<String> = units
        .iter()
        .filter_map(|u| u.module.first().cloned())
        .collect();
    let exports = root_items(units, &tops);
    let resolver = Resolver {
        tops: &tops,
        root_items: &exports,
    };
    let mut out = BTreeSet::new();
    for unit in units {
        let from = unit.top();
        let Some(from_layer) = layer_of(&from) else {
            continue;
        };
        let mut edges = Edges {
            resolver: &resolver,
            scope: scope_of(unit),
            from: from.clone(),
            found: BTreeSet::new(),
        };
        edges.visit_file(&unit.ast);
        for (target, path) in edges.found {
            let Some(to_layer) = layer_of(&target) else {
                continue;
            };
            if !layer_may_depend_on(from_layer, to_layer) {
                out.insert(format!(
                    "{} -> {} (via {})",
                    unit.rel,
                    target,
                    path.join("::")
                ));
            }
        }
    }
    out.into_iter().collect()
}

fn units_from_sources(files: &[(&str, &[&str], &str)]) -> Vec<Unit> {
    files
        .iter()
        .map(|(rel, module, text)| Unit {
            rel: rel.to_string(),
            module: module.iter().map(|s| s.to_string()).collect(),
            root_name: module.is_empty().then(|| "lib".to_string()),
            ast: syn::parse_file(text).unwrap(),
        })
        .collect()
}

#[test]
fn syn_graph_finds_no_layer_violation() {
    let src = repo_root().join("src");
    let units = load_units(&src);
    assert!(
        units.len() > 100,
        "module tree walk found only {} files",
        units.len()
    );
    let found = violations(&units);
    assert!(
        found.is_empty(),
        "layer violations found by the syn oracle:\n{}",
        found.join("\n")
    );
}

#[cfg(test)]
mod oracle_tests {
    use super::*;

    /// A tiny crate: lib.rs declares `parsers` (parsers layer) and `registry` (registry layer),
    /// which may not depend on each other. `parsers/x.rs` is the file under test.
    fn check(body: &str) -> Vec<String> {
        let lib = "mod parsers; mod registry; pub(crate) use registry::*;\n";
        let registry = "pub(crate) fn fetch() {}\npub(crate) struct Client;\n";
        let units = units_from_sources(&[
            ("src/lib.rs", &[], lib),
            ("src/registry.rs", &["registry"], registry),
            ("src/parsers.rs", &["parsers"], ""),
            ("src/parsers/x.rs", &["parsers", "x"], body),
        ]);
        violations(&units)
    }

    #[test]
    fn direct_and_use_paths_are_found() {
        assert_eq!(check("fn f() { crate::registry::fetch(); }").len(), 1);
        assert_eq!(check("use crate::registry::Client;").len(), 1);
    }

    #[test]
    fn aliases_groups_and_renames_are_followed() {
        let found = |body: &str| !check(body).is_empty();
        assert!(found("use crate::registry as r; fn f() { r::fetch(); }"));
        assert!(found("use crate::{registry::{self, Client}, parsers};"));
        assert!(found(
            "use crate::registry::fetch as get; fn f() { get(); }"
        ));
        // The alias alone, without the `use` line being the offender, still resolves.
        assert!(found("fn f() { use crate::registry as r; r::fetch(); }"));
    }

    #[test]
    fn super_chains_and_root_reexports_are_followed() {
        assert_eq!(
            check("fn f() { super::super::registry::fetch(); }").len(),
            1
        );
        assert_eq!(check("fn f() { crate::fetch(); }").len(), 1);
        assert_eq!(check("use crate::*; fn f() { fetch(); }").len(), 1);
    }

    #[test]
    fn macro_arguments_are_scanned() {
        assert_eq!(
            check("fn f() { let _ = format!(\"{}\", crate::registry::fetch()); }").len(),
            1
        );
        assert_eq!(
            check("macro_rules! m { () => { crate::registry::fetch() } }").len(),
            1
        );
    }

    #[test]
    fn test_modules_and_same_layer_paths_are_ignored() {
        assert!(check("#[cfg(test)] mod t { fn f() { crate::registry::fetch(); } }").is_empty());
        assert!(check("fn f() { crate::parsers::helper(); super::helper(); }").is_empty());
        assert!(check("use std::collections::HashMap; fn f() { std::mem::drop(1); }").is_empty());
    }
}
