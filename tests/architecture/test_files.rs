//! Which source files are compiled only for tests. A file is test-only when a
//! `#[cfg(test)] mod name;` declaration pulls it in (or a test-only file declares it), never
//! because of what it is called: `engine/leak_tests.rs` declared with a plain `mod` is production.

use super::*;
use std::collections::BTreeSet;

struct Declaration {
    name: String,
    path_attr: Option<String>,
    cfg_test: bool,
}

/// The `mod name;` declarations of one file with whether a `#[cfg(test)]` attribute applies.
fn declarations(raw: &str) -> Vec<Declaration> {
    let stripped = strip(raw);
    let raw_lines: Vec<&str> = raw.lines().collect();
    let mut found = Vec::new();
    let mut cfg_test = false;
    for line in stripped.lines() {
        let line = line.trim();
        if line.starts_with("#[") {
            cfg_test |= line.replace(' ', "").starts_with("#[cfg(test)]");
            continue;
        }
        let item = line
            .strip_prefix("pub")
            .map(|rest| {
                let rest = rest.trim_start();
                if rest.starts_with('(') {
                    rest.split_once(')').map_or(rest, |(_, after)| after)
                } else {
                    rest
                }
            })
            .unwrap_or(line)
            .trim_start();
        if let Some(name) = item
            .strip_prefix("mod ")
            .and_then(|rest| rest.strip_suffix(';'))
        {
            let name = name.trim().to_string();
            // The attribute's string is blanked in the stripped text; read it from the source.
            let path_attr = raw_lines
                .iter()
                .position(|l| l.contains(&format!("mod {name};")))
                .and_then(|at| at.checked_sub(2).map(|from| &raw_lines[from..at]))
                .and_then(|lines| {
                    lines.iter().rev().find_map(|l| {
                        let l = l.trim();
                        let value = l.strip_prefix("#[path")?.split('"').nth(1)?;
                        Some(value.to_string())
                    })
                });
            found.push(Declaration {
                name,
                path_attr,
                cfg_test,
            });
        }
        cfg_test = false;
    }
    found
}

/// The files `mod name;` in `parent` may refer to.
fn candidates(parent: &str, declaration: &Declaration) -> Vec<String> {
    let (dir, file) = parent.rsplit_once('/').unwrap_or(("", parent));
    if let Some(path) = &declaration.path_attr {
        return vec![format!("{dir}/{path}")];
    }
    let base = if matches!(file, "mod.rs" | "lib.rs" | "main.rs") {
        dir.to_string()
    } else {
        format!("{dir}/{}", file.trim_end_matches(".rs"))
    };
    vec![
        format!("{base}/{}.rs", declaration.name),
        format!("{base}/{}/mod.rs", declaration.name),
    ]
}

/// Files compiled into the production crate: everything reachable from a crate root through
/// declarations that carry no `#[cfg(test)]`.
fn production_files(decls: &[(&String, Vec<Declaration>)]) -> BTreeSet<String> {
    let mut production: BTreeSet<String> = decls
        .iter()
        .map(|(rel, _)| (*rel).clone())
        .filter(|rel| rel == "src/lib.rs" || rel == "src/main.rs" || rel.starts_with("src/bin/"))
        .collect();
    loop {
        let before = production.len();
        for (rel, list) in decls {
            if !production.contains(*rel) {
                continue;
            }
            for declaration in list.iter().filter(|d| !d.cfg_test) {
                production.extend(candidates(rel, declaration));
            }
        }
        if production.len() == before {
            return production;
        }
    }
}

/// Relative paths of the files that only exist in test builds. A file that production code also
/// declares is production, even when a `#[cfg(test)] #[path]` module includes it again.
pub(crate) fn test_only_files(sources: &[(String, String)]) -> BTreeSet<String> {
    let decls: Vec<(&String, Vec<Declaration>)> = sources
        .iter()
        .map(|(rel, raw)| (rel, declarations(raw)))
        .collect();
    let mut tests = BTreeSet::new();
    loop {
        let before = tests.len();
        for (rel, list) in &decls {
            let parent_is_test = tests.contains(*rel);
            for declaration in list {
                if parent_is_test || declaration.cfg_test {
                    tests.extend(candidates(rel, declaration));
                }
            }
        }
        if tests.len() == before {
            let production = production_files(&decls);
            tests.retain(|file| !production.contains(file));
            return tests;
        }
    }
}

/// `#[cfg(test)] #[path = ".."] mod x;` that points at a file another declaration also uses:
/// the production module and its test alias would share one file.
pub(crate) fn shared_test_path_violations(sources: &[(String, String)]) -> Vec<String> {
    let decls: Vec<(&String, Vec<Declaration>)> = sources
        .iter()
        .map(|(rel, raw)| (rel, declarations(raw)))
        .collect();
    let mut violations = Vec::new();
    for (rel, list) in &decls {
        for declaration in list.iter().filter(|d| d.cfg_test && d.path_attr.is_some()) {
            let targets = candidates(rel, declaration);
            let shared = decls.iter().any(|(other, others)| {
                others.iter().any(|d| {
                    let same = std::ptr::eq(d, declaration);
                    !(same || d.cfg_test && d.path_attr.is_some())
                        && candidates(other, d).iter().any(|c| targets.contains(c))
                })
            });
            if shared {
                violations.push(format!(
                    "{rel} aliases a file that another module declaration also uses (`mod {}`); a test-only alias must not share production files",
                    declaration.name
                ));
            }
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(rel: &str, code: &str) -> (String, String) {
        (rel.to_string(), code.to_string())
    }

    fn leak_tree() -> Vec<(String, String)> {
        vec![
            src(
                "src/lib.rs",
                "mod engine;
",
            ),
            src(
                "src/engine/mod.rs",
                "mod leak;
#[cfg(test)]
#[path = \"leak.rs\"]\nmod leak_tests;\n",
            ),
            src("src/engine/leak.rs", ""),
        ]
    }

    #[test]
    fn a_production_file_is_not_test_only_because_a_test_alias_includes_it() {
        let tests = test_only_files(&leak_tree());
        assert!(!tests.contains("src/engine/leak.rs"));
        assert_eq!(shared_test_path_violations(&leak_tree()).len(), 1);
    }

    #[test]
    fn a_test_only_path_module_with_its_own_file_is_fine() {
        let tree = vec![
            src("src/lib.rs", "mod engine;\n"),
            src(
                "src/engine/mod.rs",
                "#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod x_tests;\n",
            ),
            src("src/engine/x_tests.rs", ""),
        ];
        assert!(test_only_files(&tree).contains("src/engine/x_tests.rs"));
        assert!(shared_test_path_violations(&tree).is_empty());
    }

    #[test]
    fn the_real_tree_has_no_shared_test_aliases() {
        let root = repo_root();
        let mut paths = Vec::new();
        collect_rs(&root.join("src"), &mut paths);
        let raw: Vec<(String, String)> = paths
            .iter()
            .map(|path| {
                let rel = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                (rel, std::fs::read_to_string(path).unwrap())
            })
            .collect();
        let violations = shared_test_path_violations(&raw);
        assert!(violations.is_empty(), "{}", violations.join("\n"));
    }

    #[test]
    fn an_alias_injected_into_the_real_engine_is_caught() {
        let root = repo_root();
        let mut paths = Vec::new();
        collect_rs(&root.join("src"), &mut paths);
        let mut raw: Vec<(String, String)> = paths
            .iter()
            .map(|path| {
                let rel = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                (rel, std::fs::read_to_string(path).unwrap())
            })
            .collect();
        for (rel, code) in raw.iter_mut() {
            if rel == "src/engine/mod.rs" {
                code.push_str("\n#[cfg(test)]\n#[path = \"scan.rs\"]\nmod scan_alias_tests;\n");
            }
        }
        assert!(!test_only_files(&raw).contains("src/engine/scan.rs"));
        assert_eq!(shared_test_path_violations(&raw).len(), 1);
    }
}
