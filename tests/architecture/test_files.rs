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

/// Relative paths of the files that only exist in test builds.
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
            return tests;
        }
    }
}
