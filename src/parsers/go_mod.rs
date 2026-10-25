use crate::Dependency;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

mod graph;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let project_dir = std::fs::canonicalize(project_dir)?;
    for ancestor in project_dir.ancestors() {
        let workspace = ancestor.join("go.work");
        if super::path_detected(&workspace)? {
            anyhow::bail!(
                "Unsupported Go workspace '{}': workspace dependency sources are not trusted yet",
                workspace.display()
            );
        }
    }
    let path = project_dir.join("go.mod");
    let content = crate::untrusted::read_line_file(&path).context("Failed to read go.mod")?;
    validate_replace_targets(&content, &path)?;

    let requirements = parse_requirements(&content);
    validate_tool_directives(&content, &requirements, &path)?;
    let mut deps = Vec::new();
    for (name, version) in requirements {
        let dep = Dependency {
            name,
            version,
            ecosystem: crate::Ecosystem::Go,
            actual_name: None,
        };
        super::validate_dependency(&dep, &path)?;
        deps.push(dep);
    }

    Ok(deps)
}

fn validate_replace_targets(content: &str, path: &Path) -> Result<()> {
    if parse_local_replace_entries(content).next().is_some() {
        anyhow::bail!(
            "Unsupported local go.mod replace target in {}: local replace directives are not trusted yet",
            path.display()
        );
    }
    if crate::untrusted::rows(content)
        .any(|line| line.trim().split([' ', '\t', '(']).next() == Some("replace"))
    {
        anyhow::bail!(
            "Unsupported remote go.mod replace target in {}: replacement module identities are not trusted yet",
            path.display()
        );
    }
    Ok(())
}

/// Go's modfile syntax allows module paths to be written as interpreted
/// ("...") or raw (`...`) strings. Strings with escapes are left quoted so
/// they fail package-name validation instead of being guessed at.
fn unquote_go_token(token: &str) -> String {
    for quote in ['"', '`'] {
        if token.len() >= 2
            && token.starts_with(quote)
            && token.ends_with(quote)
            && !token[1..token.len() - 1].contains(['"', '`', '\\'])
        {
            return token[1..token.len() - 1].to_string();
        }
    }
    token.to_string()
}

/// Collect the argument tokens of every `keyword ...` line and every line of
/// a `keyword ( ... )` block.
fn parse_directive(content: &str, keyword: &str) -> Vec<Vec<String>> {
    let mut entries = Vec::new();
    let mut in_block = false;

    for line in crate::untrusted::rows(content) {
        let line = line.split_once("//").map_or(line, |(code, _)| code).trim();
        let directive = line
            .strip_prefix(keyword)
            .filter(|rest| rest.starts_with(char::is_whitespace) || rest.starts_with('('));

        if directive.is_some_and(|rest| rest.trim() == "(") {
            in_block = true;
            continue;
        }
        if line == ")" {
            in_block = false;
            continue;
        }

        let args = match directive {
            Some(rest) => rest,
            None if in_block && !line.is_empty() => line,
            None => continue,
        };
        let tokens: Vec<String> = args.split_whitespace().map(unquote_go_token).collect();
        if !tokens.is_empty() {
            entries.push(tokens);
        }
    }

    entries
}

fn parse_requirements(content: &str) -> Vec<(String, Option<String>)> {
    parse_directive(content, "require")
        .into_iter()
        .map(|mut tokens| {
            let version = tokens.get(1).cloned();
            (tokens.swap_remove(0), version)
        })
        .collect()
}

fn module_provides(module: &str, package: &str) -> bool {
    package == module
        || package
            .strip_prefix(module)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Go 1.24 `tool` directives name packages that `go tool` builds and runs.
/// Each must come from the main module or a required module (which is then
/// checked like any other requirement); anything else cannot be verified.
fn validate_tool_directives(
    content: &str,
    requirements: &[(String, Option<String>)],
    path: &Path,
) -> Result<()> {
    let main_module = parse_directive(content, "module")
        .into_iter()
        .next()
        .and_then(|tokens| tokens.into_iter().next());
    for tokens in parse_directive(content, "tool") {
        let tool = &tokens[0];
        let provided = main_module
            .as_deref()
            .is_some_and(|module| module_provides(module, tool))
            || requirements
                .iter()
                .any(|(module, _)| module_provides(module, tool));
        if !provided {
            anyhow::bail!(
                "Unsupported go.mod tool '{}' in {}: no required module provides this tool package, so its source cannot be verified",
                crate::report::sanitize_for_terminal(tool),
                path.display()
            );
        }
    }
    Ok(())
}

/// Every required module version must have a well-formed `<version>/go.mod`
/// checksum in go.sum. Go always needs that hash, so a requirement without one
/// means go.sum was not produced by `go mod tidy` for this go.mod and Go would
/// fetch the module unverified. Local replacements are exempt; extra go.sum
/// entries (older versions kept by `go mod tidy`) are normal and ignored.
pub(crate) fn check_go_sum_entries(go_mod: &str, go_sum: &str) -> Result<()> {
    let mut hashes: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    for line in crate::untrusted::rows(go_sum).filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [module, version, hash] = fields[..] else {
            anyhow::bail!("Malformed go.sum line {line:?}: expected '<module> <version> <hash>'");
        };
        if !is_go_h1_hash(hash) {
            anyhow::bail!("Malformed go.sum hash {hash:?} for {module} {version}");
        }
        let key = (module.to_string(), version.to_string());
        if let Some(previous) = hashes.insert(key, hash.to_string())
            && previous != hash
        {
            anyhow::bail!("go.sum has conflicting hashes for {module} {version}");
        }
    }

    let local = parse_local_replace_targets(go_mod);
    let indirect = indirect_requirements(go_mod);
    let mut missing: Vec<String> = Vec::new();
    let mut unhashed: Vec<String> = Vec::new();
    for (name, version) in parse_requirements(go_mod) {
        let Some(version) = version else { continue };
        if local.contains(name.as_str()) {
            continue;
        }
        if !hashes.contains_key(&(name.clone(), format!("{version}/go.mod"))) {
            missing.push(format!("{name} {version}"));
        }
        // Modules the build imports from need the content hash too; only `// indirect` ones that
        // provide no package may have just the go.mod hash.
        if !indirect.contains(&(name.clone(), version.clone()))
            && !hashes.contains_key(&(name.clone(), version.clone()))
        {
            unhashed.push(format!("{name} {version}"));
        }
    }
    missing.sort();
    missing.dedup();
    unhashed.sort();
    unhashed.dedup();
    if !missing.is_empty() {
        return Err(crate::remedy::problem(
            &crate::remedy::GO_SUM,
            format!(
                "go.sum has no checksum for required module version(s): {}.",
                missing.join(", ")
            ),
        ));
    }
    if !unhashed.is_empty() {
        return Err(crate::remedy::problem(
            &crate::remedy::GO_SUM,
            format!(
                "go.sum has no content hash (the entry without /go.mod) for direct requirement(s): {}.",
                unhashed.join(", ")
            ),
        ));
    }
    graph::check_unlisted_modules(go_mod, go_sum)
}

/// Requirements go.mod marks `// indirect`.
fn indirect_requirements(go_mod: &str) -> HashSet<(String, String)> {
    let mut indirect = HashSet::new();
    for line in crate::untrusted::rows(go_mod) {
        let Some((code, comment)) = line.split_once("//") else {
            continue;
        };
        if comment.trim() != "indirect" && !comment.trim_start().starts_with("indirect") {
            continue;
        }
        let code = code.trim();
        let code = code.strip_prefix("require").map_or(code, str::trim);
        let tokens: Vec<String> = code.split_whitespace().map(unquote_go_token).collect();
        if let [name, version, ..] = &tokens[..] {
            indirect.insert((name.clone(), version.clone()));
        }
    }
    indirect
}

/// Go uses `vendor/` instead of the module cache by default from go 1.14 on; before that the
/// directory is ignored and go.sum still governs.
pub(crate) fn vendoring_applies(go_mod: &str) -> bool {
    let Some(version) = parse_directive(go_mod, "go")
        .into_iter()
        .next()
        .and_then(|tokens| tokens.into_iter().next())
    else {
        return false;
    };
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse::<u32>().ok());
    let minor = parts.next().and_then(|part| {
        part.trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse::<u32>()
            .ok()
    });
    matches!((major, minor), (Some(major), Some(minor)) if (major, minor) >= (1, 14))
}

/// `vendor/modules.txt` must list every required module version (`# <module> <version>`), as
/// `go mod vendor` writes it. While vendoring is in effect Go ignores go.sum, so this list is
/// what ties the vendored code to go.mod; a vendor directory that does not cover go.mod is not
/// a substitute for go.sum.
pub(crate) fn check_vendor_modules(go_mod: &str, modules_txt: &str) -> Result<()> {
    let mut vendored: HashSet<(String, String)> = HashSet::new();
    for line in crate::untrusted::rows(modules_txt) {
        let Some(rest) = line.strip_prefix("# ") else {
            continue;
        };
        let rest = rest.split(" => ").next().unwrap_or(rest);
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if let [name, version, ..] = fields[..] {
            vendored.insert((name.to_string(), version.to_string()));
        }
    }
    let local = parse_local_replace_targets(go_mod);
    let mut missing: Vec<String> = parse_requirements(go_mod)
        .into_iter()
        .filter(|(name, _)| !local.contains(name.as_str()))
        .filter_map(|(name, version)| {
            let version = version?;
            (!vendored.contains(&(name.clone(), version.clone())))
                .then(|| format!("{name} {version}"))
        })
        .collect();
    missing.sort();
    missing.dedup();
    if !missing.is_empty() {
        anyhow::bail!(
            "vendor/modules.txt does not list required module version(s): {}. Fix: run `go mod vendor` so the vendor directory matches go.mod.",
            missing.join(", ")
        );
    }
    graph::check_unlisted_vendored(go_mod, &vendored)
}

/// `h1:` followed by a 44-character standard base64 SHA-256 digest.
fn is_go_h1_hash(hash: &str) -> bool {
    let Some(digest) = hash.strip_prefix("h1:") else {
        return false;
    };
    digest.len() == 44
        && digest.ends_with('=')
        && digest[..43]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

pub(crate) fn requires_go_sum(content: &str) -> bool {
    let required: HashSet<String> = parse_requirements(content)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    if required.is_empty() {
        return false;
    }

    let local_replacements = parse_local_replace_targets(content);
    required
        .iter()
        .any(|dep| !local_replacements.contains(dep.as_str()))
}

fn parse_local_replace_targets(content: &str) -> HashSet<String> {
    parse_local_replace_entries(content)
        .map(|(module, _)| module)
        .collect()
}

fn parse_local_replace_entries(content: &str) -> impl Iterator<Item = (String, String)> + '_ {
    let mut replacements = HashSet::new();
    let mut in_replace = false;

    for line in crate::untrusted::rows(content) {
        let line = line.trim();
        if line == "replace (" {
            in_replace = true;
            continue;
        }
        if line == ")" {
            in_replace = false;
            continue;
        }

        if let Some(rest) = line.strip_prefix("replace ") {
            if let Some((module, target)) = parse_local_replace_entry(rest) {
                replacements.insert((module, target));
            }
            continue;
        }

        if in_replace
            && !line.is_empty()
            && !line.starts_with("//")
            && let Some((module, target)) = parse_local_replace_entry(line)
        {
            replacements.insert((module, target));
        }
    }

    replacements.into_iter()
}

fn parse_local_replace_entry(entry: &str) -> Option<(String, String)> {
    let (left, right) = entry.split_once("=>")?;
    let old_module = left.split_whitespace().next()?.to_string();
    let right_tokens: Vec<&str> = right.split_whitespace().collect();
    if right_tokens.len() == 1 && is_local_replace_target(right_tokens[0]) {
        return Some((old_module, right_tokens[0].to_string()));
    }
    if let Some(path) = right_tokens.first()
        && is_local_replace_target(path)
    {
        return Some((old_module, (*path).to_string()));
    }
    None
}

fn is_local_replace_target(path: &str) -> bool {
    path.starts_with("./") || path.starts_with("../") || path.starts_with('/')
}

#[cfg(test)]
#[path = "go_sum_tests.rs"]
mod go_sum_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_dir(content: &str) -> std::path::PathBuf {
        setup_test_dir("gomod", "go.mod", content)
    }

    #[test]
    fn a_lone_cr_cannot_hide_go_mod_directives() {
        for body in [
            "replace\rgithub.com/google/uuid => github.com/attacker/uuid v1.6.0\n",
            "replace\r(\ngithub.com/google/uuid => github.com/attacker/uuid v1.6.0\n)\n",
            "require\rgithub.com/google/uuid v1.6.0\n",
        ] {
            let content = format!("module example.com/app\n\ngo 1.21\n\n{body}");
            let dir = setup_dir(&content);
            assert!(parse(&dir).is_err(), "{body:?}");
        }
    }

    #[test]
    fn parse_whitespace_variants_of_require_directives() {
        for requirement in [
            "require\tgithub.com/gin-gonic/gin v1.9.1",
            "require\t(\n github.com/gin-gonic/gin v1.9.1\n)",
            "require(\n github.com/gin-gonic/gin v1.9.1\n)",
            "require ( // module requirements\n github.com/gin-gonic/gin v1.9.1\n) // end",
        ] {
            let dir = setup_dir(&format!("module example.com/app\n{requirement}\n"));
            let deps = parse(&dir).unwrap();
            assert_eq!(deps.len(), 1);
            assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
            assert!(requires_go_sum(
                &std::fs::read_to_string(dir.join("go.mod")).unwrap()
            ));
            cleanup(&dir);
        }
    }

    #[test]
    fn parse_require_block() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/spf13/cobra v1.7.0
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, Some("v1.9.1".to_string()));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Go);
        assert_eq!(deps[1].name, "github.com/spf13/cobra");
        cleanup(&dir);
    }

    #[test]
    fn skip_module_and_go_version() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        // module and go lines should not appear as deps
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        cleanup(&dir);
    }

    #[test]
    fn handle_empty_require_block() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert!(deps.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn skip_comments_in_require_block() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
	// indirect dependency
	github.com/gin-gonic/gin v1.9.1
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        cleanup(&dir);
    }

    #[test]
    fn indirect_comments_cannot_hide_required_modules() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/spf13/cobra v1.7.0 // indirect
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[1].name, "github.com/spf13/cobra");
        cleanup(&dir);
    }

    #[test]
    fn parse_single_line_require() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, Some("v1.9.1".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn go_sum_required_for_indirect_external_dependencies() {
        let content = r#"
module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1 // indirect
)
"#;
        assert!(requires_go_sum(content));
    }

    #[test]
    fn go_sum_required_for_external_dependencies() {
        let content = r#"
module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
"#;
        assert!(requires_go_sum(content));
    }

    #[test]
    fn go_sum_not_required_for_stdlib_only_modules() {
        let content = "module example.com/myapp\n\ngo 1.21\n";
        assert!(!requires_go_sum(content));
    }

    #[test]
    fn go_sum_not_required_when_all_dependencies_are_local_replaces() {
        let content = r#"
module example.com/myapp

go 1.21

require (
    example.com/localdep v0.0.0
)

replace example.com/localdep => ../localdep
"#;
        assert!(!requires_go_sum(content));
    }

    #[test]
    fn go_sum_required_when_replace_rhs_is_remote_module() {
        let content = r#"
module example.com/myapp

go 1.21

require example.com/a v1.2.3

replace example.com/a => example.com/b
"#;
        assert!(requires_go_sum(content));
    }

    #[test]
    fn reject_ancestor_go_work_that_can_replace_dependencies() {
        let dir = setup_dir("module example.com/app\nrequire github.com/gin-gonic/gin v1.9.1\n");
        let child = dir.join("app");
        std::fs::create_dir(&child).unwrap();
        std::fs::rename(dir.join("go.mod"), child.join("go.mod")).unwrap();
        std::fs::write(dir.join("go.work"), "go 1.21\nuse ./app\nreplace github.com/gin-gonic/gin => github.com/attacker/payload v1.0.0\n").unwrap();
        let err = parse(&child).expect_err("workspace sources must not escape module policy");
        assert!(err.to_string().contains("go.work"));
        cleanup(&dir);
    }

    #[test]
    fn reject_remote_replace_targets() {
        for replacement in [
            "replace github.com/gin-gonic/gin => github.com/attacker/payload v1.0.0",
            "replace (\n github.com/gin-gonic/gin => github.com/attacker/payload v1.0.0\n)",
        ] {
            let dir = setup_dir(&format!(
                "module example.com/app\nrequire github.com/gin-gonic/gin v1.9.1\n{replacement}\n"
            ));
            let err =
                parse(&dir).expect_err("remote replacements must not scan the original identity");
            assert!(err.to_string().contains("replace target"));
            cleanup(&dir);
        }
    }

    #[test]
    fn reject_local_replace_targets() {
        let dir = setup_dir(
            r#"
module example.com/myapp

require github.com/acme/lib v1.2.3

replace github.com/acme/lib => ../local-lib
"#,
        );
        let err = parse(&dir).expect_err("local go replace targets must fail closed");
        assert!(
            err.to_string()
                .contains("Unsupported local go.mod replace target")
        );
        cleanup(&dir);
    }
}

#[cfg(test)]
mod directive_tests {
    use super::*;
    use crate::parsers::test_utils::*;

    #[test]
    fn accept_quoted_module_and_require_paths() {
        let dir = setup_test_dir(
            "gomod",
            "go.mod",
            "module \"example.com/app\"\n\ngo 1.22\n\nrequire \"github.com/gin-gonic/gin\" v1.9.1\nrequire (\n\t`golang.org/x/text` v0.14.0 // indirect\n)\n",
        );
        let deps = parse(&dir).unwrap();
        let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
        assert_eq!(names, vec!["github.com/gin-gonic/gin", "golang.org/x/text"]);
        assert_eq!(deps[0].version.as_deref(), Some("v1.9.1"));
        cleanup(&dir);
    }

    #[test]
    fn tool_directives_must_be_provided_by_required_or_main_modules() {
        let ok = setup_test_dir(
            "gomod",
            "go.mod",
            "module example.com/app\n\ngo 1.24\n\ntool golang.org/x/tools/cmd/stringer\ntool (\n\texample.com/app/cmd/gen\n\t\"github.com/acme/tool\"\n)\n\nrequire (\n\tgolang.org/x/tools v0.30.0 // indirect\n\tgithub.com/acme/tool v1.0.0\n)\n",
        );
        let names: Vec<String> = parse(&ok)
            .unwrap()
            .into_iter()
            .map(|dep| dep.name)
            .collect();
        assert_eq!(names, vec!["golang.org/x/tools", "github.com/acme/tool"]);
        cleanup(&ok);

        for go_mod in [
            "module example.com/app\n\ntool github.com/evil/tool/cmd/x\n",
            "module example.com/app\n\ntool (\n\tgithub.com/evil/tool\n)\nrequire github.com/evil/toolkit v1.0.0\n",
        ] {
            let dir = setup_test_dir("gomod", "go.mod", go_mod);
            let err = parse(&dir).expect_err(&format!("unbacked tool must fail closed: {go_mod}"));
            assert!(err.to_string().contains("tool"), "{err}");
            cleanup(&dir);
        }
    }
}
