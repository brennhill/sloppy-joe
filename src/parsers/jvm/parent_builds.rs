//! Build scripts of enclosing projects. Gradle configures the root project (and
//! every project between it and this one) before this project, and their
//! `allprojects { }` / `subprojects { }` blocks add repositories and
//! dependencies to this project; their buildscript classpath and plugins run in
//! the same build. Scanning a subproject with `--dir` must read them.

use super::*;
use std::path::PathBuf;

/// What enclosing build scripts contribute to the scanned project.
#[derive(Default)]
pub(super) struct ParentBuilds {
    /// Each enclosing build script, nearest first.
    pub scripts: Vec<(PathBuf, gradle_plugins::GradleScript)>,
    /// Dependencies their `allprojects { }` / `subprojects { }` blocks declare.
    pub deps: Vec<Dependency>,
}

/// The directory of the build this project belongs to: where the nearest
/// enclosing settings script lives. Without one the project is a standalone build.
fn build_root<'a>(
    project_dir: &'a Path,
    settings: &'a [(PathBuf, gradle_plugins::GradleScript)],
) -> &'a Path {
    settings
        .first()
        .and_then(|(path, _)| path.parent())
        .unwrap_or(project_dir)
}

pub(super) fn read_parent_builds(
    project_dir: &Path,
    boundary: &Path,
    settings: &[(PathBuf, gradle_plugins::GradleScript)],
) -> Result<ParentBuilds> {
    let mut parents = ParentBuilds::default();
    let root = build_root(project_dir, settings);
    if project_dir == root {
        return Ok(parents);
    }
    for dir in project_dir.ancestors().skip(1) {
        if !dir.starts_with(boundary) || !dir.starts_with(root) {
            break;
        }
        for filename in ["build.gradle", "build.gradle.kts"] {
            let path = dir.join(filename);
            if !super::super::path_detected(&path)? {
                continue;
            }
            let content = crate::untrusted::read_script_file(&path)?;
            let script = scan_gradle_script(&content, &path)?;
            if script.has_plugin_management {
                bail!(
                    "Unsupported Gradle plugin repository declaration in {}: pluginManagement is only valid in settings scripts",
                    path.display()
                );
            }
            parents.deps.extend(cross_project_dependencies(
                &tokenize_gradle(&content),
                &path,
            )?);
            parents.scripts.push((path, script));
        }
        if dir == root {
            break;
        }
    }
    Ok(parents)
}

/// Dependencies a parent script gives this project: those inside top-level
/// `allprojects { }` and `subprojects { }` blocks. A parent's own top-level
/// `dependencies { }` and `buildscript { }` belong to it alone; a dependency
/// declared in any other block (`project(':x') { }`, `configure(...) { }`)
/// may target this project and cannot be attributed, so it is rejected.
fn cross_project_dependencies(tokens: &[GradleToken], path: &Path) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    let mut idx = 0usize;
    while idx < tokens.len() {
        let opens_block = matches!(tokens.get(idx + 1), Some(GradleToken::Symbol('{')));
        let name = match &tokens[idx] {
            GradleToken::Ident(name) => name.as_str(),
            GradleToken::Symbol('{') => "",
            _ => {
                idx += 1;
                continue;
            }
        };
        let start = if name.is_empty() { idx } else { idx + 1 };
        if !name.is_empty() && !opens_block {
            if GRADLE_DEPENDENCY_CONFIGS.contains(&name) {
                return Err(unattributable(path));
            }
            idx += 1;
            continue;
        }
        let end = find_gradle_block_end(tokens, start).ok_or_else(|| {
            anyhow::anyhow!(
                "Broken Gradle manifest '{}': unclosed block.",
                path.display()
            )
        })?;
        let block = &tokens[start + 1..end];
        match name {
            "allprojects" | "subprojects" => deps.extend(literal_dependencies(block, path)?),
            "dependencies" | "buildscript" => {}
            _ if declares_dependencies(block) => return Err(unattributable(path)),
            _ => {}
        }
        idx = end + 1;
    }
    Ok(deps)
}

fn declares_dependencies(block: &[GradleToken]) -> bool {
    block.iter().any(|token| {
        matches!(token, GradleToken::Ident(name) if name == "dependencies"
            || GRADLE_DEPENDENCY_CONFIGS.contains(&name.as_str()))
    })
}

fn unattributable(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "Unsupported Gradle cross-project dependency in {}: dependencies declared outside a top-level dependencies {{ }}, allprojects {{ }} or subprojects {{ }} block may apply to the scanned project and cannot be attributed",
        path.display()
    )
}

/// Plugin artifacts the parent scripts request: they run in the same build.
pub(super) fn parent_plugins(
    parents: &ParentBuilds,
    boundary: &Path,
    settings: &[(PathBuf, gradle_plugins::GradleScript)],
) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    for (path, script) in &parents.scripts {
        let dir = path.parent().unwrap_or(Path::new("."));
        let enclosing: Vec<_> = settings
            .iter()
            .filter(|(settings_path, _)| {
                settings_path
                    .parent()
                    .is_some_and(|settings_dir| dir.starts_with(settings_dir))
            })
            .cloned()
            .collect();
        deps.extend(gradle_plugins::resolve_plugins(
            &gradle_plugins::PluginContext {
                build_path: path,
                project_dir: dir,
                boundary,
                build: script,
                settings: &enclosing,
            },
        )?);
    }
    Ok(deps)
}

#[cfg(test)]
#[path = "parent_builds_tests.rs"]
mod tests;
