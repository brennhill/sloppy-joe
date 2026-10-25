//! `fix-lockfile` for JavaScript projects (docs/specs/fix-lockfile.md): npm, pnpm, Bun and Yarn
//! Berry lockfile-only installs with scripts off, the Bun binary-lockfile conversion, and removal
//! of a shadow lockfile under a workspace member. Yarn Classic is guided; dependency rewrites are
//! a decision.

use super::*;
use crate::ecosystems::fixer::{
    EnvValue, FixCtx, FixPlan, OldSnapshot, Problem, Recipe, Refusal, Snapshot, literal_env,
};
use crate::remedy::{self, Remedy};

/// `.npmrc` settings that run code, pick a binary, or relocate what the scratch copy controls.
const NPMRC_DENIED: &[&str] = &[
    "script-shell",
    "node-options",
    "onload-script",
    "init-module",
    "git",
    "shell",
    "pnpmfile",
    "global-pnpmfile",
    "ignore-pnpmfile",
    "ignore-scripts",
    "allow-scripts",
    "dangerously-allow-all-scripts",
    "node-gyp",
    "use-node-version",
    "node-version",
    "manage-package-manager-versions",
    "globalconfig",
    "userconfig",
    "prefix",
    "cache",
    "store-dir",
];

/// `pnpm-workspace.yaml` settings that run code or rewrite dependencies.
const PNPM_WORKSPACE_DENIED: &[&str] = &[
    "pnpmfile",
    "pnpmfilePath",
    "globalPnpmfile",
    "configDependencies",
    "useNodeVersion",
    "patchedDependencies",
    "overrides",
    "packageExtensions",
    "executionEnv",
];

/// Dependency specifiers that make the install fetch and prepare code, or read files the scratch
/// copy does not hold.
const SPEC_PREFIXES_REFUSED: &[&str] = &[
    "git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:", "http:", "https:",
    "exec:", "patch:", "file:", "link:", "portal:",
];

const DEPENDENCY_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

pub(super) fn lockfile_fixer(
    ctx: &FixCtx<'_>,
    spec: &ProjectInputSpec,
    problems: &[Problem],
) -> Result<FixPlan> {
    let problems = fixer::attach_issue_remedies(problems, js_lockfile_remedy(spec));
    fixer::plan(&problems, |remedy| recipe(ctx, spec, remedy))
}

fn recipe(
    ctx: &FixCtx<'_>,
    spec: &ProjectInputSpec,
    remedy: &'static Remedy,
) -> Result<std::result::Result<Option<Recipe>, Refusal>> {
    let Some(binding) = &spec.js_binding else {
        return Ok(Ok(None));
    };
    let root = binding
        .root_manifest_path
        .parent()
        .unwrap_or_else(|| spec.project_dir())
        .to_path_buf();
    if remedy.id == remedy::JS_SHADOW_LOCKFILE.id {
        return Ok(shadow_recipe(ctx, spec, &root));
    }
    let Some(recipe) = manager_recipe(binding, &root, remedy) else {
        return Ok(Ok(None));
    };
    if let Err(refusal) = preconditions(ctx, &root, binding.manager) {
        return Ok(Err(refusal));
    }
    let manifests = match workspace_manifests(ctx, &root) {
        Ok(manifests) => manifests,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = refuse_code_specs(&manifests) {
        return Ok(Err(refusal));
    }
    let configs = [".npmrc", ".yarnrc.yml", "pnpm-workspace.yaml", "bunfig.toml"]
        .iter()
        .map(|name| root.join(name));
    let lockfiles = ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]
        .iter()
        .map(|name| root.join(name));
    Ok(Ok(Some(
        recipe
            .inputs_if_present(manifests)
            .inputs_if_present(configs)
            .inputs_if_present(lockfiles),
    )))
}

/// The lockfile-only install for the project's manager, or `None` when `remedy` is not one.
fn manager_recipe(binding: &JsProjectBinding, root: &Path, remedy: &'static Remedy) -> Option<Recipe> {
    let lockfile = |name: &str| binding.lockfile_path.clone().unwrap_or_else(|| root.join(name));
    let base = |output: PathBuf| {
        let mut recipe = Recipe::new(remedy.command, root.to_path_buf());
        recipe.outputs = vec![output];
        recipe
    };
    let recipe = match (binding.manager, remedy.id) {
        (JsPackageManager::Npm, "npm-lockfile") => base(lockfile("package-lock.json"))
            .tool("npm", (7, 0, 0), "npm 7.0", &["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]),
        (JsPackageManager::Npm, "npm-lockfile-upgrade") => {
            let mut recipe = base(lockfile("package-lock.json")).tool(
                "npm",
                (8, 1, 2),
                "npm 8.1.2",
                &["install", "--package-lock-only", "--ignore-scripts", "--lockfile-version", "3", "--no-audit", "--no-fund"],
            );
            // npm keeps going when it cannot fetch an old entry's metadata; that entry is unverified.
            recipe.failure_markers = &["Could not fetch metadata"];
            recipe
        }
        (JsPackageManager::Pnpm, "pnpm-lockfile") => {
            let mut recipe = base(lockfile("pnpm-lock.yaml")).tool(
                "pnpm",
                (9, 0, 0),
                "pnpm 9.0",
                &["install", "--lockfile-only", "--ignore-scripts", "--ignore-pnpmfile", "--no-frozen-lockfile"],
            );
            recipe.old_snapshot = OldSnapshot::Reader(pnpm_old_snapshot);
            recipe
        }
        (JsPackageManager::Bun, "bun-lockfile") => base(lockfile("bun.lock"))
            .tool("bun", (1, 1, 43), "bun 1.1.43", &["install", "--lockfile-only", "--ignore-scripts"]),
        (JsPackageManager::Bun, "bun-binary-lockfile") => {
            let mut recipe = base(root.join("bun.lock")).tool(
                "bun",
                (1, 1, 43),
                "bun 1.1.43",
                &["install", "--save-text-lockfile", "--frozen-lockfile", "--lockfile-only", "--ignore-scripts"],
            );
            recipe.deletions = vec![root.join("bun.lockb")];
            // `bun bun.lockb` prints the binary lockfile as a Yarn v1 lockfile. Bun only does so
            // for a path ending in `.lockb`, which this literal guarantees.
            recipe.old_snapshot = OldSnapshot::ToolPrint {
                args: vec!["bun.lockb".to_string()],
                parse: bun_binary_snapshot,
            };
            recipe
        }
        (JsPackageManager::Yarn, "yarn-berry-lockfile") => base(lockfile("yarn.lock")).tool(
            "yarn",
            (3, 0, 0),
            "Yarn 3.0",
            &["install", "--mode=update-lockfile"],
        ),
        _ => return None,
    };
    let mut recipe = recipe;
    recipe.env = manager_env();
    Some(recipe)
}

/// Scripts off by environment as well as by flag, every cache and store in the scratch home, no
/// self-updating package managers.
fn manager_env() -> Vec<(&'static str, EnvValue)> {
    let mut env = literal_env(&[
        ("npm_config_ignore_scripts", "true"),
        ("npm_config_audit", "false"),
        ("npm_config_fund", "false"),
        ("npm_config_update_notifier", "false"),
        ("npm_config_manage_package_manager_versions", "false"),
        ("npm_config_package_manager_strict", "false"),
        ("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0"),
        ("COREPACK_ENABLE_STRICT", "0"),
        ("YARN_ENABLE_SCRIPTS", "0"),
        ("YARN_IGNORE_PATH", "1"),
        ("YARN_ENABLE_IMMUTABLE_INSTALLS", "false"),
        ("YARN_ENABLE_TELEMETRY", "0"),
        ("YARN_ENABLE_PROGRESS_BARS", "0"),
        ("YARN_ENABLE_GLOBAL_CACHE", "0"),
        ("DO_NOT_TRACK", "1"),
    ]);
    env.extend([
        ("npm_config_userconfig", EnvValue::ScratchFile("npmrc-user")),
        ("npm_config_globalconfig", EnvValue::ScratchFile("npmrc-global")),
        ("npm_config_cache", EnvValue::ScratchDir("npm-cache")),
        ("npm_config_store_dir", EnvValue::ScratchDir("pnpm-store")),
        ("COREPACK_HOME", EnvValue::ScratchDir("corepack")),
        ("YARN_CACHE_FOLDER", EnvValue::ScratchDir("yarn-cache")),
        ("YARN_GLOBAL_FOLDER", EnvValue::ScratchDir("yarn-global")),
        ("BUN_INSTALL", EnvValue::ScratchDir("bun")),
        ("BUN_INSTALL_CACHE_DIR", EnvValue::ScratchDir("bun-cache")),
    ]);
    env
}

fn shadow_recipe(
    ctx: &FixCtx<'_>,
    spec: &ProjectInputSpec,
    root: &Path,
) -> std::result::Result<Option<Recipe>, Refusal> {
    let shadows: Vec<PathBuf> = ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]
        .iter()
        .map(|name| spec.project_dir().join(name))
        .filter(|path| parsers::path_detected(path).unwrap_or(false))
        .collect();
    if shadows.is_empty() {
        return Ok(None);
    }
    let mut recipe = Recipe::new(
        format!(
            "remove {}",
            shadows.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(" and ")
        ),
        root.to_path_buf(),
    );
    recipe.deletions = shadows.clone();
    let manifests = workspace_manifests(ctx, root)?;
    let configs = [".npmrc", ".yarnrc.yml", "pnpm-workspace.yaml", "bunfig.toml"]
        .iter()
        .map(|name| root.join(name));
    let lockfiles = ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]
        .iter()
        .map(|name| root.join(name));
    Ok(Some(
        recipe
            .inputs_if_present(manifests)
            .inputs_if_present(configs)
            .inputs_if_present(lockfiles)
            .inputs_if_present(shadows),
    ))
}

/// The root manifest and every workspace member manifest under `root`.
fn workspace_manifests(ctx: &FixCtx<'_>, root: &Path) -> std::result::Result<Vec<PathBuf>, Refusal> {
    let canonical = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
    let mut manifests = vec![root.join("package.json")];
    let workspace = find_js_workspace_root(&canonical, &canonical).map_err(|e| format!("{e:#}"))?;
    if let Some(workspace) = workspace {
        let members = workspace_manifest_paths(&workspace, &ctx.config.ignore_dirs)
            .map_err(|e| format!("{e:#}"))?;
        for member in members {
            let relative = member.strip_prefix(&canonical).unwrap_or(&member);
            let path = root.join(relative);
            if !manifests.contains(&path) {
                manifests.push(path);
            }
        }
    }
    Ok(manifests)
}

/// The code-execution surfaces of the JS package managers, beyond what the scan's own policy
/// already blocks (docs/specs/fix-lockfile.md, Preconditions).
fn preconditions(ctx: &FixCtx<'_>, root: &Path, manager: JsPackageManager) -> std::result::Result<(), Refusal> {
    let _ = ctx;
    for name in [".pnpmfile.cjs", ".pnpmfile.mjs", ".pnpmfile.js", ".yarnrc"] {
        if parsers::path_detected(&root.join(name)).unwrap_or(false) {
            return Err(format!("{name} at the workspace root can run code during install"));
        }
    }
    refuse_npmrc(&root.join(".npmrc"))?;
    refuse_yaml_keys(&root.join(".yarnrc.yml"), &["yarnPath", "plugins"])?;
    refuse_yaml_keys(&root.join("pnpm-workspace.yaml"), PNPM_WORKSPACE_DENIED)?;
    let bunfig = root.join("bunfig.toml");
    if parsers::path_detected(&bunfig).unwrap_or(false) {
        let text = crate::untrusted::read_text(&bunfig, crate::untrusted::Format::Text, parsers::MAX_MANIFEST_BYTES)
            .map_err(|e| format!("{e:#}"))?;
        if text.contains("preload") {
            return Err("bunfig.toml preloads scripts".to_string());
        }
    }
    let manifest = read_npm_manifest_value(&root.join("package.json")).map_err(|e| format!("{e:#}"))?;
    if let Some(field) = manifest.get("packageManager").and_then(|v| v.as_str())
        && (field.contains("://") || field.contains('/'))
    {
        return Err(format!(
            "packageManager '{}' points at a download, which would run a binary the repository chose",
            crate::report::sanitize_for_terminal(field)
        ));
    }
    if manager == JsPackageManager::Yarn && parsers::path_detected(&root.join(".yarn/plugins")).unwrap_or(false) {
        return Err("the repository commits Yarn plugins (.yarn/plugins), which Yarn can load".to_string());
    }
    Ok(())
}

fn refuse_npmrc(path: &Path) -> std::result::Result<(), Refusal> {
    if !parsers::path_detected(path).unwrap_or(false) {
        return Ok(());
    }
    let text = crate::untrusted::read_line_file(path).map_err(|e| format!("{e:#}"))?;
    for row in crate::untrusted::rows(&text) {
        let row = row.trim();
        if row.starts_with('#') || row.starts_with(';') {
            continue;
        }
        let key = row.split('=').next().unwrap_or_default().trim().to_ascii_lowercase();
        if NPMRC_DENIED.contains(&key.as_str()) {
            return Err(format!(".npmrc sets '{key}', which can run code or redirect what the install uses"));
        }
    }
    Ok(())
}

fn refuse_yaml_keys(path: &Path, denied: &[&str]) -> std::result::Result<(), Refusal> {
    if !parsers::path_detected(path).unwrap_or(false) {
        return Ok(());
    }
    let value = match crate::untrusted::read(path, crate::untrusted::Format::Yaml, parsers::MAX_MANIFEST_BYTES)
        .map_err(|e| format!("{e:#}"))?
    {
        crate::untrusted::Untrusted::Yaml(value) => value,
        _ => return Err(format!("{} is not YAML", path.display())),
    };
    for key in denied {
        if value.get(*key).is_some() {
            return Err(format!(
                "{} sets '{key}', which can run code or rewrite dependencies",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Git, URL, local-path and executable dependencies make the install fetch, build or read code.
fn refuse_code_specs(manifests: &[PathBuf]) -> std::result::Result<(), Refusal> {
    for path in manifests {
        let manifest = read_npm_manifest_value(path).map_err(|e| format!("{e:#}"))?;
        for section in DEPENDENCY_SECTIONS {
            let Some(entries) = manifest.get(*section).and_then(|v| v.as_object()) else {
                continue;
            };
            for (name, spec) in entries {
                let spec = spec.as_str().unwrap_or_default().trim();
                let target = spec.strip_prefix("npm:").unwrap_or(spec);
                let refused = SPEC_PREFIXES_REFUSED.iter().any(|prefix| target.starts_with(prefix))
                    || looks_like_github_shorthand(target);
                if refused {
                    return Err(format!(
                        "{} declares '{}' as '{}': git, URL, local-path and exec dependencies make the install fetch or run code outside the registry",
                        path.display(),
                        crate::report::sanitize_for_terminal(name),
                        crate::report::sanitize_for_terminal(spec)
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `user/repo` or `user/repo#ref`: npm reads it as a GitHub dependency.
fn looks_like_github_shorthand(spec: &str) -> bool {
    !spec.starts_with('@')
        && !spec.starts_with("workspace:")
        && spec.split('#').next().is_some_and(|base| {
            let mut parts = base.split('/');
            matches!((parts.next(), parts.next(), parts.next()), (Some(a), Some(b), None) if !a.is_empty() && !b.is_empty())
        })
}

/// The committed pnpm lockfile: the scan's parser for 9.0, the legacy reader for older formats
/// (every package then counts as reachable).
fn pnpm_old_snapshot(spec: &ProjectInputSpec) -> Result<Snapshot> {
    if let Ok(snapshot) = fixer::lockfile_data_snapshot(spec) {
        return Ok(snapshot);
    }
    let path = selected_lockfile_path(spec)
        .ok_or_else(|| anyhow::anyhow!("the pnpm project has no lockfile path"))?;
    let content = crate::untrusted::read_line_file(&path)?;
    if content.contains("lockfileVersion: 5") || content.contains("lockfileVersion: '5") {
        anyhow::bail!("pnpm 9 cannot read a 5.x lockfile; regenerate it by hand with pnpm 8 first");
    }
    let mut snapshot = fixer::lockfile_data_snapshot_without_lockfile(spec)?;
    snapshot.exists = true;
    snapshot.packages = crate::lockfiles::pnpm_legacy_packages(&content)?;
    snapshot.reachable = None;
    Ok(snapshot)
}

/// The Yarn v1 text `bun bun.lockb` prints. Sources on the public registry are left out of the
/// comparison (bun.lock records them as the default registry); any other source is kept, so a
/// conversion that changes it is refused.
fn bun_binary_snapshot(printed: &str, spec: &ProjectInputSpec) -> Result<Snapshot> {
    let path = spec.project_dir().join("bun.lockb.printed");
    let parsed = crate::lockfiles::yarn::parse_lockfile(printed, path, spec.project_dir())?;
    let mut snapshot = fixer::lockfile_data_snapshot_without_lockfile(spec)?;
    snapshot.exists = true;
    snapshot.packages = parsed
        .locked_packages()?
        .into_iter()
        .map(|mut package| {
            if package
                .source
                .as_deref()
                .is_some_and(|source| source.starts_with("https://registry.npmjs.org/"))
            {
                package.source = None;
            }
            package
        })
        .collect();
    Ok(snapshot)
}

#[cfg(test)]
#[path = "lock_fixer_tests.rs"]
mod tests;
