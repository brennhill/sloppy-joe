//! Repository files that choose which Python interpreter, cache or environment an install uses:
//! `.python-version`, a committed `.venv`, `poetry.toml` and the `.env` that pipenv loads. Each can
//! make the tool run or install something the lockfile hashes never covered.

use super::*;
use anyhow::bail;

/// The directories uv, Poetry and pipenv consult: the project directory and its parents up to the
/// repository root.
fn config_dirs(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = std::fs::canonicalize(project_dir)?;
    let boundary = cache::find_git_root(&dir).map_err(anyhow::Error::msg)?;
    let mut dirs = Vec::new();
    for ancestor in dir.ancestors() {
        dirs.push(ancestor.to_path_buf());
        if boundary.as_deref() == Some(ancestor) {
            break;
        }
    }
    Ok(dirs)
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

pub(super) fn check_interpreter_config(
    spec: &ProjectInputSpec,
    strict: bool,
) -> Result<Vec<Issue>> {
    let dirs = config_dirs(spec.project_dir())?;
    for dir in &dirs {
        reject_python_version_path(&dir.join(".python-version"))?;
        reject_poetry_toml(&dir.join("poetry.toml"))?;
    }
    let is_pipfile = spec
        .manifest_path
        .file_name()
        .and_then(|name| name.to_str())
        == Some("Pipfile");
    if is_pipfile {
        reject_pipenv_dotenv(&spec.project_dir().join(".env"))?;
    }
    committed_venv_issues(spec, &dirs, strict)
}

/// uv accepts a path or executable in `.python-version` and runs it to query the interpreter.
fn reject_python_version_path(path: &Path) -> Result<()> {
    if !exists(path) {
        return Ok(());
    }
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    for line in content.split(['\n', '\r']) {
        let line = line.trim();
        if !line.starts_with('#') && line.contains(['/', '\\']) {
            bail!(
                "Unsupported interpreter request '{}' in {}: uv runs the interpreter a path names, so it executes code from the repository during install. Fix: name a version such as 3.12.",
                crate::report::sanitize_for_terminal(line),
                path.display()
            );
        }
    }
    Ok(())
}

/// Poetry settings that stay allowed in a project `poetry.toml`; none of them changes where
/// packages come from or where installed artifacts are cached.
const POETRY_ALLOWED_KEYS: &[&str] = &[
    "virtualenvs.create",
    "virtualenvs.in-project",
    "virtualenvs.prefer-active-python",
    "virtualenvs.use-poetry-python",
    "virtualenvs.options.always-copy",
    "virtualenvs.options.no-pip",
    "virtualenvs.options.no-setuptools",
    "virtualenvs.options.system-site-packages",
    "installer.parallel",
    "installer.max-workers",
    "installer.no-binary",
    "installer.only-binary",
    "installer.re-resolve",
    "installer.modern-installation",
    "solver.lazy-wheel",
    "requests.max-retries",
    "system-git-client",
    "keyring.enabled",
];

fn flatten_keys(prefix: &str, value: &toml::Value, out: &mut Vec<String>) {
    match value {
        toml::Value::Table(table) if !table.is_empty() => {
            for (key, child) in table {
                let dotted = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_keys(&dotted, child, out);
            }
        }
        _ => out.push(prefix.to_string()),
    }
}

/// `poetry.toml` can move Poetry's cache (whose unpacked artifacts it installs without re-hashing),
/// the virtualenv location, and its package repositories and credentials. Anything outside the
/// allowlist blocks.
fn reject_poetry_toml(path: &Path) -> Result<()> {
    if !exists(path) {
        return Ok(());
    }
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    crate::fsutil::reject_unmodeled_line_breaks(&content, path)?;
    let parsed: toml::Value = toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))?;
    let mut keys = Vec::new();
    flatten_keys("", &parsed, &mut keys);
    for key in keys.iter().filter(|key| !key.is_empty()) {
        if !POETRY_ALLOWED_KEYS.contains(&key.as_str()) {
            bail!(
                "Unsupported Poetry setting '{}' in {}: it changes the cache, environment or package repositories Poetry installs from, so the lockfile hashes no longer vouch for the install",
                crate::report::sanitize_for_terminal(key),
                path.display()
            );
        }
    }
    Ok(())
}

const DOTENV_BLOCKED_PREFIXES: &[&str] = &[
    "PIP_",
    "PIPENV_",
    "PYTHON",
    "UV_",
    "POETRY_",
    "LD_",
    "DYLD_",
    "VIRTUAL_ENV",
    "PATH",
];

/// pipenv loads `.env` beside the Pipfile for every command, so it can set `PYTHONPATH`,
/// `PIP_INDEX_URL`, `PIPENV_*` and similar variables for the install.
fn reject_pipenv_dotenv(path: &Path) -> Result<()> {
    if !exists(path) {
        return Ok(());
    }
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    crate::fsutil::reject_unmodeled_line_breaks(&content, path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let key = line.split_once('=').map(|(key, _)| key.trim());
        let valid = key.filter(|key| {
            !key.is_empty()
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !key.starts_with(|c: char| c.is_ascii_digit())
        });
        let Some(key) = valid else {
            bail!(
                "Unsupported line in {}: pipenv loads this file for every command and the line cannot be read as KEY=VALUE, so the variables it sets cannot be vetted",
                path.display()
            );
        };
        let upper = key.to_ascii_uppercase();
        if DOTENV_BLOCKED_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        {
            bail!(
                "Unsupported variable '{}' in {}: pipenv loads this file for every command, so it can redirect package sources or run repository code during install",
                crate::report::sanitize_for_terminal(key),
                path.display()
            );
        }
    }
    Ok(())
}

fn venv_present(dir: &Path) -> bool {
    let venv = dir.join(".venv");
    exists(&venv.join("pyvenv.cfg")) || exists(&venv.join("bin/python"))
}

/// Whether `.venv` files are tracked by git, from the index. `None` when the index cannot be
/// read reliably (unsupported index version, oversized, unreadable).
fn venv_tracked(repo_root: &Path) -> Option<bool> {
    let dot_git = repo_root.join(".git");
    let git_dir = if dot_git.is_dir() {
        dot_git
    } else {
        let pointer = std::fs::read_to_string(&dot_git).ok()?;
        let target = Path::new(pointer.trim().strip_prefix("gitdir:")?.trim()).to_path_buf();
        if target.is_absolute() {
            target
        } else {
            repo_root.join(target)
        }
    };
    let index_path = git_dir.join("index");
    if std::fs::metadata(&index_path).ok()?.len() > 256 * 1024 * 1024 {
        return None;
    }
    let index = std::fs::read(index_path).ok()?;
    // Versions 2 and 3 store full paths; version 4 compresses prefixes and cannot be searched.
    if index.get(..4)? != b"DIRC" || !matches!(index.get(7)?, 2 | 3) {
        return None;
    }
    let tracked = [&b".venv/pyvenv.cfg"[..], b".venv/bin/python"]
        .iter()
        .any(|needle| index.windows(needle.len()).any(|window| window == *needle));
    Some(tracked)
}

/// uv, Poetry and pipenv use an existing `.venv` and run its interpreter. A `.venv` that a pull
/// request commits therefore executes repository code. One that is merely present in a developer
/// checkout is the developer's own, so only a tracked (or undecidable) one counts.
fn committed_venv_issues(
    spec: &ProjectInputSpec,
    dirs: &[PathBuf],
    strict: bool,
) -> Result<Vec<Issue>> {
    let boundary = cache::find_git_root(spec.project_dir()).map_err(anyhow::Error::msg)?;
    let mut issues = Vec::new();
    for dir in dirs.iter().filter(|dir| venv_present(dir)) {
        match boundary.as_deref().and_then(venv_tracked) {
            Some(false) => {}
            Some(true) => bail!(
                "Committed virtual environment '{}': uv, Poetry and pipenv run its interpreter, so it executes repository code during install. Fix: remove it from the repository and add .venv to .gitignore.",
                dir.join(".venv").display()
            ),
            None => issues.push(
                Issue::new(
                    dir.join(".venv").display().to_string(),
                    checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST,
                    if strict {
                        Severity::Error
                    } else {
                        Severity::Warning
                    },
                )
                .message("A .venv exists and sloppy-joe cannot tell whether git tracks it; uv, Poetry and pipenv run its interpreter, so a committed one executes repository code.")
                .fix("Make sure .venv is not committed (add it to .gitignore). Blocks in --ci."),
            ),
        }
    }
    Ok(issues)
}

#[cfg(test)]
#[path = "interpreter_config_tests.rs"]
mod tests;
