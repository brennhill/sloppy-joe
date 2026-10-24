//! Repository files that choose which Python interpreter, cache or environment an install uses:
//! `.python-version`, a committed `.venv`, `poetry.toml` and the `.env` that pipenv loads. Each can
//! make the tool run or install something the lockfile hashes never covered. `.python-version`,
//! `.venv` and `.env` are rows of the plugin's ambient-input table; `poetry.toml` needs the
//! operator's allows, so it is checked here.

use super::*;
use crate::config_surface::{Surface, ValueRule, rule};
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

#[cfg(test)]
pub(super) fn check_interpreter_config(spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
    check_interpreter_config_with(spec, &[])
}

/// `allows` are the operator's `config_key_allow` entries; each one applied is a warning.
pub(super) fn check_interpreter_config_with(
    spec: &ProjectInputSpec,
    allows: &[crate::config_surface::KeyAllow],
) -> Result<Vec<Issue>> {
    let dirs = config_dirs(spec.project_dir())?;
    let mut applied = Vec::new();
    for dir in &dirs {
        applied.extend(check_poetry_toml(&dir.join("poetry.toml"), allows)?);
    }
    Ok(crate::config_surface::issues(&applied))
}

/// uv accepts a path or executable in `.python-version` and runs it to query the interpreter.
pub(super) fn reject_python_version_path(path: &Path) -> Result<()> {
    if !exists(path) {
        return Ok(());
    }
    let content = crate::untrusted::read_text(
        path,
        crate::untrusted::Format::Text,
        crate::fsutil::MAX_MANIFEST_BYTES,
    )?;
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

/// `poetry.toml` can move Poetry's cache (whose unpacked artifacts it installs without re-hashing),
/// the virtualenv location, and its package repositories and credentials. Those are denied and
/// cannot be allowed by config. The settings listed here change none of that and stay allowed;
/// any other key blocks unless the operator allows it (`config_key_allow`, file `poetry.toml`).
const POETRY: Surface = Surface {
    id: "poetry.toml",
    subject: "Poetry setting",
    why: "it changes the cache, environment or package repositories Poetry installs from, so the lockfile hashes no longer vouch for the install",
    allow: &[
        rule("virtualenvs.create", ValueRule::Any),
        rule("virtualenvs.in-project", ValueRule::Any),
        rule("virtualenvs.prefer-active-python", ValueRule::Any),
        rule("virtualenvs.use-poetry-python", ValueRule::Any),
        rule("virtualenvs.options.always-copy", ValueRule::Any),
        rule("virtualenvs.options.no-pip", ValueRule::Any),
        rule("virtualenvs.options.no-setuptools", ValueRule::Any),
        rule("virtualenvs.options.system-site-packages", ValueRule::Any),
        rule("installer.parallel", ValueRule::Any),
        rule("installer.max-workers", ValueRule::Any),
        rule("installer.no-binary", ValueRule::Any),
        rule("installer.only-binary", ValueRule::Any),
        rule("installer.re-resolve", ValueRule::Any),
        rule("installer.modern-installation", ValueRule::Any),
        rule("solver.lazy-wheel", ValueRule::Any),
        rule("requests.max-retries", ValueRule::Any),
        rule("system-git-client", ValueRule::Any),
        rule("keyring.enabled", ValueRule::Any),
    ],
    deny: &[
        "cache-dir",
        "data-dir",
        "virtualenvs.path",
        "repositories",
        "certificates",
        "http-basic",
        "pypi-token",
    ],
    deny_under: &[],
    scope: &[],
};

fn check_poetry_toml(
    path: &Path,
    allows: &[crate::config_surface::KeyAllow],
) -> Result<Vec<crate::config_surface::AppliedAllow>> {
    if !exists(path) {
        return Ok(Vec::new());
    }
    let parsed = match crate::untrusted::read(
        path,
        crate::untrusted::Format::Toml,
        crate::fsutil::MAX_MANIFEST_BYTES,
    )? {
        crate::untrusted::Untrusted::Toml(value) => value,
        _ => unreachable!("TOML format produces TOML"),
    };
    crate::config_surface::check_toml(&POETRY, &parsed, path, allows)
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
pub(super) fn reject_pipenv_dotenv(path: &Path) -> Result<()> {
    if !exists(path) {
        return Ok(());
    }
    let content = crate::untrusted::read_line_file(path)?;
    for line in crate::untrusted::rows(&content) {
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

#[cfg(test)]
#[path = "interpreter_config_tests.rs"]
mod tests;
