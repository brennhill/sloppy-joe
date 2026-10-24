//! Python tool configuration beside a project that changes where installs come from, or installs
//! packages the scan never reads. Shared by every Python project kind.

use super::*;
use anyhow::bail;

pub(super) fn check_tool_config(
    ctx: &PreflightCtx<'_>,
    spec: &ProjectInputSpec,
) -> Result<Vec<Issue>> {
    // uv reads `uv.toml` for `uv pip` and `uv sync` alike, whatever file declares the dependencies.
    parsers::pyproject_toml::reject_uv_toml_redirects(&spec.manifest_path)?;
    reject_pdm_config(spec, ctx.scan.config)?;
    reject_hatch_toml(spec.project_dir())?;
    let strict = ctx.scan.opts.scan_mode == ScanMode::Ci;
    unscanned_tool_files(spec, strict)
}

fn read_toml(path: &Path) -> Result<toml::Value> {
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// PDM sources (`[[tool.pdm.source]]`) and `pdm.toml` index settings decide where PDM installs
/// from. A source named `pypi` replaces the default index; every other source must be allowlisted
/// in `trusted_indexes.pypi`, and `pdm.toml` may not redirect the index at all.
fn reject_pdm_config(spec: &ProjectInputSpec, config: &config::SloppyJoeConfig) -> Result<()> {
    for name in ["pdm.toml", ".pdm.toml"] {
        let path = spec.project_dir().join(name);
        if !exists(&path) {
            continue;
        }
        let parsed = read_toml(&path)?;
        if parsed
            .get("pypi")
            .and_then(|pypi| pypi.as_table())
            .is_some_and(|pypi| !pypi.is_empty())
        {
            bail!(
                "Unsupported PDM configuration in {}: [pypi] settings redirect the package index, so the lockfile no longer vouches for the install",
                path.display()
            );
        }
    }
    if spec
        .manifest_path
        .file_name()
        .and_then(|name| name.to_str())
        != Some("pyproject.toml")
    {
        return Ok(());
    }
    let pyproject = read_toml(&spec.manifest_path)?;
    let sources = pyproject
        .get("tool")
        .and_then(|tool| tool.get("pdm"))
        .and_then(|pdm| pdm.get("source"))
        .and_then(|source| source.as_array());
    for source in sources.into_iter().flatten() {
        let url = source.get("url").and_then(|url| url.as_str());
        let name = source.get("name").and_then(|name| name.as_str());
        let trusted = url.is_some_and(|url| config.is_trusted_index("pypi", url));
        let is_default_name = name.is_some_and(|name| name.eq_ignore_ascii_case("pypi"));
        if !trusted || (is_default_name && url.is_none()) {
            bail!(
                "Unsupported PDM source '{}' in {}: it is not the default PyPI index and is not allowlisted in trusted_indexes.pypi, so PDM would install from an index the scan did not vet",
                crate::report::sanitize_for_terminal(name.unwrap_or("<unnamed>")),
                spec.manifest_path.display()
            );
        }
    }
    Ok(())
}

/// `hatch.toml` declares environments (`[envs.*]`) just like `[tool.hatch.envs]` in pyproject,
/// but its dependencies are not scanned.
fn reject_hatch_toml(project_dir: &Path) -> Result<()> {
    for name in ["hatch.toml", ".hatch.toml"] {
        let path = project_dir.join(name);
        if !exists(&path) {
            continue;
        }
        let parsed = read_toml(&path)?;
        if parsers::pyproject_toml::toml_value_declares_dependencies(&parsed) {
            bail!(
                "Unsupported Hatch environments in {}: dependencies declared in hatch.toml are installed but not scanned. Fix: declare them under [tool.hatch.envs] in pyproject.toml",
                path.display()
            );
        }
    }
    Ok(())
}

/// Whether a tox configuration declares environment `deps` or `requires`. In `setup.cfg` and
/// `pyproject.toml` only a tox section counts; `tox.ini` and `tox.toml` are tox's own files.
fn tox_installs_packages(path: &Path, shared_file_section: Option<&str>) -> Result<bool> {
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    if let Some(section) = shared_file_section {
        let lowered = content.to_ascii_lowercase();
        let has_tox = lowered.contains("[tox:tox]")
            || lowered.contains("[testenv")
            || lowered.contains(&format!("[{section}"));
        if !has_tox {
            return Ok(false);
        }
    }
    Ok(content.lines().any(|line| {
        let line = line.trim_start();
        ["deps", "requires"].iter().any(|key| {
            line.strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with(['=', ':']))
        })
    }))
}

/// Files that install Python packages but that no scan reads: conda environments and tox
/// environment dependencies. A warning, and an error in `--ci`.
fn unscanned_tool_files(spec: &ProjectInputSpec, strict: bool) -> Result<Vec<Issue>> {
    let mut found = Vec::new();
    for name in ["environment.yml", "environment.yaml"] {
        let path = spec.project_dir().join(name);
        if exists(&path) {
            found.push(path);
        }
    }
    for (name, section) in [
        ("tox.ini", None),
        ("tox.toml", None),
        ("setup.cfg", Some("tox")),
        ("pyproject.toml", Some("tool.tox")),
    ] {
        let path = spec.project_dir().join(name);
        if exists(&path) && tox_installs_packages(&path, section)? {
            found.push(path);
        }
    }
    let severity = if strict {
        Severity::Error
    } else {
        Severity::Warning
    };
    Ok(found
        .into_iter()
        .map(|path| {
            Issue::new(
                path.display().to_string(),
                checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST,
                severity,
            )
            .message(format!(
                "'{}' installs Python packages next to '{}' but sloppy-joe does not read it, so those packages are not scanned.",
                path.display(),
                spec.manifest_path.display()
            ))
            .fix("Declare the dependencies in the scanned manifest and lockfile, or remove the file. Blocks in --ci.")
        })
        .collect())
}

#[cfg(test)]
#[path = "tool_config_tests.rs"]
mod tests;
