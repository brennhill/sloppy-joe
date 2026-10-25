//! `fix-lockfile` for Python (docs/specs/fix-lockfile.md). `uv lock --no-build` resolves without
//! building any source distribution, so it is fixable. `poetry lock` builds a source distribution
//! when it needs metadata no wheel provides, and has no flag to forbid that, so it runs only when
//! every locked package has a wheel and no new dependency has to be resolved. Pipfile.lock and
//! hash-locked requirements are guided.

use super::*;
use crate::ecosystems::fixer::{EnvValue, FixCtx, FixPlan, Problem, Recipe, Refusal, literal_env};
use crate::remedy::{self, Remedy};

pub(super) fn lockfile_fixer(
    _ctx: &FixCtx<'_>,
    spec: &ProjectInputSpec,
    problems: &[Problem],
) -> Result<FixPlan> {
    let lockfile_remedy = match spec.kind {
        ProjectInputKind::PyProjectPoetry => &remedy::POETRY_LOCK,
        ProjectInputKind::PyProjectUv => &remedy::UV_LOCK,
        ProjectInputKind::PyPipfile => &remedy::PIPENV_LOCK,
        _ => &remedy::PIP_COMPILE_HASHES,
    };
    let problems = fixer::attach_issue_remedies(problems, lockfile_remedy);
    fixer::plan(&problems, |remedy| recipe(spec, remedy))
}

fn recipe(
    spec: &ProjectInputSpec,
    remedy: &'static Remedy,
) -> Result<std::result::Result<Option<Recipe>, Refusal>> {
    let uv = remedy.id == remedy::UV_LOCK.id && spec.kind == ProjectInputKind::PyProjectUv;
    let poetry =
        remedy.id == remedy::POETRY_LOCK.id && spec.kind == ProjectInputKind::PyProjectPoetry;
    if !uv && !poetry {
        return Ok(Ok(None));
    }
    let pyproject = read_toml(&spec.manifest_path)?;
    let lockfile = common::named_lockfile(spec).expect("Poetry and uv name their lockfile");
    let old_lock = if parsers::path_detected(&lockfile)? {
        Some(read_toml(&lockfile)?)
    } else {
        None
    };
    let checked = if uv {
        uv_preconditions(spec, &pyproject, old_lock.as_ref())
    } else {
        poetry_preconditions(spec, &pyproject, old_lock.as_ref())
    };
    if let Err(refusal) = checked {
        return Ok(Err(refusal));
    }
    let mut recipe = if uv {
        Recipe::new(remedy.command, spec.project_dir().to_path_buf()).tool(
            "uv",
            (0, 3, 0),
            "uv 0.3",
            &["lock", "--no-build", "--no-python-downloads"],
        )
    } else {
        Recipe::new(remedy.command, spec.project_dir().to_path_buf()).tool(
            "poetry",
            (2, 0, 0),
            "Poetry 2.0",
            &["lock", "--no-interaction", "--no-ansi", "--no-plugins"],
        )
    };
    recipe.outputs = vec![lockfile.clone()];
    recipe.env = python_env();
    Ok(Ok(Some(
        recipe.inputs_if_present([spec.manifest_path.clone(), lockfile]),
    )))
}

fn python_env() -> Vec<(&'static str, EnvValue)> {
    let mut env = literal_env(&[
        ("UV_NO_BUILD", "1"),
        ("UV_PYTHON_DOWNLOADS", "never"),
        ("UV_NO_PROGRESS", "1"),
        ("POETRY_NO_INTERACTION", "1"),
        ("POETRY_KEYRING_ENABLED", "false"),
        ("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring"),
        ("PIP_NO_INPUT", "1"),
        ("PYTHONNOUSERSITE", "1"),
    ]);
    env.extend([
        ("UV_CACHE_DIR", EnvValue::ScratchDir("uv-cache")),
        ("UV_PYTHON_INSTALL_DIR", EnvValue::ScratchDir("uv-python")),
        ("POETRY_CONFIG_DIR", EnvValue::ScratchDir("poetry-config")),
        ("POETRY_CACHE_DIR", EnvValue::ScratchDir("poetry-cache")),
        ("POETRY_DATA_DIR", EnvValue::ScratchDir("poetry-data")),
        ("POETRY_VIRTUALENVS_PATH", EnvValue::ScratchDir("poetry-venvs")),
    ]);
    env
}

fn read_toml(path: &Path) -> Result<toml::Value> {
    match crate::untrusted::read(path, crate::untrusted::Format::Toml, parsers::MAX_MANIFEST_BYTES)? {
        crate::untrusted::Untrusted::Toml(value) => Ok(value),
        _ => anyhow::bail!("{} is not TOML", path.display()),
    }
}

fn table_path<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
    path.iter().try_fold(value, |value, key| value.get(*key))
}

fn refuse_tool_config(spec: &ProjectInputSpec, names: &[&str]) -> std::result::Result<(), Refusal> {
    for name in names {
        if parsers::path_detected(&spec.project_dir().join(name)).unwrap_or(false) {
            return Err(format!(
                "{name} configures the tool in ways fix-lockfile does not review; regenerate the lockfile by hand"
            ));
        }
    }
    Ok(())
}

/// Locked packages that have no wheel: resolving them means building the sdist, which runs it.
fn packages_without_wheels(lock: &toml::Value, wheels: impl Fn(&toml::value::Table) -> bool) -> Vec<String> {
    lock.get("package")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|package| package.as_table())
        .filter(|package| !wheels(package))
        .filter_map(|package| {
            Some(format!(
                "{}@{}",
                package.get("name")?.as_str()?,
                package.get("version").and_then(|v| v.as_str()).unwrap_or("?")
            ))
        })
        .collect()
}

fn refuse_without_wheels(missing: Vec<String>) -> std::result::Result<(), Refusal> {
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "locked package(s) {} have no wheel, so resolving them would build a source distribution, which runs its code",
        missing.join(", ")
    ))
}

fn uv_preconditions(
    spec: &ProjectInputSpec,
    pyproject: &toml::Value,
    old_lock: Option<&toml::Value>,
) -> std::result::Result<(), Refusal> {
    refuse_tool_config(spec, &["uv.toml"])?;
    if table_path(pyproject, &["project", "dynamic"])
        .and_then(|v| v.as_array())
        .is_some_and(|dynamic| !dynamic.is_empty())
    {
        return Err("the project's metadata is dynamic, so uv would have to build it".to_string());
    }
    if table_path(pyproject, &["tool", "uv", "workspace"]).is_some() {
        return Err("pyproject.toml declares a uv workspace, whose members are not copied".to_string());
    }
    // An index source only picks a registry; git, path, URL and workspace sources make uv clone,
    // read or build code outside the registry.
    let sources = table_path(pyproject, &["tool", "uv", "sources"]).and_then(|v| v.as_table());
    for (name, source) in sources.into_iter().flatten() {
        let entries: Vec<&toml::Value> = match source {
            toml::Value::Array(list) => list.iter().collect(),
            other => vec![other],
        };
        let index_only = entries.iter().all(|entry| {
            entry
                .as_table()
                .is_some_and(|table| table.keys().all(|key| key == "index" || key == "marker"))
        });
        if !index_only {
            return Err(format!(
                "tool.uv.sources gives '{}' a git, path, URL or workspace source",
                crate::report::sanitize_for_terminal(name)
            ));
        }
    }
    let Some(lock) = old_lock else {
        return Ok(());
    };
    refuse_without_wheels(packages_without_wheels(lock, |package| {
        let local_root = package.get("source").and_then(|s| s.as_table()).is_some_and(|source| {
            ["editable", "virtual", "directory", "path"]
                .iter()
                .any(|key| source.contains_key(*key))
        });
        local_root
            || package
                .get("wheels")
                .and_then(|w| w.as_array())
                .is_some_and(|wheels| !wheels.is_empty())
    }))
}

fn poetry_preconditions(
    spec: &ProjectInputSpec,
    pyproject: &toml::Value,
    old_lock: Option<&toml::Value>,
) -> std::result::Result<(), Refusal> {
    refuse_tool_config(spec, &["poetry.toml"])?;
    if table_path(pyproject, &["tool", "poetry", "requires-plugins"]).is_some() {
        return Err("pyproject.toml requires Poetry plugins, which Poetry installs and runs".to_string());
    }
    const SDIST_BUILD: &str = "poetry builds a source distribution when no wheel gives it the metadata, and has no flag to forbid that";
    let Some(lock) = old_lock else {
        return Err(format!("there is no poetry.lock, so the packages to resolve are unknown and {SDIST_BUILD}"));
    };
    let locked: Vec<String> = lock
        .get("package")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|package| package.get("name")?.as_str())
        .map(crate::lockfiles::python_hashes::normalize_name)
        .collect();
    let deps = for_kind(spec.kind)
        .parse_manifest(spec.project_dir(), spec)
        .map_err(|e| format!("{e:#}"))?;
    if let Some(new) = deps.iter().find(|dep| {
        !locked.contains(&crate::lockfiles::python_hashes::normalize_name(dep.package_name()))
    }) {
        return Err(format!(
            "'{}' is not locked yet, so poetry would resolve it, and {SDIST_BUILD}",
            crate::report::sanitize_for_terminal(new.package_name())
        ));
    }
    refuse_without_wheels(packages_without_wheels(lock, |package| {
        package
            .get("files")
            .and_then(|f| f.as_array())
            .is_some_and(|files| {
                files.iter().any(|file| {
                    file.get("file")
                        .and_then(|name| name.as_str())
                        .is_some_and(|name| name.ends_with(".whl"))
                })
            })
    }))
}

#[cfg(test)]
#[path = "lock_fixer_tests.rs"]
mod tests;
