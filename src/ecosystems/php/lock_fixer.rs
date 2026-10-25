//! `fix-lockfile` for Composer (docs/specs/fix-lockfile.md): `composer update --lock` pins every
//! locked package to its locked version and resolves what composer.json newly requires; a missing
//! lockfile is resolved from scratch. Scripts and plugins are off, nothing is installed.

use super::*;
use crate::ecosystems::fixer::{EnvValue, FixCtx, FixPlan, Problem, Recipe, Refusal, literal_env};
use crate::remedy::{self, Remedy};

/// Repository types that make Composer run version-control tools or read local code.
const REPOSITORY_TYPES_REFUSED: &[&str] = &[
    "vcs",
    "git",
    "github",
    "gitlab",
    "git-bitbucket",
    "bitbucket",
    "hg",
    "svn",
    "fossil",
    "perforce",
    "path",
    "artifact",
    "package",
];

pub(super) fn lockfile_fixer(
    _ctx: &FixCtx<'_>,
    spec: &ProjectInputSpec,
    problems: &[Problem],
) -> Result<FixPlan> {
    let problems = fixer::attach_issue_remedies(problems, &remedy::COMPOSER_LOCK);
    fixer::plan(&problems, |remedy| recipe(spec, remedy))
}

fn recipe(
    spec: &ProjectInputSpec,
    remedy: &'static Remedy,
) -> Result<std::result::Result<Option<Recipe>, Refusal>> {
    if remedy.id != remedy::COMPOSER_LOCK.id && remedy.id != remedy::COMPOSER_LOCK_MISSING.id {
        return Ok(Ok(None));
    }
    let crate::untrusted::Untrusted::Json(manifest) = crate::untrusted::read(
        &spec.manifest_path,
        crate::untrusted::Format::Json,
        parsers::MAX_MANIFEST_BYTES,
    )?
    else {
        anyhow::bail!("{} is not JSON", spec.manifest_path.display());
    };
    if let Err(refusal) = preconditions(&manifest) {
        return Ok(Err(refusal));
    }
    let lockfile = common::named_lockfile(spec).expect("Php names composer.lock");
    let existing = parsers::path_detected(&lockfile)?;
    let (display, args): (&str, &[&str]) = if existing {
        (
            remedy::COMPOSER_LOCK.command,
            &[
                "update",
                "--lock",
                "--no-install",
                "--no-scripts",
                "--no-plugins",
                "--no-interaction",
                "--no-progress",
            ],
        )
    } else {
        (
            remedy::COMPOSER_LOCK_MISSING.command,
            &[
                "update",
                "--no-install",
                "--no-scripts",
                "--no-plugins",
                "--no-interaction",
                "--no-progress",
            ],
        )
    };
    let mut recipe = Recipe::new(display, spec.project_dir().to_path_buf()).tool(
        "composer",
        (2, 0, 0),
        "Composer 2.0",
        args,
    );
    recipe.outputs = vec![lockfile.clone()];
    recipe.env = composer_env();
    Ok(Ok(Some(recipe.inputs_if_present([
        spec.manifest_path.clone(),
        lockfile,
    ]))))
}

fn composer_env() -> Vec<(&'static str, EnvValue)> {
    let mut env = literal_env(&[
        ("COMPOSER_NO_INTERACTION", "1"),
        ("COMPOSER_NO_AUDIT", "1"),
        ("COMPOSER_DISABLE_XDEBUG_WARN", "1"),
        ("COMPOSER_ALLOW_SUPERUSER", "0"),
    ]);
    env.extend([
        ("COMPOSER_HOME", EnvValue::ScratchDir("composer")),
        ("COMPOSER_CACHE_DIR", EnvValue::ScratchDir("composer-cache")),
    ]);
    env
}

/// Version-control, path, artifact and inline package repositories make Composer run git or
/// similar tools, or read code the scratch copy does not hold.
fn preconditions(manifest: &serde_json::Value) -> std::result::Result<(), Refusal> {
    let repositories: Vec<&serde_json::Value> = match manifest.get("repositories") {
        Some(serde_json::Value::Array(list)) => list.iter().collect(),
        Some(serde_json::Value::Object(map)) => map.values().collect(),
        _ => Vec::new(),
    };
    for repository in repositories {
        let kind = repository
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if REPOSITORY_TYPES_REFUSED.contains(&kind) {
            return Err(format!(
                "composer.json declares a '{}' repository, which makes Composer run version-control tools or read local code",
                crate::report::sanitize_for_terminal(kind)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcs_and_path_repositories_are_refused() {
        let vcs = serde_json::json!({"repositories":[{"type":"vcs","url":"https://g/x.git"}]});
        assert!(preconditions(&vcs).is_err());
        let path = serde_json::json!({"repositories":{"local":{"type":"path","url":"../x"}}});
        assert!(preconditions(&path).is_err());
        let packagist = serde_json::json!({"repositories":[{"type":"composer","url":"https://repo.packagist.org"}]});
        assert!(preconditions(&packagist).is_ok());
    }
}
