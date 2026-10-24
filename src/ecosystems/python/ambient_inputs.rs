//! Repository files uv, Poetry, pip, PDM, Hatch, tox and pipenv read beside a Python project.

use super::*;
use crate::ecosystems::ambient::{AmbientInput as Row, Disposition::*, Scope::*};

const PIPFILE: &[ProjectInputKind] = &[ProjectInputKind::PyPipfile];

const VENV_WHY: &str = "uv, Poetry and pipenv run the interpreter inside an existing .venv, so a committed one executes repository code during install. Fix: remove it from the repository and add .venv to .gitignore.";

pub(super) const AMBIENT: &[Row] = &[
    // uv runs a path or executable named here to query the interpreter.
    Row::new(
        ".python-version",
        AncestorsToRepoRoot,
        Modeled(interpreter_config::reject_python_version_path),
    ),
    Row::new(
        ".venv/pyvenv.cfg",
        AncestorsToRepoRoot,
        BlockedIfTracked(VENV_WHY),
    ),
    Row::new(
        ".venv/bin/python",
        AncestorsToRepoRoot,
        BlockedIfTracked(VENV_WHY),
    ),
    // pipenv loads `.env` beside the Pipfile for every command; other managers do not.
    Row::new(
        ".env",
        ProjectDir,
        Modeled(interpreter_config::reject_pipenv_dotenv),
    )
    .only(PIPFILE),
    Row::new(
        "poetry.toml",
        AncestorsToRepoRoot,
        ModeledElsewhere(
            "interpreter_config::check_poetry_toml, with the operator's config_key_allow",
        ),
    ),
    Row::new(
        "uv.toml",
        AncestorsToRepoRoot,
        ModeledElsewhere("pyproject_toml::check_uv_config (uv_surface), with config_key_allow"),
    ),
    Row::new(
        "pyproject.toml",
        AncestorsToRepoRoot,
        ModeledElsewhere(
            "pyproject_toml::check_uv_config checks [tool.uv] of every ancestor pyproject.toml",
        ),
    ),
    Row::new(
        "pdm.toml",
        ProjectDir,
        ModeledElsewhere("tool_config::reject_pdm_config"),
    ),
    Row::new(
        ".pdm.toml",
        ProjectDir,
        ModeledElsewhere("tool_config::reject_pdm_config"),
    ),
    Row::new(
        "hatch.toml",
        ProjectDir,
        ModeledElsewhere("tool_config::reject_hatch_toml"),
    ),
    Row::new(
        "tox.ini",
        ProjectDir,
        ModeledElsewhere("tool_config::unscanned_tool_files"),
    ),
    Row::new(
        "tox.toml",
        ProjectDir,
        ModeledElsewhere("tool_config::unscanned_tool_files"),
    ),
    Row::new(
        "setup.cfg",
        ProjectDir,
        ModeledElsewhere("parsers::setup_cfg and tool_config::unscanned_tool_files"),
    ),
    Row::new(
        "setup.py",
        ProjectDir,
        ModeledElsewhere("parsers::setup_py (lexed; anything it cannot model blocks)"),
    ),
    // pip reads user, global, site and virtualenv config plus PIP_CONFIG_FILE, never a file the
    // repository commits beside the project.
    Row::new(
        "pip.conf",
        ProjectDir,
        Irrelevant(
            "pip does not read a repository-local pip.conf; user, global and site config are outside the repository",
        ),
    ),
    Row::new(
        "pip.ini",
        ProjectDir,
        Irrelevant(
            "pip does not read a repository-local pip.ini; user, global and site config are outside the repository",
        ),
    ),
];
