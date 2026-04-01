# PyPI Rules

## Required inputs

- Trusted path: Poetry projects using `pyproject.toml` with Poetry metadata.
- Legacy but supported paths: `requirements*.txt`, `Pipfile`, `setup.cfg`, `setup.py`, and non-Poetry `pyproject.toml`.
- Default behavior is `python_enforcement = "prefer_poetry"`:
  Poetry is trusted, legacy manifests are still scanned, and every run emits a warning urging migration to Poetry.
- Optional stricter behavior is `python_enforcement = "poetry_only"`:
  legacy Python manifests block the scan.

## Lockfile policy

- Poetry projects require `poetry.lock`.
- A missing, unreadable, or malformed `poetry.lock` blocks Poetry scans.
- Poetry projects use `poetry.lock` for exact version resolution and transitive dependency scanning.
- Legacy Python manifests do not inherit trust from an adjacent `poetry.lock`.
  They scan as legacy inputs and warn that trusted lockfile-backed transitive coverage is unavailable.
- If a Poetry manifest and `poetry.lock` disagree on a direct exact pin, `sloppy-joe` reports the lockfile as out of sync and keeps the manifest's exact version authoritative for that direct dependency.

## Parsing rules

- Included requirements files are expanded recursively, but files that are only reached through `-r` / `--requirement` are not scanned again as standalone projects during repo-root discovery.
- Exact pins keep working when they carry inline comments or pip hash options.
- `requirements*.txt` local-path, editable, VCS, and direct-URL entries fail closed.
- `Pipfile` path, VCS, URL, file, and editable sources fail closed.
- `setup.cfg` parses `install_requires` and `options.extras_require`.
- `setup.py` is only accepted when dependency declarations are statically readable from literal `install_requires` / `extras_require` values. Dynamic dependency construction fails closed.
- Non-Poetry `pyproject.toml` parses standard `[project] dependencies`, `[project.optional-dependencies]`, and `[dependency-groups]`. Dynamic dependency declarations fail closed.

## Recommendation

- Keep direct requirements pinned where practical.
- Prefer Poetry with committed `poetry.lock` for Python projects that matter.
- Treat legacy Python manifest warnings as migration work, not noise.
- Avoid local-path, editable, VCS, and direct-URL requirements in scanned manifests; they fail closed today.
