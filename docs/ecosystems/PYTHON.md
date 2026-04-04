# Python

This guide covers the current Python support surface in `sloppy-joe`.

## Quick Start

The trusted Python path is Poetry:

- manifest: `pyproject.toml`
- lockfile: `poetry.lock`

Recommended commands:

```bash
sloppy-joe check
sloppy-joe check --full
sloppy-joe check --ci
```

Legacy Python manifests still scan by default, but they are not the trusted path.

## What sloppy-joe checks

- Supported manifest inputs:
  - Poetry `pyproject.toml`
  - non-Poetry `pyproject.toml`
  - `requirements*.txt`
  - `Pipfile`
  - `setup.cfg`
  - statically readable `setup.py`
- Poetry projects require `poetry.lock` and use it for exact version resolution plus trusted transitive coverage.
- Legacy Python manifests are still scanned for direct dependencies and standard signals like existence, similarity, canonicals, and vulnerabilities.
- Included requirements files are expanded recursively.
- `setup.py` is accepted only when dependency declarations are statically readable from literal values.

## What blocks

- Poetry projects without a readable `poetry.lock`.
- Malformed Poetry lockfiles.
- Unsafe legacy dependency forms, including:
  - direct URLs
  - editable installs
  - local paths
  - VCS sources
- Dynamic `setup.py` dependency construction.
- Legacy Python manifests entirely, if `python_enforcement` is set to `poetry_only`.

## Current limitations

- Poetry is the only trusted Python lockfile path today.
- Legacy manifests remain allowed in the default `prefer_poetry` mode, but they warn on every run and do not inherit trusted Poetry transitive coverage.
- `uv.lock` is not yet supported as a trusted Python lockfile.
- Dynamic dependency generation fails closed rather than being partially interpreted.

## Recommended workflow

- Prefer Poetry with a committed `poetry.lock`.
- Treat legacy manifest warnings as migration work, not noise.
- Keep exact pins where practical in legacy manifests.
- Use `python_enforcement = "poetry_only"` once the repo is fully migrated to Poetry.
