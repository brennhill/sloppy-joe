# Python

This guide covers the current Python support surface in `sloppy-joe`.

## Quick Start

Trusted Python modes today are:

- Poetry projects: `pyproject.toml` + `poetry.lock`
- uv projects: `pyproject.toml` + `uv.lock`
- pip-tools environment locks: fully hash-locked `requirements*.txt`

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
  - uv `pyproject.toml`
  - non-Poetry `pyproject.toml`
  - `requirements*.txt`
  - `Pipfile`
  - `setup.cfg`
  - statically readable `setup.py`
- Poetry projects require `poetry.lock` and use it for exact version resolution plus trusted transitive coverage.
- uv projects require `uv.lock` and use it for exact version resolution plus trusted transitive coverage.
- pip-tools requirements are trusted only when every installable requirement is exact-pinned and fully hash-covered, including recursively included requirement files.
- Repo-visible Poetry and uv sources can use exact normalized Python index allowlists through `trusted_indexes.pypi`.
- For Poetry and uv, manifest source intent and lockfile provenance must agree before a non-PyPI source is trusted.
- A repo-defined Poetry or uv source named `pypi` is not trusted unless it resolves to the canonical PyPI simple index. A custom index pretending to be `pypi` fails closed.
- Declared but unused non-PyPI Poetry/uv sources warn and suggest removal for clarity and maintenance.
- Legacy Python manifests are still scanned for direct dependencies and standard signals like existence, similarity, canonicals, and vulnerabilities.
- Included requirements files are expanded recursively.
- `setup.py` is accepted only when dependency declarations are statically readable from literal values.

## What blocks

- Poetry projects without a readable `poetry.lock`.
- uv projects without a readable `uv.lock`.
- Malformed Poetry lockfiles.
- Malformed, stale, or unsupported `uv.lock` files.
- Mixed Poetry and uv project metadata in the same `pyproject.toml`.
- Poetry or uv projects whose locked graph resolves from a non-PyPI source that is not allowlisted exactly in `trusted_indexes.pypi`.
- Poetry or uv dependencies whose declared source intent disagrees with the resolved source in the lockfile.
- Poetry or uv source declarations that reuse the reserved name `pypi` for a non-canonical index URL.
- Hash-locked pip-tools requirements that are missing hashes, use non-exact pins, or inherit an included file that is not fully hash-locked.
- Unsafe legacy dependency forms, including:
  - direct URLs
  - editable installs
  - local paths
  - VCS sources
- Dynamic `setup.py` dependency construction.
- Legacy Python manifests entirely, if `python_enforcement` is set to `poetry_only`.

## Current limitations

- Poetry and uv are first-class trusted project modes.
- pip-tools with full hashes is a trusted environment-lock mode, but it is narrower than Poetry or uv because it represents a compiled install set rather than a richer project graph.
- Poetry and uv support repo-visible custom indexes by exact normalized URL allowlist only. PyPI stays implicitly trusted as `https://pypi.org/simple/`.
- `pypi` is treated as a reserved identity, not a user-chosen alias. We are not aware of a legitimate reason to rename a custom index to `pypi`, and doing so is more likely to indicate confusion, misconfiguration, or an attack than a valid use case.
- Legacy manifests remain allowed in the default `prefer_poetry` mode, but they warn on every run and do not inherit trusted transitive coverage.
- pip/pip-tools `--index-url` and `--extra-index-url`, editable/local first-party provenance, and stronger cross-mode artifact/source modeling are still future work.
- Dynamic dependency generation fails closed rather than being partially interpreted.

## Recommended workflow

- Prefer Poetry or uv with a committed lockfile.
- If you use non-PyPI Poetry or uv sources, allowlist the exact normalized index URL under `trusted_indexes.pypi`.
- If you use pip-tools, compile exact pins with hashes and commit the compiled requirements file.
- Treat legacy manifest warnings as migration work, not noise.
- Keep exact pins where practical in legacy manifests.
- Use `python_enforcement = "poetry_only"` once the repo is fully migrated to Poetry.
