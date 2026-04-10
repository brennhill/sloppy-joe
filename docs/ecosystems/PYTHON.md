# Python

This guide covers the current Python support surface in `sloppy-joe`.

## Quick Start

Trusted Python modes today are:

- Poetry projects: `pyproject.toml` + `poetry.lock`
- uv projects: `pyproject.toml` + `uv.lock`

Reduced-confidence Python mode:

- pip-tools environment locks: fully hash-locked `requirements*.txt` without an explicit file-bound primary index

Recommended commands:

```bash
sloppy-joe check
sloppy-joe check --full
sloppy-joe check --ci
sloppy-joe check --python-groups dev,test --python-version 3.12
sloppy-joe check --python-extras docs --python-platform linux --python-arch aarch64 --python-version 3.12
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
- Fully hash-locked pip-tools requirements provide exact pinned versions only when every installable requirement is exact-pinned and fully hash-covered, including recursively included requirement files.
- pip-tools reaches exact source provenance only when the committed requirements graph binds its own primary `--index-url` and any `--extra-index-url` values with supported HTTP(S) URLs. If the primary index is not explicitly file-bound, sloppy-joe downgrades pip-tools to reduced-confidence mode.
- Trusted Poetry and uv inputs are evaluated against one concrete Python install profile at a time instead of flattening dev/groups/extras/markers into unconditional direct dependencies.
- The default Python profile is `runtime`. When scoped dependencies exist and you do not provide a profile, sloppy-joe warns that only the runtime dependency shape was checked.
- Explicit profile selection is currently CLI-driven: `--python-groups`, `--python-extras`, `--python-platform`, `--python-arch`, and `--python-version`.
- Repo-visible Poetry and uv sources can use exact normalized Python index allowlists through `trusted_indexes.pypi`.
- For Poetry and uv, manifest source intent and lockfile provenance must agree before a non-PyPI source is trusted.
- For Poetry and uv, reachable non-PyPI packages must also be authorized by the in-scope root dependency graph; declaring an alternate source does not automatically authorize unrelated transitives.
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
- Hash-locked pip-tools requirements that declare an explicit Python index URL not allowlisted in `trusted_indexes.pypi`.
- Unsafe legacy dependency forms, including:
  - direct URLs
  - editable installs
  - local paths
  - VCS sources
  - unsupported pip global options such as `--trusted-host`
- Dynamic `setup.py` dependency construction.
- Legacy Python manifests entirely, if `python_enforcement` is set to `poetry_only`.

## Current limitations

- Poetry and uv are first-class trusted project modes.
- pip-tools with full hashes is fully trusted only when the requirements graph itself binds the primary index with `--index-url` and any non-PyPI `--extra-index-url` values are exactly allowlisted. Without an explicit primary index, pip-tools remains reduced-confidence because source selection can still come from pip config or environment variables.
- Python profile defaults and aliases are not configurable in `config.json` yet; profile selection is currently CLI-only.
- Poetry and uv support repo-visible custom indexes by exact normalized URL allowlist only. PyPI stays implicitly trusted as `https://pypi.org/simple/`.
- `pypi` is treated as a reserved identity, not a user-chosen alias. We are not aware of a legitimate reason to rename a custom index to `pypi`, and doing so is more likely to indicate confusion, misconfiguration, or an attack than a valid use case.
- `poetry_lock_policy` controls how missing Poetry proofs are handled. `strict` is the recommended CI/production setting. `warn_missing_proofs` still blocks contradictions, but it downgrades missing proof to reduced-confidence mode instead of fully trusted lock coverage.
- Legacy manifests remain allowed in the default `prefer_poetry` mode, but they warn on every run and do not inherit trusted transitive coverage.
- pip-tools still fails closed on unsupported global options and does not yet model editable/local first-party provenance beyond blocking those unsafe forms outright.
- Dynamic dependency generation fails closed rather than being partially interpreted.

## Recommended workflow

- Prefer Poetry or uv with a committed lockfile.
- If the repo uses scoped Python dependencies, make CI pass the real profile explicitly with `--python-groups`, `--python-extras`, `--python-platform`, `--python-arch`, and `--python-version`.
- In CI or production, prefer `poetry_lock_policy = "strict"` so missing Poetry proof blocks instead of silently downgrading trust.
- If you use non-PyPI Poetry or uv sources, allowlist the exact normalized index URL under `trusted_indexes.pypi`.
- If you use pip-tools, compile exact pins with hashes, commit the compiled requirements graph, and bind the primary index with `--index-url`. Any non-PyPI `--extra-index-url` must also be allowlisted under `trusted_indexes.pypi`.
- Treat legacy manifest warnings as migration work, not noise.
- Keep exact pins where practical in legacy manifests.
- Use `python_enforcement = "poetry_only"` once the repo is fully migrated to Poetry.
