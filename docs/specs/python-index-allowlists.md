# Python Exact Index Allowlists

**Created**: 2026-04-05  
**Status**: Draft

## Context

Python Phase 1 made Poetry, `uv`, and fully hash-locked pip-tools trusted modes, but
Python source provenance is still too weak for many real AI/ML repos.

The main remaining gap is alternate index trust. Modern Python projects commonly use:

- private package indexes
- vendor wheel channels
- GPU-specific wheel indexes
- repo-visible source declarations in Poetry or `uv`

Today, the safe answer is mostly to block or under-model these cases. That is better
than silently trusting them, but it is still incomplete.

This phase should harden Python source trust the same way Cargo registry trust was
hardened:

- trust only exact authorized source URLs
- prove which source the lockfile actually resolved from
- require manifest intent and locked provenance to agree
- keep host-local and env-driven source state out of trust

## Scope

This phase is intentionally narrow.

In scope:

- Poetry source declarations in `pyproject.toml`
- repo-visible `tool.uv` source/index declarations in `pyproject.toml`
- exact normalized source URL allowlists
- source provenance checks against `poetry.lock` and `uv.lock`
- warnings for declared-but-unused non-PyPI sources

Out of scope for this phase:

- `requirements.txt` `--index-url` / `--extra-index-url`
- `pip.conf`
- `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, and other env-driven source selection
- host-local Python package-manager config outside the repo
- editable/local package provenance
- broader artifact modeling beyond what Poetry/uv already expose

## Trust Model

### What “trust” means

For Python package indexes, trust means only:

- the index URL is an authorized provenance source

It does **not** mean:

- packages from that index are considered safe
- packages from that index skip typosquat, metadata, age-gate, or vulnerability checks
- source aliases are trusted without exact URL matching
- hidden host-local source rewrites are trusted

### Default PyPI treatment

The canonical PyPI simple index remains implicitly trusted by default:

- `https://pypi.org/simple`

Trailing slash variants are treated as equivalent after normalization.

### Additional trusted indexes

Any non-PyPI Python source must be allowlisted by exact normalized URL.

Proposed config shape:

```json
{
  "trusted_indexes": {
    "pypi": [
      "https://download.pytorch.org/whl/cu124",
      "https://packages.example.com/simple"
    ]
  }
}
```

Rules:

- exact normalized URL matching only
- no wildcard hosts
- no path-prefix trust
- no trust from source alias alone

## URL Normalization

All Python index URLs should be normalized before comparison.

Required normalization for this phase:

- trim surrounding whitespace
- normalize trailing slash so:
  - `https://pypi.org/simple`
  - `https://pypi.org/simple/`
  are treated as equivalent

This phase does **not** add fuzzy URL equivalence beyond that. If two URLs differ in
scheme, host, or path, they are different trust identities.

## Structured Python Source Matching

### Core rule

Trusted Python source selection requires both:

- manifest intent
- lockfile provenance

Either alone is insufficient.

If a dependency is tied to a named source in repo-visible config, the resolved source in
the authoritative lockfile must match that declared source.

If the lockfile shows a package resolved from a non-PyPI source, that exact normalized
URL must be allowlisted.

## Poetry

### Inputs

- `pyproject.toml`
- `poetry.lock`

### What must be modeled

- source declarations in `pyproject.toml`
- any dependency-level source binding in manifest metadata
- actual resolved source provenance from `poetry.lock`

### Trust rules

- If a resolved package comes from normalized PyPI simple, it is allowed by default.
- If a resolved package comes from any other source, that exact normalized URL must be
  in `trusted_indexes.pypi`.
- If the manifest explicitly binds a dependency to a named source, the lockfile must
  prove the dependency resolved from the corresponding configured source URL.
- If the lockfile proves a different source than the manifest declares, block.
- If the lockfile does not prove source provenance clearly enough, block.

### Unused sources

If `pyproject.toml` declares a non-PyPI source that no locked package actually uses:

- warn
- do not block
- suggest removing the unused source for clarity and maintenance

## uv

### Inputs

- `pyproject.toml`
- `uv.lock`

### What must be modeled

- repo-visible `tool.uv` source/index configuration
- dependency-level source intent when uv metadata provides it
- actual resolved package source provenance from `uv.lock`

### Trust rules

- If a resolved package comes from normalized PyPI simple, it is allowed by default.
- If a resolved package comes from any other source, that exact normalized URL must be
  in `trusted_indexes.pypi`.
- If the manifest explicitly binds a dependency to a source/index, the lockfile must
  prove it resolved from that configured source URL.
- If the lockfile source and manifest-declared source disagree, block.
- If source provenance in `uv.lock` is missing or ambiguous, block.

### Unused sources

If repo-visible uv source/index config declares a non-PyPI source that no locked package
uses:

- warn
- do not block
- suggest removing the unused source for clarity and maintenance

## Fail-Closed Conditions

The scan must block when any of these are true:

- a resolved non-PyPI source is not allowlisted
- a dependency is manifest-bound to one source, but the lockfile proves another
- source provenance in the lockfile is missing, ambiguous, or unsupported
- effective source trust depends on host-local config outside the repo
- effective source trust depends on env vars or other hidden runtime state

## Warning-Only Conditions

The scan should warn, not block, when:

- a non-PyPI source is declared in repo-visible Poetry/uv config but not used by the
  locked graph

Recommended warning content:

- identify the unused source
- say it is currently unused by the locked dependency graph
- suggest removing it for clarity and maintenance

## Host-Local and Env-Driven State

This phase keeps the existing strict boundary:

- repo-visible source config may be trusted if modeled exactly
- host-local source config outside the repo is not trusted
- env-var-driven source selection is not trusted

That means the scanner should treat these as untrusted if they affect effective source
resolution:

- `pip.conf` outside the repo
- `PIP_INDEX_URL`
- `PIP_EXTRA_INDEX_URL`
- equivalent host-local package-manager state

## Acceptance Criteria

### 1. Exact source allowlists

- **Given** a Poetry or uv project that resolves from PyPI only, **When** the scan runs,
  **Then** the project passes without extra source config.
- **Given** a Poetry or uv project that resolves from a non-PyPI source, **When** that
  exact normalized URL is allowlisted, **Then** the scan may trust it.
- **Given** a Poetry or uv project that resolves from a non-PyPI source, **When** that
  exact normalized URL is not allowlisted, **Then** the scan blocks.

### 2. URL normalization

- **Given** a trusted index config entry of `https://packages.example.com/simple`,
  **When** the lockfile shows `https://packages.example.com/simple/`, **Then** the scan
  treats them as equivalent.
- **Given** a trusted index config entry with a different scheme, host, or path than the
  lockfile source, **When** the scan runs, **Then** the scan blocks.

### 3. Manifest intent + lockfile provenance agreement

- **Given** a dependency explicitly tied to a source in Poetry or uv metadata, **When**
  the lockfile proves the same source, **Then** the scan continues.
- **Given** a dependency explicitly tied to a source in manifest metadata, **When** the
  lockfile proves a different source, **Then** the scan blocks.
- **Given** a dependency tied to a source in manifest metadata, **When** the lockfile
  does not prove any corresponding source clearly enough, **Then** the scan blocks.

### 4. Unused sources

- **Given** a repo-visible Poetry or uv source declaration that no locked package uses,
  **When** the scan runs, **Then** the scan warns and does not block.
- **Given** such a warning, **When** the user reads it, **Then** it recommends removing
  the unused source for clarity and maintenance.

### 5. Hidden source state

- **Given** effective source trust depends on host-local config outside the repo,
  **When** the scan runs, **Then** the scan blocks.
- **Given** effective source trust depends on environment variables, **When** the scan
  runs, **Then** the scan blocks.

## Test Matrix

Poetry:

- PyPI-only Poetry project passes without `trusted_indexes`
- Poetry project with allowlisted alternate source passes
- Poetry project with non-allowlisted alternate source blocks
- Poetry dependency bound to source A but locked to source B blocks
- Poetry project with unused alternate source warns only
- Poetry project with trailing-slash allowlist match passes

uv:

- PyPI-only uv project passes without `trusted_indexes`
- uv project with allowlisted alternate source passes
- uv project with non-allowlisted alternate source blocks
- uv dependency bound to source A but locked to source B blocks
- uv project with unused alternate source warns only
- uv project with trailing-slash allowlist match passes

Fail-closed:

- source provenance missing from lockfile blocks
- env-driven source trust blocks
- host-local source trust blocks

## Recommended rollout

1. Add normalized `trusted_indexes.pypi` config support
2. Implement Poetry source extraction and lockfile matching
3. Implement uv source extraction and lockfile matching
4. Add warning path for unused declared non-PyPI sources
5. Add adversarial fixtures for Poetry and uv alternate sources

## Non-Goals Reminder

This phase should not expand into:

- pip/pip-tools index flags
- local/editable package trust
- broad wildcard URL trust
- host-local source config support

Those can be separate Python phases after exact structured source trust is in place.
