# Python Provenance Hardening Specification

**Created**: 2026-04-04
**Status**: Draft

## Context

Python is currently secure but too narrow in `sloppy-joe`.

- The trusted Python path is Poetry with `poetry.lock`.
- Legacy manifests still scan, but they are warning-heavy and do not provide trusted
  transitive coverage.
- `uv.lock` is not yet a trusted path.
- `requirements.txt` is supported only as a legacy manifest, even when it comes from a
  reproducible pip-tools workflow.
- Alternate package indexes, first-party local packages, and editable installs are
  mostly blocked rather than modeled precisely.

That leaves one of the most common AI ecosystems under-modeled. Modern Python teams use
Poetry, `uv`, and pip-tools with hashes. AI-heavy repos also commonly use:

- private package indexes
- GPU or vendor wheel channels
- monorepo-local packages
- editable first-party packages during development

The goal of this spec is to make Python precise in the same way Cargo and JavaScript
have been hardened:

- support mainstream safe Python workflows
- require exact provenance for package indexes and artifacts
- treat first-party local packages as first-class local provenance
- keep ambiguous or hidden provenance fail-closed

## Expected Outcomes

- Poetry and `uv` become equal first-class trusted Python project modes.
- pip-tools with full hash coverage becomes a first-class trusted Python install mode.
- Plain `requirements*.txt`, `Pipfile`, `setup.cfg`, `setup.py`, and legacy
  non-Poetry `pyproject.toml` remain warning/legacy paths by default unless they can be
  elevated into an explicitly trusted mode.
- Private indexes and alternate sources are supported only by exact allowlist.
- First-party local/editable Python packages are supported only when they are
  repo-visible or exact-path allowlisted and scanned as first-class Python projects.
- Artifact identity is enforced with hashes for trusted Python modes.

## Non-Goals

- Trusting arbitrary `pip.conf`, `PIP_INDEX_URL`, or host-local Python package-manager
  configuration outside the repo by default.
- Executing Python code to discover dependencies dynamically.
- Trusting direct URL, VCS, or local-path Python dependencies without explicit local or
  source provenance rules.
- Trusting unhashed `requirements.txt` files as a first-class exact lock mode.
- Modeling every historical or niche Python resolver in this phase.

## Trusted Python Modes

Python should become a multi-trusted-path ecosystem with three distinct trust tiers.

### Tier 1: Trusted Project Lock Modes

These are authoritative, project-shaped dependency models:

- Poetry: `pyproject.toml` + `poetry.lock`
- uv: `pyproject.toml` + `uv.lock`

Properties:

- exact direct resolution
- trusted transitive extraction
- lockfile freshness/sync validation
- source and artifact provenance validation

### Tier 2: Trusted Environment Lock Mode

This is a reproducible install target, but not a universal project graph:

- pip-tools: compiled `requirements*.txt` with exact pins and full `--hash` coverage

Properties:

- exact direct resolution
- exact transitive resolution only for the compiled environment represented by that file
- artifact-hash identity enforcement
- lower universality than Poetry/uv for multi-platform and multi-Python targets

### Tier 3: Legacy / Warning Modes

These continue to scan, but are not first-class trusted lock paths:

- plain `requirements*.txt` without full hash coverage
- `Pipfile`
- `setup.cfg`
- statically readable `setup.py`
- legacy non-Poetry `pyproject.toml`

Properties:

- direct dependencies still scan
- unsafe forms still fail closed
- warning on every run in default policy
- no trusted transitive lockfile coverage unless elevated into an explicit trusted mode

## Definitions

- **Trusted Python project mode**: a Python dependency model that describes a whole
  project graph and supports exact version plus source validation for both direct and
  transitive dependencies.
- **Trusted Python install mode**: a Python dependency model that describes a concrete
  environment install set with exact version and artifact-hash validation.
- **Trusted index source**: an exact allowlisted Python package index URL.
- **Trusted local Python package**: a local package directory that resolves either under
  the scan root or to an exact allowlisted external path, and is scanned as a
  first-class Python project.
- **Trusted editable dependency**: an editable Python dependency whose target is a
  trusted local Python package.
- **Full hash coverage**: every installable package entry in a trusted requirements file
  is pinned exactly and includes one or more `--hash=` values as required by pip
  hash-checking mode.
- **Repo-visible config**: package-manager or source configuration contained within the
  scan root.

---

## Acceptance Criteria

### 1. Trusted `uv.lock`

- **Given** a Python project with `pyproject.toml` and `uv.lock`, **When** the lockfile
  is readable, supported, fresh, and internally consistent, **Then** sloppy-joe uses
  `uv.lock` as a first-class trusted lockfile path.
- **Given** a Python project with both `poetry.lock` and `uv.lock`, **When** the
  project is a uv-managed project, **Then** uv must be selected intentionally and not
  inferred from file coexistence alone.
- **Given** a `uv.lock` file whose schema or format is unsupported, **When** the scan
  runs, **Then** the scan blocks instead of partially interpreting it.
- **Given** a `uv.lock` file whose resolved graph no longer matches `pyproject.toml`,
  **When** the scan runs, **Then** the scan emits a trusted-lockfile-sync failure rather
  than trusting stale exact versions.
- **Given** a `uv.lock` package entry missing exact source or artifact identity fields
  required for trusted resolution, **When** the scan runs, **Then** the scan blocks.

### 2. Trusted pip-tools With Hashes

- **Given** a `requirements.txt` generated by pip-tools with exact pins and full hash
  coverage, **When** the scan runs, **Then** sloppy-joe treats it as a trusted Python
  install mode.
- **Given** a compiled requirements file with exact pins but missing hashes for any
  package, **When** the scan runs, **Then** it does not qualify as a trusted lock mode
  and falls back to legacy/warning handling.
- **Given** a requirements file that contains any non-exact requirement in trusted
  pip-tools mode, **When** the scan runs, **Then** the scan refuses to trust it as an
  exact environment lock.
- **Given** a trusted pip-tools requirements file that includes layered constraints,
  **When** the final install file still contains exact pins plus full hash coverage,
  **Then** the scan continues.
- **Given** multiple environment-specific compiled requirements files, **When** a repo
  chooses one as the trusted install target, **Then** sloppy-joe scopes trusted exact
  resolution to that file only and does not pretend it is universal.

### 3. Source / Index Allowlists

- **Given** a Poetry or uv dependency source configured through repo-visible metadata,
  **When** the exact source URL is allowlisted in config, **Then** the scan accepts it
  as trusted alternate index provenance.
- **Given** a source name or alias without an exact allowlisted URL, **When** the scan
  runs, **Then** the scan blocks.
- **Given** a trusted Python mode that resolves a package from a non-allowlisted index,
  **When** the scan runs, **Then** the scan blocks even if the package name and version
  look valid.
- **Given** multiple indexes are configured, **When** a package can be satisfied from
  more than one source and the resolved source cannot be proven exactly, **Then** the
  scan blocks.
- **Given** package-manager source configuration exists only in host-local state outside
  the repo, **When** the scan runs in strict mode, **Then** the scan blocks.

### 4. First-Party Local / Editable Provenance

- **Given** a local Python dependency declared through a supported local-package
  mechanism, **When** the target resolves inside the scan root and is a readable Python
  project, **Then** sloppy-joe treats it as first-party local provenance rather than a
  public PyPI package.
- **Given** a local Python dependency that resolves outside the scan root, **When** the
  exact target directory is allowlisted in config and is a readable Python project,
  **Then** the scan continues.
- **Given** a local Python dependency outside the scan root that is not exact-path
  allowlisted, **When** the scan runs, **Then** the scan blocks.
- **Given** an editable dependency whose target is a trusted local Python package,
  **When** the scan runs, **Then** the scan continues and treats it as first-party local
  provenance.
- **Given** an editable dependency targeting a non-local or untrusted package source,
  **When** the scan runs, **Then** the scan blocks.
- **Given** a first-party local Python package, **When** the scan runs, **Then**
  registry-specific metadata checks such as publisher-change and version-age must not be
  applied to that package.

### 5. Artifact-Hash Identity Enforcement

- **Given** a trusted Python mode that provides artifact hashes, **When** the scan runs,
  **Then** the package artifact identity must be validated by those hashes rather than
  only by package name and version.
- **Given** a trusted requirements file in pip hash-checking style, **When** any
  installable line lacks hashes, **Then** the scan blocks trusted-mode promotion.
- **Given** a trusted project lock mode resolves artifacts from alternate sources,
  **When** the lockfile or metadata cannot prove artifact identity, **Then** the scan
  blocks.
- **Given** the same package name and version can be served from multiple indexes,
  **When** artifact identity and resolved source do not match the trusted record,
  **Then** the scan blocks.

### 6. Markers, Extras, and Groups

- **Given** a trusted Python mode that carries dependency groups, extras, or markers,
  **When** the scan runs, **Then** sloppy-joe must preserve those scopes rather than
  flattening them into unconditional installs.
- **Given** environment markers cannot be resolved safely for the trusted mode,
  **When** the scan runs, **Then** the scan must use a documented reduced-confidence
  path or block rather than silently over- or under-approximating the graph.

### 7. Dynamic and Hidden State

- **Given** a Python manifest whose dependencies are generated dynamically from code or
  hidden host state, **When** the scan runs, **Then** the scan blocks.
- **Given** repo-local package-manager config changes the effective Python source graph,
  **When** sloppy-joe can model it exactly, **Then** it may be trusted by the same
  source and local-path rules as ordinary dependencies.
- **Given** host-local Python package-manager config changes the effective source graph,
  **When** the scan runs in strict mode, **Then** the scan blocks.

---

## Config Additions

### Trusted Indexes

Python needs exact source allowlists comparable to Cargo trusted registries.

Proposed shape:

```json
{
  "trusted_indexes": {
    "pypi": [
      "https://pypi.org/simple",
      "https://download.pytorch.org/whl/cu124"
    ]
  }
}
```

Rules:

- exact URL matching only
- no implicit trust from source alias alone
- no broad hostname trust in this phase

### Trusted Local Paths

Python should reuse the existing exact-path model rather than inventing a broad path
trust mechanism.

Proposed shape:

```json
{
  "trusted_local_paths": {
    "pypi": [
      "/opt/company/python-shared-lib"
    ]
  }
}
```

Rules:

- exact canonical directory paths only
- no parent-directory or glob trust
- symlink resolution must still land on the allowlisted exact directory

### Python Enforcement

`python_enforcement` will need to grow beyond `prefer_poetry` and `poetry_only`.

Target direction:

- `prefer_trusted`: trust Poetry, uv, and hash-locked pip-tools; warn on legacy modes
- `poetry_only`: existing strict Poetry-only policy
- `trusted_only`: require any first-class trusted Python mode and block all legacy modes

This spec does not require implementing all policy modes in the first phase, but it
does require the enforcement model to stop assuming Poetry is the only trusted path.

---

## Detection and Authority Rules

### Detection Priority

Python detection should remain manifest-first, but trusted authority should become
mode-aware.

Recommended direction:

1. Poetry project + `poetry.lock`
2. uv project + `uv.lock`
3. trusted pip-tools requirements file with full hash coverage
4. legacy Python manifest path

### No Silent Promotion

- A plain `requirements.txt` must not silently become a trusted pip-tools file unless it
  satisfies the explicit trusted criteria.
- A `pyproject.toml` must not silently assume uv or Poetry authority based only on the
  presence of a lockfile that belongs to a different tool model.

---

## Fixture and Adversarial Coverage

Python needs the same regression corpus already built for npm and Cargo.

Required fixture set:

- trusted Poetry project
- trusted uv project
- malformed `uv.lock`
- stale `uv.lock`
- trusted pip-tools with full hashes
- pip-tools missing one hash
- pip-tools with non-exact requirement
- alternate private index allowlisted
- alternate private index non-allowlisted
- first-party editable local package in-repo
- external local package exact-path allowlisted
- external local package non-allowlisted
- direct URL requirement
- VCS requirement
- dynamic dependency generation
- marker-scoped dependency
- extra-scoped dependency
- dependency-confusion case between public and private indexes

---

## Rollout Order

The implementation order should follow both impact and safety.

### Phase 1

- trusted `uv.lock`
- trusted pip-tools with hashes

### Phase 2

- source/index allowlists
- first-party local/editable provenance

### Phase 3

- artifact-hash identity enforcement across all trusted Python modes
- marker/extra/group precision tightening

This order delivers the highest adoption win first, while keeping provenance widening
behind explicit trust rules.

---

## Open Design Constraints

- Prefer repo-visible truth over hidden host configuration.
- Treat Poetry and uv symmetrically as project lock modes.
- Treat pip-tools as a strong environment lock mode, not a universal project graph.
- Preserve fail-closed behavior whenever Python provenance cannot be proven exactly.
