# Manifest & Lockfile Coverage Specification

**Created**: 2026-03-22
**Status**: Draft
**Input**: "Unsupported formats mean deps are invisible. pyproject.toml, pnpm-lock.yaml, yarn.lock."

## Context

### Problem / Why Now

sloppy-joe is invisible to projects that don't use a supported manifest format. A Python
project using `pyproject.toml` (the modern standard since PEP 621) gets "Could not
detect project type" — and either the team disables the check or runs without protection.
The same applies to JavaScript projects using pnpm or yarn, which together represent a
large share of the npm ecosystem.

Every unsupported format is an attacker's free pass. If the tool can't see the
dependencies, it can't check them.

### Expected Outcomes

- Python projects using `pyproject.toml` (PEP 621 and Poetry formats) are scanned.
- JavaScript projects using pnpm or yarn get lockfile version resolution.
- Python lockfiles (`poetry.lock`, `uv.lock`) provide version resolution.
- Pipenv projects using `Pipfile` are scanned.
- Auto-detection correctly prioritizes the most authoritative manifest.
- All new parsers produce the same types as existing parsers.

### Alternatives Considered

- **Support only PEP 621**: Misses Poetry-format `pyproject.toml` projects, which are
  still common.
- **Parse `setup.py`**: Requires executing Python code to extract dependencies — a
  security risk for a supply chain security tool.
- **Support all lockfile formats at once**: Too large a change for one phase. pnpm and
  yarn are the highest-leverage targets.

---

## Acceptance Criteria

### Python pyproject.toml (PEP 621)

- **Given** a `pyproject.toml` with `[project.dependencies]`, **When** the scan runs,
  **Then** all listed dependencies are checked.
- **Given** a `pyproject.toml` with `[project.optional-dependencies]`, **When** the
  scan runs, **Then** optional dependency groups are also checked.
- **Given** both `pyproject.toml` and `requirements.txt` in the same directory,
  **When** auto-detection runs, **Then** `pyproject.toml` takes precedence (it is the
  authoritative source; requirements.txt may be a generated subset).

### Python pyproject.toml (Poetry)

- **Given** a `pyproject.toml` with `[tool.poetry.dependencies]`, **When** the scan
  runs, **Then** all listed dependencies are checked (excluding `python` runtime
  constraint).
- **Given** a `pyproject.toml` with `[tool.poetry.group.dev.dependencies]`, **When** the
  scan runs, **Then** dev dependencies are also checked.

### pnpm lockfile resolution

- **Given** `package.json` + `pnpm-lock.yaml`, **When** the scan runs, **Then**
  exact versions are resolved from the pnpm lockfile.
- **Given** a dep with `^18.2.0` in `package.json` and `18.3.1` resolved in
  `pnpm-lock.yaml`, **When** the scan runs, **Then** version-sensitive checks use
  `18.3.1`.

### Yarn lockfile resolution

- **Given** `package.json` + `yarn.lock`, **When** the scan runs, **Then** exact
  versions are resolved from the yarn lockfile.
- **Given** Yarn berry (`yarn.lock` v6+ format), **When** the scan runs, **Then**
  the newer format is also parsed.

### Python lockfile resolution

- **Given** `pyproject.toml` + `poetry.lock`, **When** the scan runs, **Then** exact
  versions are resolved from poetry.lock.
- **Given** `pyproject.toml` + `uv.lock`, **When** the scan runs, **Then** exact
  versions are resolved from uv.lock.

### Pipfile support

- **Given** a `Pipfile` with `[packages]` and `[dev-packages]`, **When** the scan
  runs, **Then** all listed dependencies are checked.

### Edge cases

- `pyproject.toml` with only `[build-system.requires]` and no `[project.dependencies]`:
  check the build deps (they're still installed and can be malicious).
- `pyproject.toml` using Poetry's `[tool.poetry.dependencies]` instead of PEP 621's
  `[project.dependencies]`: support both formats.
- Auto-detection priority when multiple manifests exist: `pyproject.toml` >
  `requirements.txt` > `Pipfile` for Python.
- `pnpm-lock.yaml` present but `package.json` missing: skip (manifest is the source
  of dependency intent; lockfile alone is not sufficient).

---

## Constraints

### Operational

- New parsers must not break existing manifests or lockfiles.
- Auto-detection must prefer the most authoritative manifest when multiple exist.
- All new parsers MUST produce the same `Dependency` struct as existing parsers.
- All new lockfile parsers MUST produce the same `ResolutionResult` as existing lockfile
  parsers.
- All existing checks (existence, similarity, metadata, OSV, canonical) MUST work
  unchanged with deps from new parsers.

### Security

- PEP 503 normalization must apply to all Python manifest formats consistently
  (lowercase, `[-_.]` to `-`).
- `setup.py` parsing is excluded because it requires executing arbitrary Python code.

---

## Scope Boundaries

In scope:
- `pyproject.toml` parsing (PEP 621 and Poetry formats).
- `Pipfile` parsing.
- `pnpm-lock.yaml` parsing.
- `yarn.lock` parsing (v1 and berry formats).
- `poetry.lock` parsing.
- `uv.lock` parsing.
- Auto-detection priority updates.
- PEP 503 name normalization for all Python formats.

Out of scope:
- `setup.py` (requires executing Python code to extract dependencies — security risk).
- `setup.cfg` (legacy, declining usage).
- `Gemfile.lock`, `composer.lock`, Gradle lockfiles (separate phase).
- Workspace/monorepo manifest merging.

---

## I/O Contracts

### Manifest input formats

#### pyproject.toml (PEP 621)

```toml
[project]
dependencies = [
    "requests>=2.28",
    "click~=8.0",
    "pydantic",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "black"]
```

Parse each string using the same version-extraction logic as requirements.txt.

#### pyproject.toml (Poetry)

```toml
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"
click = {version = "~8.0", optional = true}

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
```

Skip `python` (it's a runtime constraint, not a package dep).

#### pnpm-lock.yaml

```yaml
lockfileVersion: '9.0'
packages:
  'react@18.3.1':
    resolution: {integrity: sha512-...}
    engines: {node: '>=0.10.0'}
```

Key format: `name@version`. Parse name and version from the key.

#### yarn.lock (v1)

```
react@^18.2.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#..."
  integrity sha512-...
```

Parse package name from the key (before `@`), version from the `version` field.

### Lockfile discovery order

- npm: `package-lock.json` > `npm-shrinkwrap.json` > `pnpm-lock.yaml` > `yarn.lock`
- PyPI: `poetry.lock` > `uv.lock`

### Auto-detection priority (Python)

`pyproject.toml` > `requirements.txt` > `Pipfile`

### Data shapes

All parsers produce the existing `Dependency` struct (name, version, ecosystem).
All lockfile parsers produce the existing `ResolutionResult` type.

### PEP 503 normalization

All Python package names are normalized: lowercase, `[-_.]` replaced with `-`.
This applies regardless of which manifest format is used.

---

## Context Anchors

- `src/parsers/mod.rs` — existing auto-detection logic; update detection order.
- `src/parsers/` — existing manifest parsers; new parsers follow same patterns.
- `src/lockfiles/mod.rs` — existing lockfile parsers; add pnpm, yarn, poetry, uv.
- `Dependency` struct — existing type that all new parsers must produce.
- `ResolutionResult` — existing type that all new lockfile parsers must produce.
- PEP 503 — Python package name normalization standard.
- PEP 621 — Python `pyproject.toml` project metadata standard.
- `toml` crate — already a dependency, used for pyproject.toml and Pipfile parsing.

---

## Architecture

### Data Sources

- `pyproject.toml` (PEP 621 and Poetry formats)
- `Pipfile`
- `pnpm-lock.yaml`
- `yarn.lock` (v1 and berry formats)
- `poetry.lock`
- `uv.lock`

### Modules

- `src/parsers/pyproject_toml.rs` — new parser for PEP 621 + Poetry formats
- `src/parsers/pipfile.rs` — new parser for Pipenv
- `src/parsers/mod.rs` — update auto-detection order
- `src/lockfiles/mod.rs` — add pnpm, yarn, poetry, uv lockfile parsers

### Dependencies

- `toml` crate (already a dependency, for pyproject.toml and Pipfile)
- `serde_yaml` or manual YAML parsing for pnpm-lock.yaml
- Manual line parsing for yarn.lock v1 (not YAML, not JSON — custom format)
