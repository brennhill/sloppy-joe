# Transitive Dependency Scanning Specification

**Created**: 2026-03-22
**Status**: Draft
**Input**: "Transitive deps are the biggest structural gap. The lockfile data is already there."

## Context

### Problem / Why Now

The majority of real-world supply chain attacks target transitive dependencies —
packages that the developer never explicitly chose. event-stream, ua-parser-js,
colors.js, and node-ipc were all transitive deps in most affected projects. sloppy-joe
currently ignores them entirely.

The data already exists. `package-lock.json` contains every transitive dep with its
exact installed version. `Cargo.lock` does the same. sloppy-joe reads these files today
but only uses them to resolve direct dep versions. Extending the scan to cover the full
tree closes the single largest coverage gap identified in the adversarial security review.

### Expected Outcomes

- Transitive deps get existence, metadata, and OSV checks by default.
- Issues are clearly labeled as direct or transitive with dependency chain info.
- Full similarity checking on transitive deps is available via `--deep` (opt-in).
- Performance remains acceptable with bounded concurrency and caching.
- No regressions in existing direct-dep scanning behavior.

### Alternatives Considered

- **Scan only direct deps (status quo)**: Leaves the largest attack surface uncovered.
- **Full similarity on all deps by default**: Generates ~36,000 mutation queries for a
  medium project. Too expensive for default behavior.
- **Separate transitive-only command**: Fragments the user experience. Better to extend
  the existing `check` command with `--deep`.

---

## Acceptance Criteria

### Existence and OSV checks on transitive deps (default)

- **Given** a lockfile with transitive dep `event-stream@3.3.6` which has a known
  OSV entry, **When** the scan runs, **Then** the scan emits
  `malicious/known-vulnerability` for `event-stream` with severity Error.
- **Given** a lockfile with transitive dep `nonexistent-pkg` which does not exist on
  the registry, **When** the scan runs, **Then** the scan emits `existence` for
  `nonexistent-pkg`.
- **Given** a lockfile with 1,200 clean transitive deps, **When** the scan runs,
  **Then** no transitive issues are emitted and the scan completes in reasonable time.

### Transitive vs direct issue labeling

- **Given** a transitive dep issue, **When** displayed, **Then** the issue includes
  a field or label indicating it is transitive and names the direct dep(s) that
  pull it in (when determinable from the lockfile).
- **Given** JSON output, **When** parsed, **Then** transitive issues have a
  `"source": "transitive"` field (direct issues have `"source": "direct"`).

### Full similarity with --deep flag

- **Given** `--deep` flag, **When** the scan runs, **Then** similarity checks run
  on ALL deps (direct + transitive), not just direct deps.
- **Given** `--deep` flag with a large lockfile, **When** the scan runs, **Then**
  registry queries respect per-ecosystem concurrency limits and the 7-day similarity
  cache reduces subsequent runs to near-zero queries.
- **Given** no `--deep` flag, **When** the scan runs, **Then** similarity checks
  run only on direct deps (current behavior preserved).

### Metadata checks on transitive deps

- **Given** a transitive dep that is 2 days old with 5 downloads and install scripts,
  **When** the scan runs, **Then** the scan emits `metadata/new-package`,
  `metadata/low-downloads`, and `metadata/install-script-risk`.
- **Given** a transitive dep where the maintainer changed between versions, **When**
  the scan runs, **Then** `metadata/maintainer-change` is emitted.

### Projected transitive deps (Python manifests without a lockfile)

`requirements*.txt` without hashes, `setup.py`, `setup.cfg`, a non-Poetry/uv `pyproject.toml`
and a `Pipfile` without `Pipfile.lock` record no transitive tree. Their transitive deps are
projected from PyPI metadata instead of read from a lockfile.

- **Given** `requirements.txt` with `requests>=2` and PyPI listing `requests` 2.31.0 whose
  `requires_dist` names `urllib3<3,>=1.21.1` and `ghost-helper>=1` (not on PyPI), **When** a full
  scan runs, **Then** `urllib3` is checked at the newest non-yanked final version below 3 with
  `"source": "transitive"`, `ghost-helper` gets a blocking `existence` issue, every finding on a
  projected package ends with the `[projected transitive: ...]` note, and a
  `resolution/python-projected-transitives` warning says the versions were projected and may
  differ from what pip installs.
- **Given** `requests==2.31.0`, **When** the projection runs, **Then** it reads that release's
  metadata without listing versions.
- **Given** a release with a wheel whose core metadata file PyPI serves (PEP 658/714
  `core-metadata` hash on the file), **Then** the `Requires-Dist` of that file (fetched from the
  PyPI file host, sha256-verified) is followed instead of `info.requires_dist`, which PyPI takes
  from the first file uploaded; each read counts against the metadata-fetch bound, and a failed
  read blocks with `resolution/python-projection-failed`. **Given** `requires_dist: null` and no
  wheel with a hashed core metadata file, **Then** `resolution/python-unprojectable` warns that
  the release's dependencies are unknown.
- **Given** a requirement with `extra == "socks"`, **When** `socks` is not requested, **Then** it is
  not followed; **Given** a `sys_platform == "win32"` marker on a Linux runner, **Then** it is
  followed (markers are evaluated for every environment; undecided counts as true).
- **Given** two dependents requiring `shared>=1` and `shared<2`, **Then** `shared` is checked at the
  newest version satisfying both; **Given** `shared<2` and `shared>=3`, **Then** the newest version
  each allows is checked and `resolution/python-projected-conflict` warns.
- **Given** a PyPI lookup that fails, a `Requires-Dist` entry that is a direct URL or local path, or
  a listed release PyPI serves no metadata for, **Then** `resolution/python-projection-failed`
  blocks and the rest is still projected.
- **Given** a closure deeper than 40 levels, with more than 500 projected packages (direct deps not
  counted) or needing more than 1500 PyPI metadata requests, **Then**
  `resolution/python-projection-bound` blocks, naming the bound.
- **Given** a requirements graph with an allowlisted non-PyPI `--index-url`/`--extra-index-url`,
  or a `pyproject.toml` with an allowlisted `[[tool.pdm.source]]` other than PyPI (its build and
  tool dependencies included), **Then** PyPI is not queried for that manifest and
  `resolution/python-unprojectable` warns;
  **Given** an `internal` package (direct or transitive), **Then** it is never looked up on PyPI
  and the same warning names it.
- **Given** a fast scan, **Then** nothing is projected.

### Edge cases

- Lockfile contains deps not reachable from any direct dep (orphaned entries from
  previous installs): still check them — they're in the installed tree.
- Same package appears at multiple versions in the lockfile (Cargo allows this): check
  each version independently.
- Direct dep is also listed in the lockfile's transitive tree: classify as `direct`,
  not `transitive`. Direct takes precedence.
- Lockfile is absent: no transitive scanning possible, except for the Python manifests above,
  whose transitive deps are projected from PyPI metadata and labeled as projected.
- `--deep` with no lockfile: emit a warning that `--deep` requires a lockfile to
  discover transitive deps.

---

## Constraints

### Operational

- Default behavior must not break existing scans or slow them down significantly.
- Transitive similarity must be opt-in (`--deep`) due to registry load.
- Per-ecosystem rate limits must be respected.
- The tool must not pretend to scan transitives when no lockfile is present. Projected Python
  transitives say so: a summary warning per manifest and a note on every finding.
- A projection never stops short silently: every failed lookup and every exceeded bound blocks.
- A projection never asks PyPI about a name another index may serve (a non-PyPI index in the
  requirements graph or in `[[tool.pdm.source]]`, an `internal` package).
- Package names are validated before any registry URL is built, and versions before they are
  used as a URL path segment.
- The system MUST use the existing 7-day similarity cache for `--deep` transitive
  similarity queries.
- The system MUST use the existing 6-hour OSV cache for transitive OSV queries.
- The system MUST respect per-ecosystem concurrency limits for all transitive dep
  queries (same limits as direct deps).

### Security

- Issues must be clearly labeled as direct or transitive.
- The `internal` and `allowed` lists MUST apply to transitive deps the same way they
  apply to direct deps. Internal packages retain OSV checks. Allowed packages retain
  canonical, metadata, version-age, and OSV checks.

---

## Scope Boundaries

In scope:
- Parsing full lockfile trees for npm (`package-lock.json`, `npm-shrinkwrap.json`) and
  Cargo (`Cargo.lock`).
- Running existence, metadata, and OSV checks on transitive deps by default.
- Opt-in similarity checking on transitive deps via `--deep`.
- Labeling issues as direct or transitive with dependency chain info.
- The `--deep` CLI argument on the `check` subcommand.
- Projecting the transitive deps of Python manifests without a lockfile from PyPI metadata.

Out of scope:
- Reproducing pip's resolver for projected deps: `-c` constraint files, pip configuration and
  environment variables, backtracking, the target interpreter. Projected versions are a model.
- New CLI flags for the projection; its bounds are fixed.
- Lockfile formats not yet supported (pnpm, yarn, poetry, etc.).
- Workspace/monorepo support (scanning multiple lockfiles).
- Dependency graph visualization.
- Automated remediation (updating transitive deps).
- Transitive dep pinning recommendations.
- Ecosystems without supported lockfile formats (Go, Ruby, PHP, JVM, .NET in phase 1).

---

## I/O Contracts

### CLI signatures

```
sloppy-joe check [--deep] [existing flags...]
```

- `--deep`: Run similarity checks on all deps (direct + transitive). Without this flag,
  similarity runs only on direct deps.

### Check names emitted

All existing check names apply to transitive deps. No new check families are introduced.
Projection adds, all with `"source": "transitive"`:

| Check | Severity | When |
| --- | --- | --- |
| `resolution/python-projected-transitives` | Warning | A manifest's transitive deps were projected (count, reduced confidence, lockfile remedy). |
| `resolution/python-projected-conflict` | Warning | No version satisfies every collected specifier of a package. |
| `resolution/python-unprojectable` | Warning | Non-PyPI index, `internal` package, or a release PyPI has no dependency metadata for. |
| `resolution/python-projection-failed` | Error | A metadata lookup failed or a requirement cannot be modeled. |
| `resolution/python-projection-bound` | Error | The depth, package or metadata-fetch bound was exceeded. |

The registry contract gains `RegistryMetadata::pypi_versions(name)` (every listed version and
whether it is yanked; `None` when the package does not exist) and
`RegistryMetadata::pypi_requires_dist(name, version)` (`info.requires_dist` from
`/pypi/<name>/<version>/json`, with `metadata_missing` when it is `null` and no wheel has a
hashed core metadata file, and `wheel_metadata` naming the wheel to read when one has) and
`RegistryMetadata::pypi_wheel_requires_dist(name, wheel)` (the `Requires-Dist` of
`<wheel url>.metadata`, verified against its published sha256). Registries that cannot answer
return an error.

### Data shapes

```
Issue {
  ...existing fields...
  source: "direct" | "transitive"
}
```

- **TransitiveDep**: A dependency discovered in the lockfile that is not a direct
  manifest dependency.
- **DependencySource**: `Direct` or `Transitive`. Attached to each Issue.
- **DependencyChain**: The path from a direct dep to a transitive dep (optional,
  best-effort).

### Human-readable output

Transitive issues MUST be visually distinguished (e.g., a `[transitive]` label or
separate section).

### JSON output

Transitive issues MUST have a `"source": "transitive"` field. Direct issues MUST have
`"source": "direct"`.

### Lockfile parsing contracts

#### npm (package-lock.json v2/v3)

All entries under `packages` except the root (`""`) are installed packages. Direct deps
are those also listed in the manifest's `dependencies`/`devDependencies`. Everything
else is transitive.

```
packages["node_modules/express"] → direct (if in package.json)
packages["node_modules/express/node_modules/body-parser"] → transitive
packages["node_modules/body-parser"] → transitive (unless in package.json)
```

#### npm (package-lock.json v1)

All entries under `dependencies` are installed packages. Nested `dependencies` within
an entry are transitive.

#### Cargo.lock

All `[[package]]` entries are installed packages. Direct deps are those in
`Cargo.toml`'s `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`.
Everything else is transitive.

### Performance estimates

| Scenario | Deps | Existence queries | OSV queries | Similarity queries (--deep) |
| --- | --- | --- | --- | --- |
| Small npm project | 200 | 200 | 200 | ~6,000 |
| Medium npm project | 800 | 800 | 800 | ~24,000 |
| Large npm monorepo | 2,000 | 2,000 | 2,000 | ~60,000 |

With the 7-day similarity cache, the `--deep` cost is paid once and subsequent runs
are near-instant. Existence and OSV queries are lightweight and cached (6h for OSV).

---

## Context Anchors

- `src/lockfiles/mod.rs` — existing lockfile parsers; extend to parse full tree.
- `src/parsers/` — existing manifest parsers (unchanged).
- `src/lib.rs` — scan orchestration; add transitive check orchestration and `--deep`
  flag handling.
- `src/main.rs` — CLI argument parsing; add `--deep` argument.
- `src/report.rs` — Issue struct; add `source` field.
- Existing `Registry`, `OsvClient`, `MetadataLookup` types — reused for transitive
  queries.
- Existing similarity, existence, metadata, malicious check modules — reused unchanged.

---

## Architecture

### Data Sources

- Existing lockfile parsers in `src/lockfiles/`
- Existing manifest parsers in `src/parsers/`
- Existing registry and OSV clients

### Modules

- `src/ecosystems/python/projection.rs` — breadth-first projection with bounds; `projection/select.rs`
  (PEP 440 version choice) and `projection/requires.rs` (one `Requires-Dist` entry and its marker).
  Reached through `EcosystemSupport::project_transitives`; the engine scans the result with the
  transitive pipeline (`src/engine/private_npm.rs`) and names no ecosystem.
- `src/registry/pypi.rs`, `src/registry/pypi_release.rs` — version listings and `Requires-Dist`.
- `src/lockfiles/mod.rs` — extend to parse full lockfile tree, not just direct deps
- `src/lib.rs` — orchestrate transitive checks, add `--deep` flag handling
- `src/main.rs` — add `--deep` CLI argument
- `src/report.rs` — add `source` field to Issue

### Dependencies

- Existing `Registry`, `OsvClient`, `MetadataLookup` types
- Existing similarity, existence, metadata, malicious check modules

### Outputs

- Issues with `source: "direct"` or `source: "transitive"`
- Human output with transitive label
- JSON output with source field
