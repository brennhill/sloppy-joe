# Lockfile Handling Specification

**Created**: 2026-03-22
**Status**: Implemented

## Context

### Problem / Why Now

Manifest-only scanning leaves accuracy on the table.

`sloppy-joe` already makes the conservative choice when a dependency is declared with a
range instead of an exact version: it refuses to pretend metadata and OSV results are
precise. That is correct, but incomplete. When a lockfile is present, the project often
already has the exact installed version locally. Using that resolved version materially
improves version-age checks, version-relative metadata checks, and OSV lookups without
adding network cost.

This spec adds lockfile-aware exact-version resolution while keeping manifest parsing as
the source of dependency intent. It also formalizes the default policy for unresolved
versions: if no exact version can be proven, the scan fails closed unless the user
explicitly opts into reduced-accuracy warnings with `allow_unresolved_versions`.

### Expected Outcomes

- npm and Cargo projects get exact-version checks from lockfiles when available.
- Lockfile resolution only overrides when the exact version can be proven.
- Missing or broken lockfiles do not cause silent guessing.
- Unresolved versions block by default and warn only by explicit opt-out.

### Alternatives Considered

- **Replace manifest parsing with lockfile parsing**: Loses dependency intent
  information that only manifests provide.
- **Resolve all versions optimistically**: Breaks the accuracy-first posture.
- **Skip lockfiles entirely**: Leaves accuracy on the table when data is available.

---

## Acceptance Criteria

### npm lockfile resolution

- **Given** `package.json` with `^18.2.0` and `package-lock.json` resolving `18.3.1`,
  **When** the scan runs, **Then** version-sensitive checks use `18.3.1`.
- **Given** an exact pin in `package.json` and a different version in
  `package-lock.json`, **When** the scan runs, **Then** the scan emits
  `resolution/lockfile-out-of-sync`.

### Cargo lockfile resolution

- **Given** exactly one locked version for a direct crate, **When** the scan runs,
  **Then** that exact version is used.
- **Given** multiple locked versions and an exact manifest pin `=1.2.3`,
  **When** the scan runs, **Then** the matching locked version is used.
- **Given** multiple locked versions and no exact disambiguator, **When** the scan
  runs, **Then** the scan emits `resolution/ambiguous`.

### Missing or broken lockfiles

- **Given** no supported lockfile, **When** the scan runs, **Then** the scanner falls
  back to existing manifest behavior without inventing a resolved version.
- **Given** a malformed supported lockfile, **When** the scan runs, **Then** the scan
  emits `resolution/parse-failed`.
- **Given** a lockfile that omits a direct dependency, **When** the scan runs,
  **Then** the scan emits `resolution/missing-lockfile-entry`.

### Unresolved version policy

- **Given** a direct dependency with a range or no version and no trusted exact
  lockfile result, **When** the scan runs with default config, **Then** the scan emits
  `resolution/no-exact-version` as a blocking error.
- **Given** the same dependency state, **When** the scan runs with
  `allow_unresolved_versions=true`, **Then** the scan emits
  `resolution/no-exact-version` as a warning and still skips version-sensitive checks.
- **Given** an exact manifest pin and a malformed or stale lockfile, **When** the scan
  runs, **Then** the scan emits the lockfile-state issue but MUST NOT also emit
  `resolution/no-exact-version`, because the manifest already proves an exact version.

### Fail-closed on parse errors

- **Given** a supported lockfile that exists but contains invalid syntax, **When** the
  scan parses it, **Then** `resolution/parse-failed` is emitted as a blocking error
  and the lockfile data is not used.
- **Given** a `Cargo.lock` with missing required fields in a `[[package]]` entry,
  **When** the scan parses it, **Then** `resolution/parse-failed` is emitted.

### Edge cases

- No supported lockfile is present: preserve current conservative behavior.
- A supported lockfile is malformed: emit `resolution/parse-failed`.
- `Cargo.lock` contains multiple versions of the same crate and the direct dependency
  cannot be proven exactly: emit `resolution/ambiguous`.
- Manifest exact pin conflicts with resolved lockfile version: emit
  `resolution/lockfile-out-of-sync`.
- A supported lockfile exists but the direct dependency is absent from it: emit
  `resolution/missing-lockfile-entry`.
- A dependency with a range or no version and no trusted exact resolution: emit
  `resolution/no-exact-version`.
- A manifest exact pin plus lockfile failure/out-of-sync: keep the exact manifest
  version for version-sensitive checks, and do not misclassify it as unresolved.

---

## Constraints

### Operational

- The system must not guess exact versions from ambiguous lockfile state.
- The system must not weaken current accuracy to improve apparent coverage.
- The feature must not add network round-trips.
- Phase 1 must stay reviewable and incremental.

### Security

- A broken explicit lockfile must not silently fall back to optimistic version
  resolution.
- Lockfile resolution MUST NOT alter canonical, similarity, existence, `internal`, or
  `allowed` classification.

---

## Scope Boundaries

In scope:
- `package-lock.json` and `npm-shrinkwrap.json` resolution (phase 1).
- `Cargo.lock` resolution (phase 1).
- Resolution precedence: lockfile > manifest exact > unresolved.
- `resolution/*` issue keys for all failure modes.
- `allow_unresolved_versions` config option.
- Fail-closed behavior on lockfile parse errors.

Out of scope:
- Transitive dependency scanning (separate spec).
- Replacing manifest parsing with lockfile parsing.
- `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`, `Gemfile.lock`,
  `composer.lock`, Gradle lockfiles, and Maven resolved graphs in phase 1.
- Full Cargo workspace graph traversal and renamed-dependency resolution in phase 1.
- Changing canonical, similarity, existence, `internal`, or `allowed` semantics.

---

## I/O Contracts

### Resolution precedence

1. Use a supported, trusted lockfile exact version when available.
2. Else use a manifest exact version when available.
3. Else keep the dependency unresolved, emit `resolution/no-exact-version`, and skip
   version-sensitive checks.

### Phase 1 supported lockfiles

- `package-lock.json`
- `npm-shrinkwrap.json`
- `Cargo.lock`

### Resolution issue keys

| Issue key | Meaning | Severity |
| --- | --- | --- |
| `resolution/missing-lockfile-entry` | Direct dep absent from lockfile | Blocking |
| `resolution/lockfile-out-of-sync` | Manifest pin disagrees with lockfile | Blocking |
| `resolution/ambiguous` | Multiple locked versions, cannot prove which | Blocking |
| `resolution/parse-failed` | Lockfile syntax or structure invalid | Blocking |
| `resolution/no-exact-version` | No exact version provable | Blocking (default) / Warning (with `allow_unresolved_versions`) |

### Cargo.lock strategy

- Parse direct dependencies from `Cargo.toml` exactly as today.
- Parse `Cargo.lock` with the existing `toml` dependency.
- Index locked package versions by crate name.
- Resolve exact direct versions conservatively:
  - one locked version for that name: use it
  - multiple locked versions and exact manifest pin: use the matching one
  - multiple locked versions without proof: emit `resolution/ambiguous`
  - missing locked version for a direct dependency: emit
    `resolution/missing-lockfile-entry`

### npm lockfile strategy

- Support v2/v3 `packages["node_modules/<name>"].version`.
- Support v1 `dependencies[<name>].version`.
- Resolve direct dependencies from `package.json`.
- Emit `resolution/lockfile-out-of-sync` when manifest exact pin and lockfile exact
  version disagree.

### Data shapes

- **ResolvedVersion**: Exact version chosen for a dependency, plus its source.
- **ResolutionSource**: `Lockfile` or `ManifestExact`.
- **ResolutionResult**: Resolved versions plus emitted resolution issues.
- **ResolutionProblem**: Parse failure, missing entry, ambiguity, out-of-sync state, or
  no exact version.
- **Dependency**: Existing manifest-derived direct dependency record.
- **allow_unresolved_versions**: Config switch that permits reduced-accuracy scans to
  continue, but only with visible warnings.

---

## Context Anchors

- `src/lockfiles/mod.rs` — resolver logic and types.
- `src/lib.rs` — scan orchestration; threads `ResolutionResult` into checks.
- `src/checks/metadata.rs` — version-sensitive metadata checks; uses resolved versions.
- `src/checks/malicious.rs` — exact-version OSV checks; uses resolved versions.
- `src/parsers/` — existing manifest parsers (unchanged, source of dependency intent).
- Existing `toml` dependency — used for `Cargo.lock` parsing.
- Existing JSON parsing stack — used for npm lockfiles.
- `Dependency` model — existing manifest-derived type (unchanged).

---

## Architecture

### Data Sources

- Existing manifest parsers in `src/parsers/`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `Cargo.lock`

### Modules

- `src/lockfiles/` — resolver logic and types
- `src/lib.rs` — orchestration
- `src/checks/metadata.rs` — version-sensitive metadata checks
- `src/checks/malicious.rs` — exact-version OSV checks

### Dependencies

- Existing `toml` dependency for `Cargo.lock`
- Existing JSON parsing stack for npm lockfiles
- Existing `Dependency` model and report model

### Outputs

- Trusted exact versions for version-sensitive checks
- Blocking `resolution/*` issues when lockfile state is not trustworthy
- `resolution/no-exact-version` when no exact version can be proven
- Warning-only `resolution/no-exact-version` when `allow_unresolved_versions=true`

### Integration strategy

- Keep `Dependency` as the manifest model.
- Thread `ResolutionResult` into scan orchestration.
- Emit unresolved-version policy once in scan orchestration.
- Use resolved exact versions only in metadata and malicious checks.
- Preserve current name-based and policy-based checks unchanged.
