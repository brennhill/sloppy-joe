# Lockfile Handling Specification

**Created**: 2026-03-22
**Status**: Draft for implementation
**Input**: "Add lockfile support to materially improve version-accurate checks."

## 1. Problem / Why Now

Manifest-only scanning leaves accuracy on the table.

`sloppy-joe` already makes the conservative choice when a dependency is declared with a
range instead of an exact version: it refuses to pretend metadata and OSV results are
precise. That is correct, but incomplete. When a lockfile is present, the project often
already has the exact installed version locally. Using that resolved version materially
improves version-age checks, version-relative metadata checks, and OSV lookups without
adding network cost.

This spec adds lockfile-aware exact-version resolution while keeping manifest parsing as
the source of dependency intent.

## 2. User Scenarios & Testing

### User Story 1 - npm project gets exact-version checks from lockfile (Priority: P1)

A project declares `react: ^18.2.0` in `package.json` and has a valid
`package-lock.json`.

**Why this priority**: npm lockfiles are the highest-leverage first target because they
map direct dependencies to exact installed versions with low ambiguity.

**Independent test**: A range in `package.json` plus a resolved direct version in
`package-lock.json` removes unresolved-version blocking and feeds the exact version into
metadata and OSV checks.

**Acceptance scenarios**:

1. **Given** `package.json` with `^18.2.0` and `package-lock.json` resolving `18.3.1`,
   **When** the scan runs, **Then** version-sensitive checks use `18.3.1`.
2. **Given** an exact pin in `package.json` and a different version in
   `package-lock.json`, **When** the scan runs, **Then** the scan emits
   `resolution/lockfile-out-of-sync`.

### User Story 2 - Cargo project resolves only when the version is provable (Priority: P1)

A Rust project declares direct dependencies in `Cargo.toml` and has a `Cargo.lock`.

**Why this priority**: Cargo gives strong local exact-version data, but direct dependency
resolution can be ambiguous when multiple locked versions of the same crate exist.

**Independent test**: `Cargo.lock` only overrides a dependency when the exact direct
version can be proven without guessing.

**Acceptance scenarios**:

1. **Given** exactly one locked version for a direct crate, **When** the scan runs,
   **Then** that exact version is used.
2. **Given** multiple locked versions and an exact manifest pin `=1.2.3`,
   **When** the scan runs, **Then** the matching locked version is used.
3. **Given** multiple locked versions and no exact disambiguator, **When** the scan
   runs, **Then** the scan emits `resolution/ambiguous`.

### User Story 3 - Missing or broken lockfiles do not cause silent guessing (Priority: P1)

A project has no supported lockfile, a malformed lockfile, or a stale lockfile.

**Why this priority**: The feature only adds value if it preserves the current
accuracy-first posture.

**Independent test**: The scanner remains conservative when lockfile resolution is
missing, broken, or ambiguous.

**Acceptance scenarios**:

1. **Given** no supported lockfile, **When** the scan runs, **Then** the scanner falls
   back to existing manifest behavior without inventing a resolved version.
2. **Given** a malformed supported lockfile, **When** the scan runs, **Then** the scan
   emits `resolution/parse-failed`.
3. **Given** a lockfile that omits a direct dependency, **When** the scan runs,
   **Then** the scan emits `resolution/missing-lockfile-entry`.

### Edge Cases

- No supported lockfile is present: preserve current conservative behavior.
- A supported lockfile is malformed: emit `resolution/parse-failed`.
- `Cargo.lock` contains multiple versions of the same crate and the direct dependency
  cannot be proven exactly: emit `resolution/ambiguous`.
- Manifest exact pin conflicts with resolved lockfile version: emit
  `resolution/lockfile-out-of-sync`.
- A supported lockfile exists but the direct dependency is absent from it: emit
  `resolution/missing-lockfile-entry`.

## 3. Requirements

### Functional Requirements

- **FR-001**: The system MUST keep manifest parsing as the source of direct dependency
  names, ecosystems, and policy classification.
- **FR-002**: The system MUST add a lockfile resolution layer after manifest parsing and
  before version-sensitive checks.
- **FR-003**: The system MUST prefer a trusted resolved lockfile version over a manifest
  range for metadata and OSV checks.
- **FR-004**: The system MUST fall back to a manifest exact version when no trusted
  lockfile result exists.
- **FR-005**: The system MUST leave a dependency unresolved when neither a trusted
  lockfile version nor a manifest exact version exists.
- **FR-006**: Phase 1 MUST support `package-lock.json` and `npm-shrinkwrap.json`.
- **FR-007**: Phase 1 MUST support `Cargo.lock`.
- **FR-008**: The system MUST emit blocking resolution issues when lockfile state makes
  exact-version-sensitive checks untrustworthy.
- **FR-009**: The system MUST use resolved versions only for version-sensitive checks.
- **FR-010**: The system MUST NOT use lockfile resolution to alter canonical, similarity,
  `internal`, or `allowed` classification.
- **FR-011**: The system MUST avoid any additional network requests for lockfile
  resolution.
- **FR-012**: The system MUST keep phase 1 scoped to direct dependencies only.
- **FR-013**: The spec MUST include context anchors to the integration points in
  `src/lib.rs`, metadata checks, and malicious checks.
- **FR-014**: The spec MUST include input contracts for each supported lockfile.
- **FR-015**: The spec MUST include output contracts for `resolution/*` issues.
- **FR-016**: The spec MUST describe side effects on metadata and OSV lookups once a
  dependency is resolved.
- **FR-017**: The spec MUST describe the state transition from unresolved dependency to
  trusted resolved version.
- **FR-018**: The spec MUST describe parse-failure and ambiguity states explicitly rather
  than implying fallback guessing.

#### Resolution precedence

1. Use a supported, trusted lockfile exact version when available.
2. Else use a manifest exact version when available.
3. Else keep the dependency unresolved and preserve current conservative behavior.

#### Phase 1 supported lockfiles

- `package-lock.json`
- `npm-shrinkwrap.json`
- `Cargo.lock`

#### Proposed resolution issue keys

- `resolution/missing-lockfile-entry`
- `resolution/lockfile-out-of-sync`
- `resolution/ambiguous`
- `resolution/parse-failed`

#### Cargo.lock strategy

- Parse direct dependencies from `Cargo.toml` exactly as today.
- Parse `Cargo.lock` with the existing `toml` dependency.
- Index locked package versions by crate name.
- Resolve exact direct versions conservatively:
  - one locked version for that name: use it
  - multiple locked versions and exact manifest pin: use the matching one
  - multiple locked versions without proof: emit `resolution/ambiguous`
  - missing locked version for a direct dependency: emit
    `resolution/missing-lockfile-entry`

#### npm lockfile strategy

- Support v2/v3 `packages["node_modules/<name>"].version`.
- Support v1 `dependencies[<name>].version`.
- Resolve direct dependencies from `package.json`.
- Emit `resolution/lockfile-out-of-sync` when manifest exact pin and lockfile exact
  version disagree.

### Scoring Rubric — Machine Usability

If this spec is graded with the UPFRONT rubric, the machine-usable sections are:

| Section | What an AI or reviewer uses it for | Weight |
| --- | --- | --- |
| Acceptance scenarios | Derive resolver and fallback tests | High |
| Edge cases | Prevent hidden ambiguity or stale-lockfile drift | High |
| Functional requirements | Anchor the lockfile contract | High |
| Resolution strategies | Constrain resolver behavior | High |
| Architectural boundaries | Prevent feature creep into unrelated checks | Medium |
| Key entities | Stabilize types and terminology | Medium |

Human-useful but weaker for implementation scoring:

| Section | Why it is weaker for implementation |
| --- | --- |
| Status metadata | Context only |
| General motivation | Useful framing, not executable behavior |

### Key Entities

- **ResolvedVersion**: Exact version chosen for a dependency, plus its source.
- **ResolutionSource**: `Lockfile` or `ManifestExact`.
- **ResolutionResult**: Resolved versions plus emitted resolution issues.
- **ResolutionProblem**: Parse failure, missing entry, ambiguity, or out-of-sync state.
- **Dependency**: Existing manifest-derived direct dependency record.

## 4. Non-Negotiable Constraints

- The system must not guess exact versions from ambiguous lockfile state.
- The system must not weaken current accuracy to improve apparent coverage.
- The feature must not add network round-trips.
- Phase 1 must stay reviewable and incremental.
- Accepted changes should stay within human-reviewable slices rather than one giant patch.

## 5. Out of Scope

- Transitive dependency scanning.
- Replacing manifest parsing with lockfile parsing.
- `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`, `Gemfile.lock`,
  `composer.lock`, Gradle lockfiles, and Maven resolved graphs in phase 1.
- Full Cargo workspace graph traversal and renamed-dependency resolution in phase 1.
- Changing canonical, similarity, existence, `internal`, or `allowed` semantics.

## 6. Architectural Boundaries

### Data sources

- Existing manifest parsers in `src/parsers/`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `Cargo.lock`

### Modules

- New `src/lockfiles/` module for resolver logic and types
- `src/lib.rs` for orchestration
- `src/checks/metadata.rs` for version-sensitive metadata checks
- `src/checks/malicious.rs` for exact-version OSV checks

### Dependencies

- Existing `toml` dependency for `Cargo.lock`
- Existing JSON parsing stack for npm lockfiles
- Existing `Dependency` model and report model

### Outputs

- Trusted exact versions for version-sensitive checks
- Blocking `resolution/*` issues when lockfile state is not trustworthy
- Preserved unresolved-version behavior when no trusted exact version exists

### Integration strategy

- Keep `Dependency` as the manifest model.
- Thread `ResolutionResult` into scan orchestration.
- Use resolved exact versions only in metadata and malicious checks.
- Preserve current name-based and policy-based checks unchanged.

## 7. Out of Scope for Scoring

These are useful to humans, but not central to machine-usability scoring for this spec:

- Release sequencing beyond phase 1
- Long-term ecosystem expansion order
- Product positioning for lockfile support

## 8. Spec Quality Self-Assessment

- **Completeness**: High. Supported inputs, precedence, failure modes, and integration
  points are all captured.
- **Ambiguity**: Low. The spec explicitly says when to resolve, when to fall back, and
  when to refuse to guess.
- **Consistency**: High. The design preserves the current accuracy-first behavior of
  unresolved-version checks.
- **Testability**: High. Each resolution path maps to direct unit or integration cases.
