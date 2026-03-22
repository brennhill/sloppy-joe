# Lockfile Handling Spec

Date: 2026-03-22
Status: Draft for implementation
Owner: `sloppy-joe`

## Summary

`sloppy-joe` currently parses manifests and checks direct dependencies from the version
strings found there. That is fast, but it is not always accurate because many manifests
contain ranges instead of concrete versions. Lockfile support closes that gap by resolving
direct dependencies to the exact installed version when a supported lockfile is present.

The design in this document keeps manifest parsing as the source of dependency intent,
then layers lockfile resolution on top for version-sensitive checks only. This preserves
current behavior where it is correct, improves accuracy where exact versions are
available, and avoids guessing when the lockfile is stale, ambiguous, or unsupported.

## Problem

Manifest-only scanning has a hard accuracy limit:

- `package.json` can request `^18.2.0`, but the installed version comes from
  `package-lock.json`.
- `Cargo.toml` can request `serde = "1"`, but the installed version comes from
  `Cargo.lock`.
- Version-age checks, OSV lookups, and release-specific metadata checks are only
  accurate against an exact resolved version.

The current tool handles exact manifest pins better than before, but unresolved version
ranges still produce intentionally conservative results. That is correct, but it leaves
coverage on the table when a lockfile already exists locally.

## Goals

- Improve accuracy for version-sensitive checks without reducing accuracy elsewhere.
- Prefer local exact versions from lockfiles over manifest ranges when the resolution is
  trustworthy.
- Detect and surface stale, missing, ambiguous, or unsupported lockfile states instead of
  silently guessing.
- Add no extra network round-trips.
- Keep the first implementation incremental and easy to verify.

## Non-Goals

- Do not scan transitive dependencies in this phase.
- Do not replace manifest parsing with lockfile parsing.
- Do not infer exact versions when the lockfile is ambiguous.
- Do not add Python, Ruby, PHP, JVM, Go, or .NET lockfile support in phase 1.
- Do not change canonical, similarity, or existence checks unless resolution status makes
  a correctness issue impossible to ignore.

## Scope

Phase 1 lockfile support covers:

- `Cargo.lock`
- `package-lock.json`
- `npm-shrinkwrap.json`

Phase 1 explicitly does not cover:

- `pnpm-lock.yaml`
- `yarn.lock`
- `poetry.lock`
- `uv.lock`
- `Gemfile.lock`
- `composer.lock`
- Gradle or Maven lock data

Those belong in later phases after the Cargo and npm flows are stable.

## Design Principles

- Manifest files remain the source of direct dependency names and policy tiers.
- Lockfiles only override the exact version used by version-sensitive checks.
- If the lockfile cannot prove the exact direct dependency version, the scanner must not
  guess.
- Accuracy beats convenience: stale or ambiguous lockfile states become explicit issues.
- Performance remains linear in the number of direct dependencies and requires only local
  file reads.

## Proposed Architecture

### 1. Keep manifest parsing unchanged

Existing parsers continue to return direct dependencies from the manifest:

- package names
- requested version strings
- ecosystem

This preserves the current source of truth for:

- which dependencies are direct
- internal and allowed package classification
- canonical and similarity checks

### 2. Add a lockfile resolution layer

Introduce a new module, likely `src/lockfiles/`, that resolves exact versions for direct
dependencies after manifest parsing and before metadata and OSV checks.

Suggested data structures:

```rust
pub struct ResolvedVersion {
    pub version: String,
    pub source: ResolutionSource,
}

pub enum ResolutionSource {
    Lockfile,
    ManifestExact,
}

pub enum ResolutionProblem {
    MissingFromLockfile,
    LockfileParseFailed,
    LockfileOutOfSync,
    AmbiguousVersion,
    UnsupportedLockfile,
}
```

The primary interface should be ecosystem-specific but return a common result:

```rust
pub struct ResolutionResult {
    pub exact_versions: HashMap<String, ResolvedVersion>,
    pub issues: Vec<Issue>,
}
```

This lets the rest of the scan pipeline:

- use a resolved exact version when present
- emit lockfile issues directly into the report
- retain current conservative behavior when no trusted exact version exists

### 3. Apply resolution only where version accuracy matters

Use resolved versions in:

- metadata fetches
- version-age checks
- OSV queries
- version-specific metadata signals such as dependency explosion and maintainer change

Do not use lockfile resolution to alter:

- dependency identity
- canonical package rules
- similarity checks
- internal or allowed matching

## Resolution Precedence

For each direct dependency:

1. If a supported lockfile resolves an exact direct version and the lockfile appears in
   sync, use that exact version.
2. Else if the manifest itself pins an exact version, use the manifest exact version.
3. Else treat the dependency as unresolved and keep the current conservative issue path.

This keeps the meaning clear:

- manifest exact versions are still useful
- lockfiles are preferred because they reflect what actually installs
- range-based manifest entries stay blocked until resolution is concrete

## Cargo.lock Resolution

### Supported input

- Current root `Cargo.toml`
- Current root `Cargo.lock`

### Strategy

1. Parse direct dependencies from `Cargo.toml` exactly as today.
2. Parse `Cargo.lock` using the existing `toml` dependency.
3. Build an index of locked package versions by crate name.
4. Resolve each direct dependency using the following rules:
   - one locked version for that name: use it
   - multiple locked versions and the manifest has an exact `=x.y.z`: use the matching one
   - multiple locked versions and no exact disambiguator: emit `resolution/ambiguous`
   - no locked version for a direct manifest dependency: emit `resolution/missing-lockfile-entry`

### Why this design

This is intentionally conservative. `Cargo.lock` does not make direct-dependency
selection trivial in every case, especially when multiple versions of the same crate are
present. The tool should only claim an exact version when the lockfile proves it.

### Phase 1 limitation

This phase does not attempt full workspace-root or renamed-dependency graph traversal.
If a future implementation needs higher Cargo precision, it can add root-package
dependency graph parsing without changing the public scan model.

## npm Lockfile Resolution

### Supported input

- `package.json`
- `package-lock.json`
- `npm-shrinkwrap.json`

### Strategy

Support both common lockfile layouts:

- v2/v3 `packages["node_modules/<name>"].version`
- v1 `dependencies[<name>].version`

For each direct dependency from `package.json`:

1. Resolve the exact version from the lockfile entry for that direct package.
2. If the manifest had an exact pin and the lockfile version differs, emit
   `resolution/lockfile-out-of-sync`.
3. If the lockfile exists but the direct dependency is missing, emit
   `resolution/missing-lockfile-entry`.
4. If the lockfile cannot be parsed, emit `resolution/parse-failed`.

### Why this design

npm lockfiles are the most direct path to materially better accuracy because they map
top-level dependencies to concrete installed versions without any extra network work.

## Report Behavior

Add lockfile-related issues to the normal report as blocking errors.

Proposed check names:

- `resolution/missing-lockfile-entry`
- `resolution/lockfile-out-of-sync`
- `resolution/ambiguous`
- `resolution/parse-failed`

These are blocking because they mean the scanner cannot honestly claim exact
version-sensitive results for that dependency.

## Scan Flow Changes

Current:

1. Parse manifest dependencies
2. Classify internal and allowed packages
3. Run checks

Proposed:

1. Parse manifest dependencies
2. Attempt ecosystem-specific direct lockfile resolution
3. Attach resolution issues to the report
4. Use resolved exact versions for metadata and OSV checks
5. Fall back to manifest exact versions where no lockfile result exists
6. Keep unresolved-version issues only for dependencies with no trusted exact version

## Integration Strategy

The smallest-churn integration is:

- keep `Dependency` as the manifest model
- add a `ResolutionResult`
- thread `exact_versions: HashMap<String, ResolvedVersion>` into metadata and malicious
  checks

That avoids rewriting all parsers and keeps this feature isolated to:

- scan orchestration
- new lockfile module
- version-sensitive checks

## Failure Handling

### Missing lockfile

If no supported lockfile exists, do not emit an issue. Fall back to current behavior.

### Parse failure

If a supported lockfile exists but cannot be parsed, emit a blocking resolution issue and
fall back to conservative manifest-only handling for affected dependencies.

### Stale lockfile

If the manifest exact pin conflicts with the lockfile exact version, emit a blocking
resolution issue and do not pretend the result is trustworthy.

### Ambiguous Cargo resolution

If multiple locked versions exist and the direct dependency cannot be proven exactly,
emit a blocking resolution issue instead of guessing.

## Testing Plan

### Unit tests

- Cargo resolver returns exact version when only one locked version exists
- Cargo resolver chooses the exact manifest match when multiple locked versions exist
- Cargo resolver emits ambiguity when multiple locked versions exist and no exact match is
  provable
- npm resolver reads v2/v3 `packages` entries
- npm resolver reads v1 `dependencies` entries
- lockfile parse failures emit resolution issues

### Integration tests

- exact manifest range plus lockfile exact version removes unresolved-version issues
- metadata fetch receives the resolved lockfile version
- OSV fetch receives the resolved lockfile version
- stale lockfile produces a blocking resolution issue
- missing lockfile preserves current manifest-only behavior

## Performance Expectations

- one additional local file read per supported ecosystem
- no new network requests
- no new runtime dependencies for phase 1
- lockfile parsing should be negligible relative to registry and OSV requests

## Rollout Plan

### Slice 1

- add lockfile resolution module and types
- implement `package-lock.json` and `npm-shrinkwrap.json`
- wire resolution into metadata and OSV checks

### Slice 2

- implement `Cargo.lock`
- add ambiguity and out-of-sync reporting

### Slice 3

- add integration tests covering fallback and error paths
- document lockfile-aware behavior in `README.md`

## Change Sizing

This is not greenfield work. The codebase already exists, so implementation should be
split into accepted changes that stay reviewable by humans.

Use the repo’s accepted-change guidance:

- maximize leverage of human attention
- keep individual implementation slices between roughly 1 and 400 LOC where practical
- do not treat a large multi-thousand-line patch as one reviewable change

Large initial builds are different. This feature is not an initial build, so it should be
delivered as small reviewable increments after this spec.

## Future Work

After phase 1 is stable, add:

- `pnpm-lock.yaml`
- `yarn.lock`
- Python lockfiles such as `poetry.lock` and `uv.lock`
- `composer.lock`
- `Gemfile.lock`

Future phases can also consider scanning resolved transitive dependencies, but that is a
separate product decision and should not be mixed into direct-dependency lockfile
resolution.
