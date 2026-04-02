# Cargo Provenance Hardening Specification

**Created**: 2026-04-02
**Status**: Draft

## Context

Cargo support is currently too blunt and too weak at the same time.

- It is too blunt because common safe patterns like `workspace = true` are blocked.
- It is too weak because alternate provenance models can only be handled safely when
  sloppy-joe can prove exactly what source Cargo resolved.

The goal of this spec is to make Cargo support precise:

- support mainstream safe Cargo workflows
- keep ambiguous or under-modeled provenance fail-closed
- require explicit trust for external local paths, private registries, and optional
  reduced-confidence git usage

## Expected Outcomes

- Cargo workspaces scan cleanly when all local member crates are readable and in scope.
- Cargo `path` dependencies are supported for in-repo crates and explicitly trusted
  external crate directories.
- Private registries are supported only through exact allowlisted manifest aliases and
  exact allowlisted `Cargo.lock` source URLs.
- Cargo git dependencies remain blocked by default, but can be downgraded to warning
  only for exact pinned revisions from allowlisted repository URLs.
- Root-level provenance rewrites (`[patch]`, `[replace]`, `[source]`) remain blocked.

## Non-Goals

- Fully supporting arbitrary Cargo source types.
- Trusting manifest-side registry aliases without matching lockfile provenance.
- Trusting floating git refs like `branch`, `tag`, or unspecified revisions.
- Supporting broad directory trust for local paths.

---

## Acceptance Criteria

### Workspace Dependencies

- **Given** a Cargo workspace where crate `app` depends on crate `util` via
  `workspace = true`, **When** `util` is discoverable, readable, and scanned as its own
  Cargo project, **Then** the scan continues without a provenance failure.
- **Given** `workspace = true` but no matching in-scope Cargo crate can be proven,
  **When** the scan runs, **Then** the scan blocks with a local-dependency-source
  resolution error.

### Path Dependencies

- **Given** a Cargo dependency with `path = "../util"` that resolves under the scan
  root, **When** the target contains a readable `Cargo.toml`, **Then** the scan treats
  it as a local first-class Cargo project.
- **Given** a Cargo dependency with `path = "../shared/util"` that resolves outside the
  scan root, **When** the exact target directory is allowlisted in config and contains a
  readable `Cargo.toml`, **Then** the scan continues.
- **Given** an external `path` dependency not on the exact allowlist, **When** the scan
  runs, **Then** the scan blocks.
- **Given** a `path` dependency that resolves outside the scan root or allowlist via
  symlink tricks or traversal, **When** the scan runs, **Then** the scan blocks.
- **Given** a `path` dependency whose target directory does not contain a readable
  `Cargo.toml`, **When** the scan runs, **Then** the scan blocks.

### Private Registries

- **Given** a dependency declared with `registry = "company"`, **When** config
  allowlists both manifest alias `company` and exact lockfile source
  `registry+https://cargo.company.example/index`, **Then** the scan accepts the
  dependency as trusted registry provenance.
- **Given** an allowlisted manifest alias but a non-allowlisted exact `Cargo.lock`
  source, **When** the scan runs, **Then** the scan blocks.
- **Given** an allowlisted `Cargo.lock` source but a non-allowlisted manifest alias,
  **When** the scan runs, **Then** the scan blocks.
- **Given** a manifest alias and lockfile source that do not correspond to the same
  configured trusted registry entry, **When** the scan runs, **Then** the scan blocks.

### Git Dependencies

- **Given** a Cargo git dependency and default config, **When** the scan runs, **Then**
  the scan blocks.
- **Given** config `cargo_git_policy = "warn_pinned"` and a git dependency pinned to an
  exact revision from an allowlisted repository URL, **When** the scan runs, **Then**
  the scan continues and emits a warning on every run.
- **Given** `cargo_git_policy = "warn_pinned"` but the git dependency uses `branch`,
  `tag`, or no exact revision, **When** the scan runs, **Then** the scan blocks.
- **Given** `cargo_git_policy = "warn_pinned"` and an exact revision from a
  non-allowlisted repository URL, **When** the scan runs, **Then** the scan blocks.

### Blocked Provenance Rewrites

- **Given** `Cargo.toml` uses root-level `[patch]`, `[replace]`, or `[source]`, **When**
  the scan runs, **Then** the scan blocks.

### Trusted Resolution

- **Given** a direct registry dependency from crates.io or an allowlisted private
  registry, **When** `Cargo.lock` proves an exact version, **Then** version-sensitive
  checks use that exact version.
- **Given** a local workspace or path dependency, **When** the scan runs, **Then**
  sloppy-joe does not treat it as a crates.io dependency and instead scans the target
  local crate as its own project.

---

## Constraints

### Security

- Local path trust must be exact-directory only. No globs, no trusted parent
  directories.
- Canonicalized filesystem targets must remain stable under symlinks and traversal.
- Registry trust requires both a manifest-side alias allowlist and an exact lockfile
  source allowlist.
- Git reduced-confidence mode must not allow floating refs.
- Unsupported provenance must fail closed.

### Operational

- Safe local Cargo patterns should work without requiring users to flatten or rewrite
  legitimate workspaces.
- The config surface must stay auditable and reviewable.
- The implementation must preserve the current fail-closed posture for malformed
  manifests and lockfiles.

---

## Scope Boundaries

In scope:

- `workspace = true`
- `path = ...` local crate support
- exact external local-path allowlist
- exact trusted Cargo registry alias + source allowlist
- optional reduced-confidence pinned git policy
- explicit blocking of `[patch]`, `[replace]`, `[source]`
- test coverage for all supported and blocked provenance types

Out of scope:

- broad directory trust for local paths
- wildcard git host trust
- support for floating git refs
- support for arbitrary Cargo provenance rewriting features
- trusting registry aliases without exact lockfile provenance

---

## Config Contracts

### Trusted Local Paths

```json
{
  "trusted_local_paths": {
    "cargo": [
      "/opt/company/shared-crate"
    ]
  }
}
```

Rules:

- entries must be exact crate directories
- entries are canonicalized before comparison
- target must contain a readable `Cargo.toml`
- symlinked paths only count if their resolved target matches the exact allowlisted path

### Trusted Registries

```json
{
  "trusted_registries": {
    "cargo": [
      {
        "name": "company",
        "source": "registry+https://cargo.company.example/index"
      }
    ]
  }
}
```

Rules:

- `name` is the exact manifest-side Cargo registry alias
- `source` is the exact `Cargo.lock` source string
- both values must match the same configured entry
- either mismatch blocks the scan

### Cargo Git Policy

```json
{
  "cargo_git_policy": "warn_pinned",
  "trusted_git_sources": {
    "cargo": [
      "https://github.com/yourorg/shared-crate"
    ]
  }
}
```

Rules:

- default policy is blocking
- `warn_pinned` permits only exact pinned revisions
- repository URL must be exactly allowlisted
- every allowed pinned git dependency emits a warning on every run

---

## Architecture

### 1. Cargo Manifest Parsing

Cargo parsing must separate dependency intent from provenance policy.

- Parse dependency tables for:
  - package name
  - requested version
  - local path target
  - workspace flag
  - registry alias
  - git URL and revision metadata
- Validate provenance after parsing instead of flattening unsupported tables into vague
  unresolved dependencies.

### 2. Cargo Local Dependency Graph

Cargo local dependencies become first-class project links.

- For `workspace = true`, sloppy-joe must prove the target local crate exists and is
  scanned as a Cargo project.
- For `path = ...`, sloppy-joe must canonicalize the path, verify trust policy, and
  prove the target directory is a valid Cargo crate.
- Local crates are scanned directly as Cargo projects; they are not sent through
  crates.io registry logic.

### 3. Cargo Registry Provenance

Registry provenance is trusted only when both layers agree:

- manifest alias is allowlisted
- exact `Cargo.lock` source is allowlisted
- exact resolved source matches the configured registry entry

### 4. Cargo Git Reduced-Confidence Mode

Git support is intentionally narrow.

- default remains blocking
- optional `warn_pinned` mode only supports exact revisions from allowlisted repo URLs
- git dependencies in reduced-confidence mode remain outside normal registry trust and
  must be surfaced loudly in output

---

## Pass / Block Matrix

| Cargo feature | Default behavior | Optional config behavior |
| --- | --- | --- |
| crates.io dependency | pass | n/a |
| `workspace = true` local crate | pass if target crate is proven and scanned | n/a |
| `path = ...` under scan root | pass if target crate is proven and scanned | n/a |
| `path = ...` outside scan root | block | pass only if exact target dir is allowlisted |
| private registry alias + matching exact lockfile source | block | pass only if both alias and source are allowlisted |
| git dep pinned to exact revision | block | warn-and-continue only if repo URL is allowlisted and policy is `warn_pinned` |
| git dep using branch/tag/no revision | block | block |
| `[patch]`, `[replace]`, `[source]` | block | block |

---

## TDD Matrix

- `workspace = true` sibling crate passes
- `workspace = true` missing target blocks
- in-root `path` crate passes
- in-root `path` crate with missing `Cargo.toml` blocks
- external exact allowlisted `path` crate passes
- non-allowlisted external `path` crate blocks
- path traversal escape blocks
- symlink escape for external path blocks
- trusted registry alias + trusted exact lockfile source passes
- trusted alias + untrusted source blocks
- untrusted alias + trusted source blocks
- pinned git dep + allowlisted repo + `warn_pinned` warns and continues
- pinned git dep + non-allowlisted repo blocks
- floating git dep blocks
- `[patch]`, `[replace]`, `[source]` block

---

## Context Anchors

- `src/parsers/cargo_toml.rs`
- `src/lockfiles/cargo.rs`
- `src/lockfiles/mod.rs`
- `src/lib.rs`
- `src/config/mod.rs`
- `docs/ecosystems/CARGO.md`

