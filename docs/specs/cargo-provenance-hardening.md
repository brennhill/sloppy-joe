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

- Cargo workspaces scan cleanly when `workspace = true` dependencies can be inherited
  from the nearest in-scope `[workspace.dependencies]` entry and then validated by the
  same provenance rules as local dependencies.
- Cargo `path` dependencies are supported for in-repo crates and explicitly trusted
  external crate directories.
- Private registries are supported only through exact allowlisted manifest aliases and
  exact allowlisted `Cargo.lock` source URLs.
- Cargo git dependencies remain blocked by default, but can be downgraded to warning
  only for exact pinned revisions from allowlisted repository URLs.
- Cargo provenance rewrites are supported only when the effective rewritten source can
  be proven by the same trust rules as an ordinary dependency from repo-visible
  configuration plus `Cargo.lock`.

## Non-Goals

- Fully supporting arbitrary Cargo source types.
- Trusting manifest-side registry aliases without matching lockfile provenance.
- Trusting floating git refs like `branch`, `tag`, or unspecified revisions.
- Supporting broad directory trust for local paths.
- Trusting hidden host-local Cargo configuration by default.

## Definitions

- **Valid local Cargo crate**: a directory with a readable, parseable `Cargo.toml` that
  contains a `[package]` table with a concrete crate name.
- **Workspace root**: the current manifest if it contains `[workspace]`; otherwise the
  nearest ancestor `Cargo.toml` with a `[workspace]` table.
- **In-scope workspace**: a workspace whose root canonical path is inside the scan root.
- **Workspace-inherited dependency**: a dependency declared with `workspace = true`
  whose effective provenance is inherited from the nearest in-scope
  `[workspace.dependencies]` entry.
- **Effective package name**: the real crate name for dependency identity. Use
  `package = "real-name"` when present; otherwise use the dependency table key.
- **Exact trusted local path**: an exact canonical directory path allowlisted under
  `trusted_local_paths.cargo`.
- **Exact trusted registry**: one config entry containing both a manifest alias and an
  exact `Cargo.lock` source string.
- **Exact manifest version**: a Cargo dependency version that is explicitly pinned with
  `=<version>`. Bare `1.2.3`, ranges like `^1.2`, `~1.2`, inequalities, and wildcard
  syntax are non-exact for sloppy-joe.
- **Exact pinned git revision**: a manifest `rev` that is a full 40-character lowercase
  hex commit SHA and a `Cargo.lock` git source that resolves to the same commit.
- **Exact URL match**: string equality after trimming surrounding whitespace only. No
  hostname, scheme, or path normalization is performed. Users must allowlist each exact
  spelling they intend to trust.
- **Raw lockfile registry source**: the exact trimmed `Cargo.lock` `source` field for a
  registry package, for example
  `registry+https://github.com/rust-lang/crates.io-index`.
- **Raw lockfile git source**: the exact trimmed `Cargo.lock` `source` field for a git
  package, expected in this phase to be
  `git+<repo-url>?rev=<40-hex>#<40-hex>`.
- **Lockfile discovery rule**: use the `Cargo.lock` in the current workspace root when
  the crate is under an in-scope workspace root; otherwise use `Cargo.lock` in the
  crate directory. No other `Cargo.lock` file is consulted for that crate.

---

## Acceptance Criteria

### Workspace Dependencies

- **Supported syntax**: only dependency entries under `[dependencies]`,
  `[dev-dependencies]`, `[build-dependencies]`, and target-specific dependency tables
  like `[target.'cfg(...)'.dependencies]` with `workspace = true`.
- **Identity rule**: `workspace = true` resolves by effective package name. Inherited
  metadata from `[workspace.dependencies]` may supply version/features but does not
  change package identity.
- **Member-local fields**: in this phase, member entries using `workspace = true` may
  carry only non-provenance modifiers: `package`, `features`, `default-features`, and
  `optional`. Member-local `version`, `path`, `registry`, `git`, `branch`, `tag`, or
  `rev` alongside `workspace = true` are unsupported and block.
- **Authoritative source**: inherited dependency metadata is read only from the nearest
  in-scope workspace root `Cargo.toml` under `[workspace.dependencies]`. If the
  matching workspace dependency entry is missing or uses unsupported provenance, the
  scan blocks.
- **Given** a Cargo workspace where crate `app` depends on `serde` via
  `workspace = true`, **When** the nearest in-scope workspace root defines
  `serde = "=1.0.228"` under `[workspace.dependencies]` and `Cargo.lock` proves the
  same exact crates.io resolution, **Then** the scan continues without a provenance
  failure.
- **Given** a Cargo workspace where crate `app` depends on `serde` via
  `workspace = true`, **When** the nearest in-scope workspace root defines
  `serde = "1.0"` under `[workspace.dependencies]` and `Cargo.lock` contains exactly
  one matching crates.io candidate, **Then** the scan emits
  `resolution/no-trusted-lockfile-sync` rather than trusting the exact locked version.
- **Given** the current manifest is itself the workspace root and uses
  `[workspace.dependencies]`, **When** a member dependency declares `workspace = true`,
  **Then** sloppy-joe treats the current manifest as the authoritative workspace root.
- **Given** a Cargo workspace where crate `app` depends on `util` via
  `workspace = true`, **When** the nearest in-scope workspace root defines
  `util = { path = "../util" }` under `[workspace.dependencies]` and the inherited
  path target is a valid local Cargo crate under the scan root or exact local-path
  allowlist, **Then** the scan continues.
- **Given** a Cargo workspace where crate `app` depends on `internal-crate` via
  `workspace = true`, **When** the nearest in-scope workspace root defines
  `internal-crate = { registry = "company", version = "=1.2.3" }` under
  `[workspace.dependencies]` and the manifest alias plus exact lockfile source are
  allowlisted, **Then** the scan continues.
- **Given** a Cargo workspace where crate `app` depends on `shared-lib` via
  `workspace = true`, **When** the nearest in-scope workspace root defines
  `shared-lib = { git = \"https://github.com/yourorg/shared-lib\", rev = \"0123456789abcdef0123456789abcdef01234567\" }`
  under `[workspace.dependencies]`, **Then** the inherited git provenance follows the
  same default-block or `warn_pinned` policy as a locally declared git dependency.
- **Given** a dependency is renamed with `foo = { package = "serde", workspace = true }`,
  **When** the workspace root defines `serde` under `[workspace.dependencies]`,
  **Then** provenance resolution uses the effective package name `serde`.
- **Given** `workspace = true` but the nearest in-scope `[workspace.dependencies]`
  entry is missing, **When** the scan runs, **Then** the scan blocks with
  `resolution/local-dependency-source`.
- **Given** `workspace = true` but the nearest workspace root resolves outside the scan
  root, **When** the scan runs, **Then** the scan blocks.
- **Given** `workspace = true` and the inherited provenance is unsupported
  (`git`, untrusted registry, malformed table, or blocked rewrite), **When** the scan
  runs, **Then** the scan blocks with the same issue class that would apply if that
  provenance were declared locally:
  - inherited invalid or missing local `path`: `resolution/local-dependency-source`
  - inherited untrusted registry provenance: `resolution/untrusted-registry-source`
  - inherited untrusted git provenance: `resolution/untrusted-git-source`
  - inherited blocked rewrite or malformed manifest/config state:
    `resolution/blocked-provenance-rewrite` or `resolution/parse-failed`

### Path Dependencies

- **Given** a Cargo dependency with `path = "../util"` that resolves under the scan
  root, **When** the target is a valid local Cargo crate, **Then** the scan treats it
  as a local first-class Cargo project.
- **Given** a Cargo dependency with `path = "../shared/util"` that resolves outside the
  scan root, **When** the exact target directory is allowlisted in config and is a
  valid local Cargo crate, **Then** the scan continues.
- **Given** an external `path` dependency not on the exact allowlist, **When** the scan
  runs, **Then** the scan blocks.
- **Given** a `path` dependency that resolves outside the scan root or allowlist via
  symlink tricks or traversal, **When** the scan runs, **Then** the scan blocks.
- **Given** a `path` dependency whose target directory does not contain a valid local
  Cargo crate, **When** the scan runs, **Then** the scan blocks.
- **Resolution base**: `path = ...` is always resolved relative to the directory
  containing the manifest that declared it, whether that declaration came from the
  current `Cargo.toml` or an inherited `[workspace.dependencies]` entry.
- **Given** a target-specific dependency table like `[target.'cfg(unix)'.dependencies]`
  declares `util = { path = "../util" }`, **When** the target resolves to a valid local
  Cargo crate by the same rules as non-target `path` dependencies, **Then** the scan
  continues.
- **Given** a target-specific dependency table like `[target.'cfg(unix)'.dependencies]`
  declares `serde = { registry = "company", version = "=1.2.3" }`, **When** the alias
  and exact lockfile source are allowlisted by the same rules as non-target registry
  dependencies, **Then** the scan continues.
- **Given** a target-specific dependency table like `[target.'cfg(unix)'.dependencies]`
  declares a git dependency, **When** the scan runs, **Then** it follows the same
  default-block or `warn_pinned` policy as non-target git dependencies.

### Private Registries

- **Given** a crates.io dependency, **When** `Cargo.lock` contains one or more package
  entries for the effective package name and exactly one candidate can be proven by
  source plus exact manifest version when needed, **Then** the scan treats it as
  trusted crates.io provenance.
- **Given** a crates.io dependency but `Cargo.lock` is missing, malformed, or does not
  contain a matching crates.io source entry for that effective package name, **When**
  the scan runs, **Then** the scan blocks.
- **Given** a crates.io dependency with multiple candidate `Cargo.lock` entries for the
  effective package name and no exact manifest version to disambiguate them, **When**
  the scan runs, **Then** the scan emits `resolution/ambiguous`.
- **Given** a crates.io or private-registry dependency has an exact manifest version but
  the matching `Cargo.lock` entry resolves to a different exact version, **When** the
  scan runs, **Then** the scan emits `resolution/lockfile-out-of-sync`.
- **Given** a dependency declared with `registry = "company"`, **When** config
  allowlists both manifest alias `company` and exact lockfile source
  `registry+https://cargo.company.example/index`, **Then** the scan accepts the
  dependency as trusted registry provenance.
- **Given** a dependency declared with `registry = "company"` but `Cargo.lock` is
  missing, unreadable, malformed, or does not contain an exact matching source for that
  crate, **When** the scan runs, **Then** the scan blocks.
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
  exact revision from an allowlisted repository URL, **When** the manifest URL exactly
  matches the allowlist, the manifest `rev` is an exact pinned git revision, and
  `Cargo.lock` resolves the same repository URL and commit, **Then** the scan continues
  and emits a warning on every run.
- **Given** `cargo_git_policy = "warn_pinned"` but the git dependency uses `branch`,
  `tag`, or no exact revision, **When** the scan runs, **Then** the scan blocks.
- **Given** `cargo_git_policy = "warn_pinned"` and an exact revision from a
  non-allowlisted repository URL, **When** the scan runs, **Then** the scan blocks.
- **Given** `cargo_git_policy = "warn_pinned"` and the manifest `rev`, manifest URL,
  or `Cargo.lock` git source do not all agree on the same exact repository and commit,
  **When** the scan runs, **Then** the scan blocks.

### Blocked Provenance Rewrites

- **Given** `Cargo.toml` uses root-level `[patch]` or `[replace]`, **When** the scan
  runs, **Then** the scan blocks.
- **Given** a scanned Cargo project or trusted external local crate has any ancestor
  directory from the crate directory up to its trust boundary that contains
  `.cargo/config.toml` or `.cargo/config` with `[patch.*]`, `[source.*]`, or
  `paths = [...]`, **When** the scan runs, **Then** the scan blocks.
  Trust boundary:
  - scan-root crates: the filesystem root
  - exact allowlisted external local crates: the filesystem root

### Trusted Resolution

- **Given** a direct registry dependency from crates.io or an allowlisted private
  registry with an exact manifest version, **When** `Cargo.lock` proves the same exact
  version, **Then** version-sensitive checks use that exact version.
- **Given** a crate is inside an in-scope workspace root that has `Cargo.lock`,
  **When** the scan runs, **Then** that workspace-root `Cargo.lock` is the authoritative
  lockfile for the crate.
- **Given** a crate is not inside an in-scope workspace root but has `Cargo.lock` in
  its own directory, **When** the scan runs, **Then** that crate-local `Cargo.lock` is
  authoritative for the crate.
- **Given** a direct registry dependency uses a non-exact manifest requirement and the
  scan cannot prove lockfile synchronization strongly enough to treat the exact locked
  version as authoritative, **When** the scan runs, **Then** it emits
  `resolution/no-trusted-lockfile-sync` instead of trusting the lockfile exact version.
- **Given** a local `path` dependency or a `workspace = true` dependency that inherits
  a `path` source, **When** the scan runs, **Then** sloppy-joe does not treat it as a
  crates.io dependency and instead scans the target local crate as its own project.

---

## Constraints

### Security

- Local path trust must be exact-directory only. No globs, no trusted parent
  directories.
- Canonicalized filesystem targets must remain stable under symlinks and traversal.
- Registry trust requires both a manifest-side alias allowlist and an exact lockfile
  source allowlist.
- Registry and git provenance comparisons use exact trimmed strings, not fuzzy URL
  normalization.
- Git reduced-confidence mode must not allow floating refs.
- Unsupported provenance must fail closed.
- Dependency rename syntax must not change how provenance is matched; only the effective
  package name participates in Cargo source identity.

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
- support for target-specific dependency tables using the same provenance rules
- support for repo-visible provenance rewrites through `[patch]`, `[replace]`, and
  repo-local `.cargo/config*` when the effective target is trusted
- support for a local-only additive overlay for machine-specific Cargo provenance
- test coverage for all supported and blocked provenance types

Out of scope:

- broad directory trust for local paths
- wildcard git host trust
- support for floating git refs
- support for arbitrary Cargo provenance rewriting features beyond the supported
  trusted-source models
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
- target must contain a valid local Cargo crate
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
- no URL normalization beyond trimming surrounding whitespace

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
- repository URL must be exactly allowlisted after trimming surrounding whitespace
- manifest `rev` must be a full 40-character lowercase hex SHA
- `Cargo.lock` must prove the same repository URL and commit
- every allowed pinned git dependency emits `resolution/reduced-confidence-git` as a
  warning issue on every run

### Local-Only Provenance Overlay

The user-local overlay is separate from committed repo policy.

Rules:

- it is additive only; it may extend exact provenance allowlists for local machine use
- it may add:
  - `trusted_local_paths.cargo`
  - `trusted_registries.cargo`
  - `trusted_git_sources.cargo`
  - `cargo_git_policy = "warn_pinned"`
  - `allow_host_local_cargo_config = true`
- it must not weaken third-party policy:
  - no `min_version_age_hours` changes
  - no `allowed`
  - no `internal`
  - no similarity or metadata exception overrides
- every active local-only relaxation must emit a warning in human output and be
  included in machine-readable output

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
- Reject malformed local or alternate-source dependency tables rather than downgrading
  them into partially trusted unresolved state.
- Support rename-aware identity by carrying both the dependency table key and the
  effective package name through validation.

Unit boundary:

- `src/parsers/cargo_toml.rs` owns manifest parsing and raw dependency intent.

### 2. Cargo Local Dependency Graph

Cargo local dependencies become first-class project links.

- `workspace = true` support is limited to in-scope workspace roots. External workspace
  roots are out of scope for this phase and must block.
- `[workspace.dependencies]` is read only from the nearest in-scope workspace root. It
  may contribute inherited version/features and provenance, but dependency identity is
  still resolved by effective package name.
- Target-specific dependency tables follow the same provenance rules as their
  non-target equivalents after effective package name and inherited provenance are
  resolved.
- For `path = ...`, sloppy-joe must canonicalize the path, verify trust policy, and
  prove the target directory is a valid local Cargo crate.
- Local crates are scanned directly as Cargo projects; they are not sent through
  crates.io registry logic.
- Scan scheduling is by canonical crate directory. Each local crate directory is queued
  at most once per scan, and cycles in local dependency graphs are broken by this
  canonical-path deduplication.
- Repo-visible `.cargo/config*` inspection runs before provenance trust is granted for
  a local crate. Hidden host-local Cargo config outside the repo is not trusted unless
  a local-only overlay explicitly opts in.

Unit boundary:

- `src/lib.rs` owns local crate discovery, path canonicalization, trust-boundary
  checks, repo-visible `.cargo/config*` inspection, local-only overlay warnings, and
  scan scheduling.

### 3. Cargo Registry Provenance

Registry provenance is trusted only when both layers agree:

- manifest alias is allowlisted
- exact `Cargo.lock` source is allowlisted
- exact resolved source matches the configured registry entry
- missing or stale lockfile evidence blocks trusted registry resolution

Matching algorithm:

1. Derive the effective package name from the manifest dependency entry.
2. Find `Cargo.lock` package entries whose `name` equals the effective package name.
3. Compare the raw lockfile registry source by exact trimmed string equality.
4. For crates.io, require raw lockfile registry source
   `registry+https://github.com/rust-lang/crates.io-index`.
5. For private registries, require the raw lockfile registry source to equal the
   configured trusted registry source.
6. If multiple matching entries remain, require an exact manifest version to
   disambiguate the candidate version.
7. If no matching entry remains, emit the canonical lockfile trust failure for that
   condition.
8. If multiple matching entries remain and no exact manifest version disambiguates them,
   keep provenance untrusted and emit `resolution/ambiguous`.

Canonical zero-candidate failure:

- if the authoritative lockfile is present and readable but no matching source candidate
  remains, emit `resolution/no-trusted-lockfile`

Unit boundary:

- `src/lockfiles/cargo.rs` owns Cargo lockfile discovery, parsing, and candidate
  matching.

### 4. Cargo Git Reduced-Confidence Mode

Git support is intentionally narrow.

- default remains blocking
- optional `warn_pinned` mode only supports exact revisions from allowlisted repo URLs
- manifest and lockfile must agree on the same exact repo URL and commit
- git dependencies in reduced-confidence mode remain outside normal registry trust and
  must be surfaced loudly in output

Matching algorithm:

1. Derive the effective package name from the manifest dependency entry.
2. Require a manifest `git` URL whose exact trimmed string matches an allowlisted repo.
3. Require a manifest `rev` that is a full 40-character lowercase hex SHA.
4. Find `Cargo.lock` package entries whose `name` equals the effective package name.
5. Parse the raw lockfile git source only if it matches
   `git+<repo-url>?rev=<40-hex>#<40-hex>`.
6. Require the parsed `<repo-url>` to exactly equal the manifest `git` URL after
   trimming surrounding whitespace.
7. Require both the query `rev` and fragment commit in the raw lockfile git source to
   exactly equal the manifest `rev`.
8. If any step fails, emit `resolution/untrusted-git-source`.

Unit boundary:

- `src/config/mod.rs` owns allowlist configuration parsing for trusted local paths,
  registries, and git sources.

### 5. Cargo Rewrite Provenance

Rewrite features are handled as effective source edges, not as exemptions.

- `[patch]` and `[replace]` are parsed into replacement provenance entries.
- repo-local `.cargo/config.toml` and `.cargo/config` `[source.*]`, `[patch.*]`, and
  `paths = [...]` are parsed only from the repo-visible trust boundary.
- each rewritten effective target must independently satisfy one of the supported
  trusted source models:
  - crates.io
  - exact allowlisted private registry
  - in-root local crate
  - exact allowlisted external local crate
  - warned pinned git, if enabled
- if the effective rewritten target cannot be proven exactly by repo-visible config
  plus the authoritative `Cargo.lock`, the scan blocks
- host-local Cargo config outside the repo is never part of trusted provenance unless a
  local-only overlay explicitly opts in, and such runs must warn loudly

## Provenance Matrix

| Cargo source type | Required evidence | Default | Weak mode | Failure mode |
| --- | --- | --- | --- | --- |
| crates.io with exact manifest version | exact `Cargo.lock` package entry with raw source `registry+https://github.com/rust-lang/crates.io-index` and matching exact version | pass | n/a | block on missing, malformed, or mismatched lockfile evidence |
| crates.io with non-exact manifest requirement | exact `Cargo.lock` package entry with raw source `registry+https://github.com/rust-lang/crates.io-index` | block exact-version trust | n/a | `resolution/no-trusted-lockfile-sync` |
| workspace-inherited dependency | nearest in-scope `[workspace.dependencies]` entry plus the evidence required by that inherited source type | pass when inherited source is trusted | n/a | block if inherited entry is missing, unsupported, or untrusted |
| path local crate under scan root | canonical path under scan root plus valid local Cargo crate target | pass | n/a | block on traversal, symlink escape, or invalid target |
| path local crate outside scan root | exact allowlisted canonical path plus valid local Cargo crate target | block | pass | block if not exactly allowlisted |
| private registry | allowlisted manifest alias plus allowlisted exact `Cargo.lock` source | block | pass | block if alias/source missing or disagree |
| git exact pinned revision | allowlisted exact repo URL plus manifest `rev` plus matching `Cargo.lock` repo and commit | block | warn | block if repo or commit is not exact |
| git branch/tag/unspecified | none | block | block | block |
| repo-visible rewrite to supported trusted target | repo-visible rewrite declaration plus the evidence required by the rewritten target source type | block unless each effective rewritten target is trusted and provable | pass | block if any effective target is untrusted or hidden |
| host-local `~/.cargo/config.toml` or `~/.cargo/config` | none by default | block | warn | block unless a local-only overlay explicitly opts in |

## Direct Registry Resolution Matrix

| Direct registry case | Outcome | Issue code |
| --- | --- | --- |
| exact manifest version + exactly one matching lockfile candidate at same version | trust lockfile exact version | none |
| exact manifest version + matching source but different exact locked version | block | `resolution/lockfile-out-of-sync` |
| non-exact manifest requirement + exactly one matching lockfile candidate | block exact-version trust | `resolution/no-trusted-lockfile-sync` |
| any manifest requirement + multiple matching candidates + exact manifest version disambiguates one | trust disambiguated exact version | none |
| any manifest requirement + multiple matching candidates + no exact manifest version disambiguates one | block | `resolution/ambiguous` |
| authoritative lockfile exists but direct dependency has no matching source candidate entry | block | `resolution/missing-lockfile-entry` |
| authoritative lockfile missing or unreadable | block | `resolution/no-trusted-lockfile` |
| matching source candidate present but lockfile malformed | block | `resolution/parse-failed` |

## Error Contract

| Condition | Expected issue class |
| --- | --- |
| malformed `Cargo.toml` or malformed local target crate manifest | `resolution/parse-failed` |
| missing or unreadable `Cargo.lock` where exact provenance is required | `resolution/no-trusted-lockfile` |
| malformed `Cargo.lock` where exact provenance is required | `resolution/parse-failed` |
| direct dependency absent from authoritative `Cargo.lock` | `resolution/missing-lockfile-entry` |
| local workspace/path target missing, ambiguous, escaped, invalid, or missing inherited `[workspace.dependencies]` entry | `resolution/local-dependency-source` |
| manifest alias or exact lockfile registry source not trusted | `resolution/untrusted-registry-source` |
| git repo URL or pinned commit not trusted | `resolution/untrusted-git-source` |
| allowed pinned git dependency under `warn_pinned` | `resolution/reduced-confidence-git` |
| manifest or repo-local rewrite whose effective target cannot be trusted exactly | `resolution/blocked-provenance-rewrite` |
| hidden host-local Cargo config without explicit local-only opt-in | `resolution/blocked-provenance-rewrite` |
| exact manifest version disagrees with exact `Cargo.lock` version | `resolution/lockfile-out-of-sync` |
| non-exact direct registry dependency whose locked exact version is present but not trusted as synchronized authoritative evidence | `resolution/no-trusted-lockfile-sync` |
| multiple matching lockfile candidates without exact manifest disambiguation | `resolution/ambiguous` |

---

## Pass / Block Matrix

| Cargo feature | Default behavior | Optional config behavior |
| --- | --- | --- |
| crates.io dependency | pass | n/a |
| `workspace = true` inherited dependency | pass only if the nearest in-scope `[workspace.dependencies]` entry exists and its inherited source is trusted | n/a |
| `path = ...` under scan root | pass if target crate is proven and scanned | n/a |
| `path = ...` outside scan root | block | pass only if exact target dir is allowlisted |
| private registry alias + matching exact lockfile source | block | pass only if both alias and source are allowlisted |
| git dep pinned to exact revision | block | warn-and-continue only if repo URL is allowlisted and policy is `warn_pinned` |
| git dep using branch/tag/no revision | block | block |
| repo-visible `[patch]`, `[replace]`, `.cargo/config* [source]`, or `paths` | block unless every effective rewritten target is trusted and provable | pass only when each effective target satisfies a supported trust model |
| host-local `~/.cargo/config.toml` or `~/.cargo/config` | block | warn-and-continue only when a local-only overlay explicitly opts in |

---

## Delivery Slices

To keep implementation reviewable, planning should split this spec into at least two
subphases:

1. `workspace/path/rewrite`
   - workspace inheritance
   - local path trust
   - repo-visible rewrite parsing and validation
   - local crate scan scheduling
2. `registry/git/overlay`
   - trusted registry alias + exact source allowlists
   - authoritative lockfile discovery and candidate matching
   - reduced-confidence pinned git policy
   - local-only provenance overlay wiring

## TDD Matrix

- `workspace = true` with inherited `[workspace.dependencies]` metadata from the
  nearest in-scope root passes
- `workspace = true` with inherited crates.io provenance passes
- `workspace = true` with inherited in-root path provenance passes
- `workspace = true` with inherited private-registry provenance follows alias+source allowlist rules
- `workspace = true` with inherited git provenance follows default block / `warn_pinned`
- current-manifest workspace root is honored for `workspace = true`
- renamed `package = "real-name"` plus `workspace = true` resolves by effective package name
- `workspace = true` missing inherited entry blocks
- `workspace = true` with workspace root outside scan root blocks
- `workspace = true` with unsupported inherited provenance blocks
- target-specific dependency table with `workspace = true` is evaluated by the same rules
- in-root `path` crate passes
- in-root `path` crate with missing `Cargo.toml` blocks
- external exact allowlisted `path` crate passes
- non-allowlisted external `path` crate blocks
- path traversal escape blocks
- symlink escape for external path blocks
- trusted registry alias + trusted exact lockfile source passes
- crates.io direct dependency + exact crates.io lockfile source passes
- trusted alias + untrusted source blocks
- untrusted alias + trusted source blocks
- authoritative lockfile present but missing direct dependency emits `resolution/missing-lockfile-entry`
- missing `Cargo.lock` for private registry blocks
- pinned git dep + allowlisted repo + `warn_pinned` warns and continues
- pinned git dep + `warn_pinned` emits `resolution/reduced-confidence-git`
- pinned git dep + non-allowlisted repo blocks
- pinned git dep + repo/commit mismatch between manifest and lockfile blocks
- exact manifest version vs exact `Cargo.lock` mismatch emits `resolution/lockfile-out-of-sync`
- floating git dep blocks
- trusted repo-visible `[patch]` rewrite to in-root path crate passes
- trusted repo-visible `[replace]` rewrite to allowlisted registry source passes
- repo-visible rewrite to untrusted target blocks
- host-local Cargo config blocks by default
- host-local Cargo config with local-only overlay warns and continues only when the
  effective rewritten targets are trusted

---

## Context Anchors

- `src/parsers/cargo_toml.rs`
- `src/lockfiles/cargo.rs`
- `src/lockfiles/mod.rs`
- `src/lib.rs`
- `src/config/mod.rs`
- `docs/ecosystems/CARGO.md`
