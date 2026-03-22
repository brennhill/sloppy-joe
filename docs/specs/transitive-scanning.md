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

### Edge cases

- Lockfile contains deps not reachable from any direct dep (orphaned entries from
  previous installs): still check them — they're in the installed tree.
- Same package appears at multiple versions in the lockfile (Cargo allows this): check
  each version independently.
- Direct dep is also listed in the lockfile's transitive tree: classify as `direct`,
  not `transitive`. Direct takes precedence.
- Lockfile is absent: no transitive scanning possible. Current behavior preserved.
- `--deep` with no lockfile: emit a warning that `--deep` requires a lockfile to
  discover transitive deps.

---

## Constraints

### Operational

- Default behavior must not break existing scans or slow them down significantly.
- Transitive similarity must be opt-in (`--deep`) due to registry load.
- Per-ecosystem rate limits must be respected.
- The tool must not pretend to scan transitives when no lockfile is present.
- The system MUST use the existing 7-day similarity cache for `--deep` transitive
  similarity queries.
- The system MUST use the existing 6-hour OSV cache for transitive OSV queries.
- The system MUST respect per-ecosystem concurrency limits for all transitive dep
  queries (same limits as direct deps).

### Security

- Issues must be clearly labeled as direct or transitive.
- The `internal` and `allowed` lists MUST apply to transitive deps the same way they
  apply to direct deps.

---

## Scope Boundaries

In scope:
- Parsing full lockfile trees for npm (`package-lock.json`, `npm-shrinkwrap.json`) and
  Cargo (`Cargo.lock`).
- Running existence, metadata, and OSV checks on transitive deps by default.
- Opt-in similarity checking on transitive deps via `--deep`.
- Labeling issues as direct or transitive with dependency chain info.
- The `--deep` CLI argument on the `check` subcommand.

Out of scope:
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
