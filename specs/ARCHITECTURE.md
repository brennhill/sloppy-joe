# Architecture

> Last reviewed: 2026-03-28 during `/plan` for config-registry

## System Context

Single-binary CLI tool. No services, databases, or queues.

**External I/O:**
- HTTP GET to package registries (npm, PyPI, crates.io, RubyGems, Go proxy, NuGet, Packagist, Maven) and OSV API
- Filesystem reads: project manifests, lockfiles, config files, cache files
- Filesystem writes: cache files only (atomic write + symlink protection)

**Output:** stdout (human-readable or JSON), stderr (progress/warnings). Exit codes: 0 (clean), 1 (issues found), 2 (runtime error).

**System invariants:**
- Config is NEVER read from inside the project directory (AI agent attack surface)
- All check failures are blocking errors — never silently skip checks (fail closed)
- Cache writes are atomic (temp file + rename, 0o600 permissions, symlink rejection)
- Package names are validated before URL construction

**Deployment:** Single binary via crates.io (`cargo install`) + GitHub releases (cross-compiled for macOS/Linux/Windows).

## Subsystem Map

```
src/
├── main.rs          — CLI (clap derive), thin dispatch to lib
├── lib.rs           — Scan orchestrator, dep classification, hash skip
├── config.rs        — Config loading, validation, resolution, security boundary
├── cache.rs         — Atomic file I/O, platform dirs, date math, symlink protection
├── ecosystem.rs     — Ecosystem enum, per-ecosystem thresholds
├── version.rs       — Version parsing, exact version extraction
├── report.rs        — Issue/ScanReport types, human/JSON output
├── checks/
│   ├── mod.rs       — Check trait, CheckContext, ScanAccumulator, error thresholds
│   ├── pipeline.rs  — Check ordering (canonical → metadata → existence → similarity → malicious)
│   ├── names.rs     — Check name constants (30+)
│   ├── canonical.rs — Canonical name enforcement
│   ├── metadata.rs  — Metadata fetching + signal checks
│   ├── signals.rs   — 8 metadata signal functions (age, downloads, install scripts, repo URL, etc.)
│   ├── existence.rs — Registry existence checks (fail closed)
│   ├── malicious.rs — OSV vulnerability lookups (fail closed)
│   └── similarity/  — 4-phase similarity pipeline, 11 generators, confusables, popular lists
├── registry/        — HTTP clients for 8 package registries (existence + metadata traits)
├── parsers/         — Manifest parsers for 8 ecosystems
└── lockfiles/       — Lockfile parsers, version resolution
```

**Data flow:** CLI → lib.rs orchestrator → parsers (manifests) → checks pipeline (registry HTTP + OSV) → report → stdout

**Key types:**
- `Dependency { name, version, ecosystem }` — parsed from manifests
- `SloppyJoeConfig` — canonical/internal/allowed rules, version age, validation
- `Issue` — check result with severity, message, fix suggestion, source (direct/transitive)
- `ScanReport` — collection of issues + package count
- `ScanOptions` — runtime flags (deep, paranoid, no_cache, cache_dir)

## Design Patterns and Connections

**Config pipeline:** resolve (find source) → load (read + parse) → validate → use
- `resolve_config_source(cli, env)` → `load_config_from_source(source, project_dir)` → `SloppyJoeConfig`
- Errors are `Result<_, String>` with multi-line actionable messages including `Fix:` hints

**Check pipeline:** Trait-based, sequential. Each check receives `CheckContext` + `ScanAccumulator`.
- Pipeline order matters: canonical → metadata → existence → similarity → malicious
- Similarity uses metadata results for download disparity enrichment

**Registry pattern:** `RegistryExistence` + `RegistryMetadata` traits, one impl per ecosystem.
- `registry_struct!` macro generates the struct with `client` + `validate_name()`
- Shared `retry_get()` with exponential backoff (3 attempts)

**File I/O pattern:** `cache::atomic_write_json()` for all file writes (temp + rename + 0o600 + symlink check).

**Error propagation:**
- Config: `Result<_, String>` with actionable messages
- Checks: `anyhow::Result` internally, errors collected in accumulator, fail-closed thresholds
- Registry: `anyhow::Result`, retried, collected

**Dep classification:** Three tiers — internal (OSV only) > allowed (skip existence/similarity) > checkable (full checks).

## Concurrency Model

No shared mutable state. Single-threaded async (tokio) for concurrent HTTP requests within a scan. No cross-process coordination. Cache files use atomic rename for safe concurrent reads/writes.

## Test Strategy

- **Unit tests:** Inline `#[cfg(test)] mod tests` in each module. 413 tests total.
- **Async tests:** `#[tokio::test]` with `FakeRegistry` for registry-dependent tests.
- **File tests:** Temp dirs via `unique_dir()` pattern, cleaned up after each test.
- **No integration tests directory** — all tests are unit tests in src/.
- **CI:** cargo-nextest + doctests, clippy -D warnings, cargo fmt --check, cargo-deny, self-check.

## Risk Areas

- **Path canonicalization:** Symlinks, trailing slashes, case sensitivity on macOS. Must canonicalize consistently.
- **Ecosystem-specific registry quirks:** Go proxy returns unusual responses for mangled paths. Maven has no single authoritative registry. Thresholds are per-ecosystem.
- **Error threshold tuning:** MIN_QUERIES_FOR_RATE=5 prevents false triggers on small/cached scans.
