# Scan Modes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `sloppy-joe check` a fast local default, add explicit `--full` and `--ci` strict modes, and record enough successful full-scan state to recommend a fresh full scan when dependency or policy state changed or the last full scan is older than 24 hours.

**Architecture:** Add an explicit scan-mode layer at the CLI and orchestration boundary, then split the current scan pipeline into a deterministic local phase and a strict online phase. Persist a successful full-scan fingerprint alongside existing cache state, and surface recommendation reasons through both human and JSON output without changing fast-mode exit behavior for stale or missing full scans.

**Tech Stack:** Rust, Clap CLI parsing, existing `sloppy-joe` cache/report infrastructure, serde JSON serialization, cargo test/clippy/fmt.

---

## Guardrails

- [ ] Keep this work isolated from unrelated dependency/version changes already present in [Cargo.toml](/Users/brenn/dev/sloppy-joe/Cargo.toml) and [Cargo.lock](/Users/brenn/dev/sloppy-joe/Cargo.lock); do not mix scan-mode implementation with dependency-policy cleanup.
- [ ] Preserve current strict behavior for `--full`/`--ci`; the only behavior change is that plain `check` becomes the fast mode.
- [ ] Treat local trust/provenance failures as blocking in every mode.
- [ ] Do not record a successful full-scan fingerprint on a failed full scan.

## Files In Scope

- [ ] Modify [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs) for CLI mode parsing and user-facing mode wiring.
- [ ] Modify [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs) for scan-mode orchestration, fast/full branching, and full-scan recommendation logic.
- [ ] Modify [src/cache.rs](/Users/brenn/dev/sloppy-joe/src/cache.rs) for persisted successful full-scan fingerprint state.
- [ ] Modify [src/report.rs](/Users/brenn/dev/sloppy-joe/src/report.rs) for human and JSON recommendation output.
- [ ] Modify [README.md](/Users/brenn/dev/sloppy-joe/README.md) and [CONFIG.md](/Users/brenn/dev/sloppy-joe/CONFIG.md) for user-facing mode guidance.
- [ ] Add or extend tests in [src/lib_tests.rs](/Users/brenn/dev/sloppy-joe/src/lib_tests.rs) and CLI tests in [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs).

## Phase 1: Define The Mode Model

- [ ] Add a `ScanMode` model with `Fast`, `Full`, and `Ci`.
  Files: [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs), [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs)
  Notes: `Ci` should share full coverage but remain distinct at the CLI boundary.
- [ ] Make plain `sloppy-joe check` default to `Fast`.
  Files: [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs)
- [ ] Add `--full` and `--ci` parsing with an explicit conflict if both are present.
  Files: [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs)
- [ ] Write the first red tests for CLI semantics before implementation.
  Tests:
  - `check_defaults_to_fast_mode`
  - `check_full_selects_full_mode`
  - `check_ci_selects_ci_mode`
  - `check_rejects_full_and_ci_together`

## Phase 2: Define Successful Full-Scan Fingerprints

- [ ] Introduce a persisted `SuccessfulFullScanFingerprint` model.
  Files: [src/cache.rs](/Users/brenn/dev/sloppy-joe/src/cache.rs), [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs)
- [ ] Canonically fingerprint:
  - authoritative manifest bytes
  - authoritative lockfile bytes
  - effective config or canonical serialized policy state
  - selected ecosystem/manager binding
  - scan-relevant flags that affect coverage
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs), [src/cache.rs](/Users/brenn/dev/sloppy-joe/src/cache.rs)
- [ ] Persist the fingerprint only after a successful `Full` or `Ci` run.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs), [src/cache.rs](/Users/brenn/dev/sloppy-joe/src/cache.rs)
- [ ] Ensure failed full scans do not overwrite the last successful full fingerprint.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs), [src/cache.rs](/Users/brenn/dev/sloppy-joe/src/cache.rs)
- [ ] Write red tests for fingerprint persistence rules before implementation.
  Tests:
  - `successful_full_scan_persists_fingerprint`
  - `failed_full_scan_does_not_replace_fingerprint`
  - `fingerprint_changes_when_manifest_changes`
  - `fingerprint_changes_when_lockfile_changes`
  - `fingerprint_changes_when_config_changes`
  - `fingerprint_changes_when_manager_binding_changes`

## Phase 3: Split Fast Vs Full Execution

- [ ] Identify and isolate the deterministic local checks that must always run in every mode.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs)
  Scope:
  - discovery
  - parser validation
  - required lockfile presence
  - manifest/lockfile sync
  - provenance/trusted-source enforcement
  - local workspace/path/source validation
  - unsupported-source blocking
- [ ] Route network-backed or heavy checks behind `Full`/`Ci`.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs)
  Scope:
  - registry metadata refresh
  - OSV refresh
  - similarity/network-backed evidence paths that are not part of the local guardrail
- [ ] Preserve current strict behavior for `Full`/`Ci`.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs)
- [ ] Keep fast mode exit behavior based only on local blocking issues.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs)
- [ ] Write red tests for mode-specific execution before implementation.
  Tests:
  - `fast_mode_runs_local_blocking_checks_without_online_refresh`
  - `fast_mode_blocks_on_local_provenance_failure`
  - `fast_mode_does_not_fail_only_for_stale_full_scan`
  - `full_mode_runs_strict_pipeline`
  - `ci_mode_matches_full_coverage`

## Phase 4: Recommend A Fresh Full Scan

- [ ] Add a `FullScanRecommendation` model with structured reasons.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs), [src/report.rs](/Users/brenn/dev/sloppy-joe/src/report.rs)
- [ ] Implement recommendation reasons for:
  - no successful full scan on record
  - last successful full scan older than 24 hours
  - manifest changed
  - lockfile changed
  - effective config/policy changed
  - selected manager/ecosystem binding changed
  - relevant mode-affecting flags changed
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs), [src/cache.rs](/Users/brenn/dev/sloppy-joe/src/cache.rs)
- [ ] Hardcode the initial TTL at 24 hours unless a simple existing config hook already makes it trivial to avoid a second pass later.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs)
- [ ] Keep recommendation state advisory in `Fast` mode only; do not downgrade `Full`/`Ci` results into warnings.
  Files: [src/lib.rs](/Users/brenn/dev/sloppy-joe/src/lib.rs), [src/report.rs](/Users/brenn/dev/sloppy-joe/src/report.rs)
- [ ] Write red tests for recommendation logic before implementation.
  Tests:
  - `fast_mode_recommends_full_when_no_successful_full_scan_exists`
  - `fast_mode_recommends_full_when_last_full_scan_is_stale`
  - `fast_mode_recommends_full_when_manifest_state_changed`
  - `fast_mode_recommends_full_when_lockfile_state_changed`
  - `fast_mode_recommends_full_when_policy_changed`
  - `fast_mode_recommends_full_when_manager_binding_changed`

## Phase 5: Human And JSON Output

- [ ] Add human output for a prominent `FULL SCAN RECOMMENDED` section with concrete reasons and `sloppy-joe check --full`.
  Files: [src/report.rs](/Users/brenn/dev/sloppy-joe/src/report.rs)
- [ ] Add JSON fields for `full_scan_recommended` and `full_scan_reasons`.
  Files: [src/report.rs](/Users/brenn/dev/sloppy-joe/src/report.rs)
- [ ] Ensure fast-mode warnings do not get lost behind normal finding output.
  Files: [src/report.rs](/Users/brenn/dev/sloppy-joe/src/report.rs)
- [ ] Write red tests for both output shapes before implementation.
  Tests:
  - `human_output_includes_full_scan_recommended_section`
  - `json_output_includes_full_scan_recommendation_fields`
  - `json_output_supports_multiple_recommendation_reasons`

## Phase 6: Documentation

- [ ] Update [README.md](/Users/brenn/dev/sloppy-joe/README.md) to explain:
  - default `check` is fast local mode
  - `--full` and `--ci` run strict online scans
  - when and why fast mode recommends a full scan
  - why `--cold` / `--no-cache` is not the normal workflow if that flag remains exposed
- [ ] Update [CONFIG.md](/Users/brenn/dev/sloppy-joe/CONFIG.md) if any mode-related config or persisted state becomes user-visible.
- [ ] Keep docs aligned with the exact CLI contract implemented in [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs).

## Phase 7: Verification And Integration

- [ ] Run targeted test loops while implementing each phase.
  Suggested commands:
  ```bash
  cargo test --quiet scan_mode
  cargo test --quiet full_scan
  cargo test --quiet recommendation
  ```
  Note: name new tests with stable `scan_mode`, `full_scan`, or `recommendation` substrings so these filters stay useful.
- [ ] Run full verification before closing the work:
  ```bash
  cargo test --quiet
  cargo clippy --all-targets --all-features -- -D warnings
  cargo fmt --check
  ```
- [ ] Manually smoke-test the CLI:
  ```bash
  cargo run -- check
  cargo run -- check --full
  cargo run -- check --ci
  cargo run -- check --json
  ```
- [ ] Confirm the fast mode warns instead of failing when a fresh full scan is recommended.
- [ ] Confirm a successful full run records a fingerprint and suppresses the recommendation until the TTL or fingerprint inputs change.

## Suggested Commit Strategy

- [ ] Commit 1: CLI mode plumbing and red tests
- [ ] Commit 2: full-scan fingerprint persistence
- [ ] Commit 3: fast/full execution split and recommendation logic
- [ ] Commit 4: output and docs
- [ ] Final polish commit only if needed for refactors discovered during verification

## Risks To Watch

- [ ] Do not let `Fast` accidentally skip existing local provenance blockers.
- [ ] Do not let `Ci` drift semantically from `Full`.
- [ ] Do not reuse the existing dependency scan hash blindly; the new successful-full-scan fingerprint has different invalidation needs.
- [ ] Do not couple recommendation state to a failed or partial full run.
- [ ] Avoid output churn that makes JSON consumers or existing tests brittle without updating the contract explicitly.
