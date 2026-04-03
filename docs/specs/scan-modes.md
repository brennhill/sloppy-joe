# Scan Modes Specification

**Created**: 2026-04-03
**Status**: Draft
**Input**: "Make `sloppy-joe check` the fast default. `--full` and `--ci` should do the big check. Detect when lockfiles or dependency state changed and suggest a full scan. Use a 24h freshness window."

## Context

### Problem / Why Now

`sloppy-joe` currently exposes one main scan path, but in practice users are asking it
to do two very different jobs:

- a fast local guardrail they can run constantly
- a strict online audit suitable for CI and release gates

The current UX blurs those together. A cold run with live registry metadata, OSV, and
similarity queries is materially slower than a static manifest/lockfile verification
pass. That is acceptable in CI, but it feels heavy for ordinary local usage and makes
the product seem harder to adopt than it needs to be.

The product should present those as explicit modes instead of forcing users to infer
intent from flags like `--no-cache`.

### Expected Outcomes

- `sloppy-joe check` becomes the fast local default.
- `sloppy-joe check --full` and `sloppy-joe check --ci` run the strict online scan.
- Fast mode always performs meaningful local safety checks even without network.
- Fast mode recommends a full scan when dependency state or policy changed, or when the
  last successful full scan is older than 24 hours.
- `--ci` mirrors `--full` in coverage, but can keep CI-oriented messaging and output.
- The user no longer has to treat `--no-cache` as the normal path.

### Alternatives Considered

- **Keep `check` as the strict full scan and add a separate fast mode**: backward-compatible,
  but keeps the common command feeling heavier than users expect.
- **Auto-run full when fast mode notices change/staleness**: maximally strict, but defeats the
  point of having a fast local mode.
- **Treat cache age only as a performance concern**: misses the product goal that users should
  be nudged toward a fresh online scan when evidence may have changed.

---

## Acceptance Criteria

### Mode behavior

- **Given** `sloppy-joe check` with no extra mode flags, **When** it runs, **Then** it executes
  the fast local scan mode.
- **Given** `sloppy-joe check --full`, **When** it runs, **Then** it executes the full online
  scan mode.
- **Given** `sloppy-joe check --ci`, **When** it runs, **Then** it executes the same scanning
  coverage as `--full`.
- **Given** both `--full` and `--ci`, **When** the CLI parses, **Then** it rejects the command
  as ambiguous.

### Fast mode guarantees

- **Given** fast mode, **When** the scan runs, **Then** it always performs:
  - manifest detection and parser validation
  - required lockfile presence checks
  - manifest/lockfile sync checks
  - provenance / trusted-source enforcement
  - local workspace/path/source validation
  - unsupported-source blocking
- **Given** no network access, **When** fast mode runs, **Then** it still provides those local
  checks and completes without pretending online evidence was refreshed.

### Full-scan recommendation logic

- **Given** no previously recorded successful full scan, **When** fast mode runs, **Then** it
  emits a prominent recommendation to run `sloppy-joe check --full`.
- **Given** the last successful full scan is older than 24 hours, **When** fast mode runs,
  **Then** it emits a prominent recommendation to run `sloppy-joe check --full`.
- **Given** the authoritative manifest or lockfile changed since the last successful full scan,
  **When** fast mode runs, **Then** it emits a prominent recommendation to run
  `sloppy-joe check --full`.
- **Given** the effective config/policy changed since the last successful full scan, **When**
  fast mode runs, **Then** it emits a prominent recommendation to run
  `sloppy-joe check --full`.
- **Given** the manager/ecosystem binding changed since the last successful full scan, **When**
  fast mode runs, **Then** it emits a prominent recommendation to run
  `sloppy-joe check --full`.

### Exit behavior

- **Given** fast mode with local checks passing but a stale or missing full-scan fingerprint,
  **When** it exits, **Then** it exits successfully and reports a warning/recommendation instead
  of blocking.
- **Given** fast mode with a local blocking issue, **When** it exits, **Then** it exits nonzero.
- **Given** `--full` or `--ci`, **When** the full policy finds blocking issues, **Then** it exits
  nonzero.

### Fingerprint persistence

- **Given** a successful full scan, **When** it completes, **Then** it records a fingerprint that
  future fast scans can compare against.
- **Given** a failed full scan, **When** it exits, **Then** it does not record a fresh success
  fingerprint.

---

## Constraints

### Product

- The default `check` command must feel materially lighter than a cold full scan.
- Fast mode must never imply that online evidence was refreshed when it was not.
- A recommendation to run `--full` must be visible in both human and JSON output.
- `--ci` must mirror `--full` coverage; it is a presentation/ergonomics alias, not a weaker mode.

### Operational

- Existing caching infrastructure should be reused where possible.
- The design should not require the user to warm caches just to get value from fast mode.
- The stale-full-scan threshold defaults to 24 hours.

### Security

- Fast mode must still enforce local trust boundaries strictly.
- Full-scan fingerprints must include policy/config state, not just manifest bytes.
- No mode should silently suppress blocking local provenance issues.

---

## Scope Boundaries

In scope:
- CLI mode surface for `check`
- full-scan fingerprint recording and comparison
- recommendation/warning output when a full scan is advised
- documentation and output wording changes

Out of scope:
- redesigning individual checks
- changing the similarity or metadata algorithms themselves
- replacing existing cache backends
- new subcommands beyond the agreed mode flags

---

## I/O Contracts

### CLI signatures

```bash
sloppy-joe check
sloppy-joe check --full
sloppy-joe check --ci
```

Retained flags still apply where they make sense:

```bash
sloppy-joe check --type cargo --config /path/to/config.json
sloppy-joe check --full --json
sloppy-joe check --ci --json
```

### Output requirements

Human output in fast mode should include a clear message like:

```text
FULL SCAN RECOMMENDED
Dependency state changed since the last successful full scan.
Run: sloppy-joe check --full
```

JSON output should include structured recommendation state, for example:

```json
{
  "full_scan_recommended": true,
  "full_scan_reason": "dependency-state-changed"
}
```

If multiple reasons apply, the JSON shape should allow an array:

```json
{
  "full_scan_recommended": true,
  "full_scan_reasons": [
    "dependency-state-changed",
    "last-full-scan-stale"
  ]
}
```

### Fingerprint contents

The successful full-scan fingerprint must include:

- authoritative manifest bytes
- authoritative lockfile bytes
- effective config/policy bytes or canonical serialized form
- selected ecosystem/manager binding
- scan-relevant flags that affect coverage

At minimum, this means changes to manifests, lockfiles, config, selected manager, and
mode-affecting flags must invalidate the last successful full-scan fingerprint.

### Freshness policy

- `full_scan_ttl_hours`: default `24`
- this should be configurable later if needed, but the initial implementation can hardcode
  `24h` if that simplifies the rollout

---

## Context Anchors

- `src/main.rs` — CLI parsing and mode surface
- `src/lib.rs` — scan orchestration and current hash/fingerprint behavior
- `src/cache.rs` — cache and persisted state helpers
- `src/report.rs` — human and JSON output shape
- `README.md` / `CONFIG.md` — user-facing mode guidance

---

## Architecture

### Mode model

Introduce an explicit scan mode concept:

- `Fast`
- `Full`
- `Ci`

`Ci` can internally map to the same execution coverage as `Full`, but should stay distinct in
the CLI model so output or future CI-specific behaviors remain possible without reworking the API.

### Execution model

#### Fast mode

Runs deterministic local validation only:

- discovery
- preflight
- manifest parsing
- lockfile/provenance/sync validation
- local source/workspace/path checks

It may still consume cached online evidence opportunistically in the future, but the core
contract is that it is useful and safe even without network refresh.

#### Full mode

Runs the current full online pipeline:

- local validation
- registry metadata
- OSV
- similarity
- transitive policy

On success, writes the new full-scan fingerprint and timestamp.

#### CI mode

Same scanning coverage as full mode, with CI-oriented messaging and no ambiguity about strictness.

### Recommendation engine

Fast mode compares the current state to the last successful full-scan fingerprint and timestamp.

If any of these conditions are true, it emits a recommendation:

- no previous successful full scan
- full scan older than 24 hours
- manifest changed
- lockfile changed
- effective policy changed
- ecosystem/manager binding changed
- scan-relevant coverage flags changed

### Persistence

Persist a small record separate from the existing “skip unchanged dependencies” optimization:

```text
SuccessfulFullScanRecord {
  fingerprint: <hash>,
  completed_at: <timestamp>,
  ecosystem_binding: <value>,
  mode_version: <schema/version marker>
}
```

This is not a replacement for the existing skip-hash mechanism. It is a usability signal for
deciding when fast mode should recommend a fresh full scan.

### Compatibility strategy

To reduce migration risk:

- keep existing internal check implementations
- change only the default orchestration path for plain `check`
- document `--full` and `--ci` as the strict equivalents
- keep `--no-cache` as an advanced/debug flag or alias it conceptually to a “cold” full scan

---

## Rollout Notes

1. Land explicit scan mode plumbing and tests.
2. Land full-scan fingerprint persistence and recommendation output.
3. Update README/CONFIG/CLI help.
4. Update self-check and CI docs to prefer `--full` or `--ci`, not cold scans by default.
5. Evaluate whether `--no-cache` should be reworded or aliased after the new model is stable.
