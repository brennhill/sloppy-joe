# Registry-Based Similarity Specification

**Created**: 2026-03-22
**Status**: Accepted
**Input**: "Eliminate the corpus. If a similar name exists on the registry, block and make the human decide."

## Context

### Problem / Why Now

The current similarity check compares dependency names against a hardcoded corpus of
~100 popular packages per ecosystem. This has three fundamental problems:

1. **Coverage ceiling**: A typosquat of the 101st most popular package is invisible.
2. **Staleness**: The hardcoded list drifts as ecosystems evolve.
3. **Wrong decision-maker**: The tool tries to guess which package is legitimate.
   It should present evidence and make the human decide.

The fix is to eliminate the corpus entirely. For each dependency, generate name mutations
and check whether any mutation exists on the actual registry. If a similar name exists,
block the build and require the user to explicitly approve the dependency. The `allowed`
list becomes the audit trail of deliberate human decisions.

This also addresses the adversarial review finding that corpus-based similarity is the
primary coverage bottleneck for typosquatting detection.

### Expected Outcomes

- Typosquats of ANY real package are caught, not just the top 100.
- Humans make the legitimacy decision, not the tool.
- The `allowed` list becomes the audit trail of deliberate approvals.
- Scope squatting detection continues to work unchanged.
- Performance remains acceptable for CI pipelines.

### Alternatives Considered

- **Keep corpus, expand it**: Still has a coverage ceiling. Any finite list eventually
  misses packages.
- **Levenshtein against the full registry**: Too many candidates for registry queries.
  Generates n x 26 candidates per position.
- **Omitted-character insertion for registry queries**: Replaced by delete-one-character
  generator which produces n candidates instead of n x 26.

---

## Acceptance Criteria

### Typosquat detection (any package)

- **Given** a dependency `expresss` and `express` exists on the registry,
  **When** the scan runs, **Then** the scan emits `similarity/*` with both names
  and blocks the build.
- **Given** a dependency `date-fms` and `date-fns` exists on the registry,
  **When** the scan runs, **Then** the scan emits `similarity/*` even though
  `date-fns` was never in any hardcoded corpus.
- **Given** a dependency `react` which exactly matches a registry package,
  **When** the scan runs, **Then** no similarity issue is emitted.

### Human approval via allowed list

- **Given** `fast-xml-parser` triggers a similarity match, **When** it is added to
  the `allowed` list, **Then** subsequent scans do not flag it.
- **Given** a similarity issue is emitted, **Then** the error message names both
  packages and tells the user to add the intended one to the `allowed` list.

### Error messages with evidence

- **Given** `expresss` matches `express`, **When** the issue is emitted, **Then** the
  message includes: the dep name, the matched name, the mutation type (e.g.,
  "repeated character"), and a directive to examine both and add the intended one to
  the `allowed` list.
- **Given** metadata is available for the matched package, **When** the issue is
  emitted, **Then** the message includes download count and package age as evidence.

### Scope squatting

- **Given** `@typos/lodash`, **When** the scan runs, **Then** `similarity/scope-squatting`
  is emitted exactly as before.

### Performance

- **Given** 50 dependencies generating ~30 mutations each, **When** deduplicated,
  **Then** total unique registry queries are bounded and execute with concurrency.
- **Given** a registry timeout or failure for a mutation query, **Then** that mutation
  is skipped (not fatal) and the check continues.

### 7-day disk cache

- **Given** a similarity scan has run once for a project, **When** the scan runs again
  within 7 days, **Then** cached existence results are reused and no duplicate registry
  queries are made for the same mutation candidates.
- **Given** a cached entry is older than 7 days, **When** the scan runs, **Then** the
  entry is treated as expired and a fresh registry query is made.
- **Given** `--no-cache` is passed, **When** the scan runs, **Then** all disk cache
  reads are skipped and results are fetched fresh from registries.
- **Given** `--cache-dir /tmp/my-cache` is passed, **When** the scan runs, **Then**
  cache files are read from and written to `/tmp/my-cache/` instead of the default
  `~/.cache/sloppy-joe/`.
- **Given** the default cache directory does not exist, **When** the scan runs,
  **Then** the directory is created automatically.

### Fail-closed on registry errors

- **Given** more than 5 individual mutation queries fail during a scan, **When** the
  scan completes the similarity phase, **Then** the build is blocked with an error
  indicating that registry reliability was too low for a trustworthy similarity check.
- **Given** the failure rate for mutation queries exceeds 10%, **When** the scan
  completes the similarity phase, **Then** the build is blocked with the same
  fail-closed error.
- **Given** 3 mutation queries fail out of 1,000, **When** the scan completes, **Then**
  the scan proceeds normally (under both the absolute and percentage thresholds).

### Input validation

- **Given** a dependency name containing `..` (path traversal), **When** the scan
  generates mutations, **Then** the name is rejected before any registry query is made
  and the scan emits a warning.
- **Given** a dependency name containing a null byte, **When** the scan generates
  mutations, **Then** the name is rejected before any registry query is made and the
  scan emits a warning.

### Per-registry concurrency limits

- **Given** dependencies from crates.io, **When** mutation queries execute, **Then** at
  most 2 concurrent requests are made to crates.io.
- **Given** dependencies from the Go module proxy, **When** mutation queries execute,
  **Then** at most 5 concurrent requests are made.
- **Given** dependencies from npm, PyPI, or other registries, **When** mutation queries
  execute, **Then** at most 20 concurrent requests are made per registry.

### Edge cases

- A dependency name is an exact match for a registry package: no issue emitted.
- A dependency is in the `internal` list: similarity check is skipped entirely.
- A dependency is in the `allowed` list: similarity check is skipped.
- A mutation matches multiple registry packages: report the closest match (fewest
  mutations, or first match in priority order).
- A mutation query fails (timeout, network error): skip that mutation silently; the
  check is best-effort for individual mutations but must not fail the entire scan.
- The dependency itself does not exist on the registry: similarity still runs. The
  existence check handles non-existence separately. Both issues can co-fire.
- Two dependencies in the same manifest are mutations of each other: both should be
  flagged by intra-manifest comparison (no network required, defense-in-depth).
- The matched registry package is itself malicious: the tool does not recommend it. It
  says "these are similar — examine both." The human decides.
- On PyPI, separator-only differences (e.g., `python_dateutil` vs `python-dateutil`)
  are the SAME package per PEP 503. Separator-normalization matches MUST be suppressed
  for PyPI to avoid false positives.

---

## Constraints

### Operational

- The system must not use a hardcoded corpus for similarity detection.
- The system must not silently degrade to no similarity checking when registry queries
  fail. Partial results are acceptable; total silence is not.
- The `allowed` list is the only way to suppress a similarity finding.
- Performance must remain acceptable for CI (< 30 seconds for similarity on a typical
  project).
- Registry mutation queries MUST run with bounded concurrency (20-30 concurrent requests).
- Individual mutation query failures MUST be skipped silently. The check MUST NOT fail
  the scan due to a single mutation query timeout.
- The system MUST deduplicate mutation candidates across all dependencies before querying
  the registry to minimize network calls.

### Security

- The system must not recommend a specific package. It presents both names and the
  human decides.
- The system MUST NOT use the Levenshtein fallback against the registry (too many
  candidates).
- The system MUST reject dependency names containing path traversal sequences (`..`)
  or null bytes before generating mutation candidates or making registry queries.
- The system MUST sanitize mutation candidates before using them in registry URL
  construction.

---

## Scope Boundaries

In scope:
- Direct dependency similarity checking via registry queries.
- Intra-manifest similarity comparison (defense-in-depth).
- Scope squatting detection (unchanged, uses `known_scopes()`).
- Case-variant detection on case-sensitive registries.
- PyPI separator-normalization suppression.
- Delete-one-character generator.
- Removal of `src/registry/corpus.rs` and all hardcoded popular package lists.
- 7-day disk cache for similarity existence results (`~/.cache/sloppy-joe/`).
- `--cache-dir` CLI flag to override cache location.
- `--no-cache` CLI flag to disable all disk caching.
- Per-registry concurrency limits (crates.io: 2, Go: 5, others: 20).
- Fail-closed on registry errors: >5 failures or >10% failure rate blocks the build.
- Input validation on package names: rejects path traversal (`..`) and null bytes.
- Mutation cap of 50 per dependency to bound registry queries.

Out of scope:
- Code-level analysis of package contents.
- Recommending which of two similar packages is "the real one."
- Transitive dependency similarity checking (separate spec).
- Registry-level package takedown or reporting.
- Offline mode (the tool already requires network for existence, metadata, and OSV).

---

## I/O Contracts

### CLI signatures

```
sloppy-joe check [--no-cache] [--cache-dir PATH] [existing flags...]
```

- `--no-cache`: Skip all disk cache reads; fetch fresh results from registries.
- `--cache-dir PATH`: Use `PATH` instead of `~/.cache/sloppy-joe/` for cached
  similarity existence results. Default: `~/.cache/sloppy-joe/`.

The similarity check runs as part of `sloppy-joe check`. No other CLI changes.

### Check names emitted

Existing `similarity/*` check names are preserved unchanged:

- `similarity/repeated-chars`
- `similarity/separator-confusion`
- `similarity/word-reorder`
- `similarity/char-swap`
- `similarity/homoglyph`
- `similarity/confused-form`
- `similarity/case-variant`
- `similarity/version-suffix`
- `similarity/scope-squatting`

The mutation type is the useful information. No prefix change for registry-backed matches.

### Mutation generators

| Generator | Candidates per dep | Example |
| --- | --- | --- |
| Separator normalization | 1 | `socket_io` → `socketio` |
| Repeated-character collapse | 1-3 | `expresss` → `express` |
| Version-suffix stripping | 0-1 | `requests2` → `requests` |
| Word reordering | 0-120 (capped at 5 segments) | `json-parse` → `parse-json` |
| Adjacent-character swaps | n-1 | `reqeust` → `request` |
| Delete one character | n | `expresss` → `express` (at pos 5) |
| Homoglyph normalization | 0-1 | `rеquests` (Cyrillic е) → `requests` |
| Confused forms | 0-4 | `py-utils` → `python-utils` |

**Not used for registry queries** (too many candidates):
- Omitted-character insertion (n x 26 candidates) — replaced by delete-one-character
- Levenshtein distance (would require querying entire registry)

### Estimated query volume

For a typical project with 50 dependencies:
- ~30 candidates per dep x 50 deps = ~1,500 raw candidates
- After deduplication and removing names that match existing deps: ~800-1,200 unique
- At 20 concurrent with ~200ms average: ~8-12 seconds

### Error message contract

Similarity issues MUST include:
- The dependency name
- The matched registry package name
- The mutation type
- A directive to examine both and add the intended one to the `allowed` list
- Download count and package age when the ecosystem supports metadata

### Data shapes

- **Mutation Candidate**: A generated name variant that might match a real package.
- **Registry Match**: A mutation candidate that exists on the registry.
- **Similarity Issue**: A blocking finding that a dependency name is one mutation away
  from an existing registry package.
- **allowed list**: Config-based audit trail of human-approved dependencies.
- **Similarity Cache Entry**: A stored existence result for a mutation candidate,
  keyed by ecosystem and candidate name, with a timestamp. Expires after 7 days.
  Stored under `~/.cache/sloppy-joe/` (or `--cache-dir` override).

---

## Context Anchors

- `src/checks/similarity.rs` — current similarity implementation; becomes async, takes
  `&dyn Registry`, removes corpus dependency.
- `src/registry/corpus.rs` — to be deleted (hardcoded popular package lists).
- `src/lib.rs` — scan orchestration; passes registry to similarity, removes corpus fetch.
- `known_scopes()` — scope squatting detection (unchanged, not corpus-based).
- Registry `exists()` method — used for mutation queries.
- Registry `metadata()` method — used for evidence gathering on matches.
- Existing `Issue` and `ScanReport` types — unchanged output format.
- `futures` crate — async stream processing (already a dependency).
- PEP 503 — PyPI name normalization standard (separator suppression).

### Resolved Decisions

1. **Intra-manifest similarity**: YES. Compare deps against each other before registry
   queries. Free (no network), provides defense-in-depth when registry queries fail.

2. **Metadata evidence**: Full metadata fetch for every matched mutation target. Matches
   are rare (0-2 per scan), so cost is bounded. Provides downloads and age evidence so
   the human can make an informed decision.

3. **Separator normalization on PyPI**: Suppressed. PyPI normalizes `[-_.]` to `-` per
   PEP 503, so separator-only differences are the same package, not a typosquat. Other
   ecosystems keep separator checking.

4. **Check names**: Keep existing `similarity/*` names unchanged. The mutation type is
   the useful information. No backward-compatibility break.

---

## Architecture

### Data Sources

- Manifest parsers under `src/parsers/` (unchanged)
- Registry `exists()` method for mutation queries
- Registry `metadata()` method for evidence gathering on matches

### Modules

- `src/checks/similarity.rs` — becomes async, takes `&dyn Registry`, removes corpus
- `src/registry/corpus.rs` — deleted
- `src/lib.rs` — updated orchestration: passes registry to similarity, removes corpus
  fetch

### Dependencies

- Existing `Registry` trait and implementations
- Existing `Issue` and `ScanReport` types
- `futures` crate for async stream processing (already a dependency)

### Integration strategy

- Remove corpus fetch from `scan_with_services_inner`
- Pass `registry` to `check_similarity` (now async)
- Move similarity after metadata fetch so metadata evidence is available for matched
  packages
- Keep scope-squatting and case-variant checks unchanged (they don't use the corpus)
- `check_similarity` function MUST become async and accept a `&dyn Registry` parameter
- The system MUST remove `src/registry/corpus.rs` and all hardcoded popular package lists
  from `src/checks/similarity.rs`
- Intra-manifest similarity comparison MUST run before registry queries as defense-in-depth
