# Architecture Guardrails Specification

**Created**: 2026-10-23
**Status**: Accepted
**Input**: "we should put some architecture guardrails in place" — agreed limits: 800 lines per file, cyclomatic complexity 15.

## Context

### Problem / Why Now

The scan pipeline is layered in intent (config, parsers, lockfiles, registry, checks) but nothing enforces
it. Measured on 2026-10-23: `src/lib.rs` is 7.8k lines with 193 functions (the longest 310 lines),
`config/mod.rs` 2.8k, `lockfiles/uv.rs` 2.1k, and the layers import each other in both directions
(`parsers` → `registry`/`checks`/`lockfiles`, `lockfiles` → `parsers`/`registry`/`checks`,
`registry` → `parsers`/`checks`). Each red-team round added logic to `lib.rs` because it was the
nearest place. Without a guardrail that keeps happening.

### Expected Outcomes

- The dependency direction between layers is checked on every `cargo test`.
- No file grows past 800 lines and no function past cyclomatic complexity 15, except the existing
  offenders, which may only shrink.
- New ecosystem-specific logic stops accumulating in `lib.rs`.
- Existing violations are listed in one baseline file, so progress is visible and regressions fail.

### Alternatives Considered

- **Fix everything first**: a multi-thousand-line refactor with no regression protection while it runs.
- **clippy `too_many_lines` / `cognitive_complexity`**: `cognitive_complexity` is nursery and measures a
  different quantity than cyclomatic complexity; `-D warnings` in CI would fail on every existing
  offender. A baselined test is stricter on new code and does not break the build today.
- **A separate lint tool** (`cargo-modules`, `cargo-geiger`-style): new dependency and CI step for
  something a 300-line test covers.

---

## Acceptance Criteria

### Layer direction

- **Given** a non-test source file under `src/`, **when** it names `crate::<module>`, **then** the edge
  from its layer to `<module>`'s layer must be allowed by the layer table, or be listed in the baseline.
- **Given** a baseline layer entry whose edge no longer exists, **then** the test fails and asks for the
  baseline to be tightened.
- **Given** a `src/` top-level module not in the layer table, **then** the test fails until it is classified.

### File size

- **Given** any `.rs` file under `src/`, **then** it has at most 800 lines, unless baselined at its
  current size; a baselined file may not grow, and shrinking it requires lowering the baseline.

### Complexity

- **Given** any function in a non-test source file, **then** its cyclomatic complexity is at most 15,
  unless baselined at its current value; baselined values may not grow and must be lowered when they shrink.

### Placement

- **Given** `src/lib.rs`, **then** it may not grow (its line count is baselined), and the number of
  `ProjectInputKind::` occurrences in it may not grow. New ecosystem logic goes in its own module.

### Baseline maintenance

- **Given** `UPDATE_ARCH_BASELINE=1 cargo test --test architecture`, **then** the baseline is rewritten
  with the current, smaller values and resolved entries removed. The run refuses to write if any measure
  is worse than its baseline (new violations are fixed, never baselined), except when no baseline exists yet.

---

## Constraints

- Pure file scanning: no new dependencies, no network, deterministic, runs in well under a second.
- Test files (`*_tests.rs`, inline `#[cfg(test)]` modules) are exempt from layer and complexity rules;
  the 800-line cap applies to every file.
- Complexity is approximate by design (text scan, not a compiler pass) and defined below. It must be
  stable: the same source gives the same number.

## Scope Boundaries

- **In scope**: `tests/architecture.rs`, `tests/architecture_baseline.txt`, this spec, a CLAUDE.md rule.
- **Out of scope**: the refactors themselves (splitting `lib.rs`, an ecosystem trait, removing layer
  cycles). They follow as separate rounds, each protected by the existing tests and by these ratchets.
- **Out of scope**: runtime behavior. No scan output changes.

## I/O Contracts

### Layers and allowed edges

| Layer | Modules | May depend on |
|---|---|---|
| foundation | `ecosystem`, `cache`, `version`, `report` | foundation |
| config | `config`, `npm_config` | foundation, config |
| parsers | `parsers` | foundation, config, parsers |
| registry | `registry` | foundation, config, registry |
| lockfiles | `lockfiles` | foundation, config, parsers, lockfiles |
| checks | `checks` | foundation, config, parsers, lockfiles, registry, checks |
| orchestration | `gradle_plugin_scan`, `lib.rs`, `main.rs` | everything |

`crate::<Item>` that is not a module (types re-exported from `lib.rs`, such as `Dependency`) is not
checked here.

### Cyclomatic complexity

`1 +` the number of: `if`, `while`, `for`, `loop`, `&&`, `||`, and `match` arms beyond the first of each
`match` (each `=>` after the first in a match). Comments, string and char literals are ignored. `?` is not
counted. Closures count toward the function that contains them.

### Baseline file

`tests/architecture_baseline.txt`, one entry per line, `#` comments allowed:

```
file-lines src/lib.rs 7810
fn-complexity src/lib.rs::scan_with_config 41
layer src/parsers/jvm.rs -> registry
placement lib-project-input-kind 146
```

## Context Anchors

- `docs/specs/architecture-v2.md` — the check pipeline this protects.
- `CLAUDE.md` — "Security tool rules": guardrails must not weaken fail-closed behavior.
- `src/lib.rs`, `src/config/mod.rs`, `src/lockfiles/uv.rs` — current largest offenders.

## Architecture

`tests/architecture.rs` walks `src/`, strips comments and strings, and computes four measures: layer
edges, file lines, per-function complexity, and `lib.rs` placement counts. It compares each to the baseline
and fails on any worse value, any unclassified module, and any stale (now-better) entry. A single
`#[test]` per rule keeps failures readable.
