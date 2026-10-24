# Closed Lock-Entry Schemas, Differential Testing, Layer Enforcement, Threat Model

**Created**: 2026-10-24
**Status**: Draft (step 4: npm, composer, cargo, uv, poetry, pipenv, pnpm done; yarn, bun, gradle open)
**Input**: items 4-7 of the answer to "any feedback on architectural improvements to prevent these
issues?", after `untrusted-input-hardening.md` (items 1-3) was implemented.

## Context

### Problem / Why Now

Items 1-3 close config files, ambient inputs and the read path. Four gaps remain:

4. **Lock entries are open.** A lockfile entry is read for the keys the scanner knows (`resolved`,
   `version`, `integrity`, ...); any other key is ignored. A key the package manager honours but the
   scanner does not model (an extra source URL, a `mirrors` list, a `dist` override) is the same
   silent-pass class as an unlisted config key.
5. **The scanner is checked against its own model of the tools.** Every round found bugs by running
   the real tool; no test does that on a schedule.
6. **Layering is enforced by a text scan** (`tests/architecture`). It has been bypassed by aliases,
   `super::` chains and unusual line breaks; each fix made the scan longer, none made it sound.
7. **The threat model is implicit.** What the scanner trusts, and what it refuses to, is spread over
   code, specs and CHANGELOG entries.

### Expected Outcomes

- A lock entry key that is not classified blocks, with the same `config_key_allow` escape as config
  surfaces.
- A reproducible harness runs the real package managers against the scanner's fixtures and flags
  disagreements, and a metamorphic suite checks that formatting-only mutations never change a verdict.
- Layer rules are enforced by the compiler or by a parser-based check, not by text matching.
- `docs/THREAT-MODEL.md` states assets, trust boundaries, attacker capabilities, mitigations (each
  linked to its test) and the explicit non-goals.

### Alternatives Considered

- Keep lock entries open and red-team them: this is what produced the 14 rounds.
- Warn on unknown lock keys: silent degradation by another name; blocks, with an allow, instead.

---

## Acceptance Criteria

### 4. Closed lock-entry schemas

- **Given** a lock entry in `package-lock.json`/`npm-shrinkwrap.json`, `composer.lock` or
  `Cargo.lock`, **when** it holds a key that is not in that format's table, **then** the project is
  blocked, naming the file, the entry and the key.
- **Given** the key is listed in the out-of-repo `config_key_allow` under the lock's surface id,
  **then** the scan passes and emits the `config/key-allowed` warning.
- **Given** a lock produced by the current release of each manager, **then** it passes (fixtures
  are real lockfiles).
- **Given** later formats (uv.lock, poetry.lock, Pipfile.lock, pnpm-lock.yaml, yarn.lock,
  bun.lock, gradle.lockfile), **then** each gets its table in a follow-up step, one commit each.

### 5. Differential and metamorphic testing

- **Given** `tests/differential/`, **when** run with `SLOPPY_JOE_DIFFERENTIAL=1`, **then** each
  fixture is installed/resolved by the real tool with every network host pointed at a logging
  sinkhole, and any request to a host the scanner passed is reported.
- **Given** a corpus fixture and a formatting mutation (CRLF, BOM, trailing whitespace, key order,
  comment insertion), **then** the scanner verdict is identical or the mutation is rejected as
  unmodeled. The suite runs in plain `cargo test`.
- Real-tool runs are opt-in (they need the tools); the metamorphic suite is not.

### 6. Compile-enforced layering

- **Given** the layer table, **when** `cargo test` runs, **then** layer direction is verified by a
  `syn`-parsed use-graph, replacing the text scan, with the same rules and baseline semantics.
- Splitting into workspace crates is deferred until the parse-based check shows the real graph.

### 7. Threat model

- **Given** `docs/THREAT-MODEL.md`, **then** every mitigation row links a test or spec, and a test
  fails if a linked path does not exist.

### 8. Findings explain themselves

- **Given** any blocking or warning finding, **when** it is reported, **then** it carries a stable
  code and an explanation a developer can learn from: what the scanner saw, why that is risky
  (the attack it enables), how to fix it, and how to allow it deliberately when that is possible.
- **Given** a finding code, **when** the explanation is looked up, **then** one exists; a test
  fails for any emitted code without an explanation entry, and for any entry no code uses.
- **Given** the explanation, **then** it is reachable from the report without linking to GitHub,
  source repositories or internal developer documentation (product rule). Where it lives is an
  open decision: text embedded in the binary and shown on request, or a public documentation
  page. Until it is decided, step 8 is not started and the fix text of each finding stays the
  place that teaches.
- **Given** new lock-schema, table and ambient-input findings (steps 1-4), **then** their
  messages name the key or file, the reason from the table's `why`, and the allow mechanism.

---

## Constraints

- Fail closed. No new baseline entry. 800 lines/file, complexity 15/function.
- Each numbered step is its own commit (or several); tests first.
- Do not push.
- Explanations never link to GitHub, source repositories or internal developer docs.
- No new user-facing control (command, flag, link) without the user's approval of that control.

## Scope Boundaries

In scope: the four items. Out of scope: running real package managers in default CI; network
responses; environment outside the repo.

## I/O Contracts

Lock schemas reuse `config_surface::Surface` (wildcard `*` matches one segment). New surface ids
are added to `KNOWN_SURFACES`: `package-lock.json`, `composer.lock`, `Cargo.lock`.

## Context Anchors

- `src/config_surface.rs`, `docs/specs/untrusted-input-hardening.md`.
- `src/ecosystems/js/npm_lockfile_checks.rs` (`validate_npm_lockfile_package_entry`).
- `src/parsers/composer_surface.rs`, `src/lockfiles/composer.rs`, `src/lockfiles/cargo.rs`.
- `tests/architecture/`, `docs/specs/architecture-guardrails.md`.

## Architecture

Step 4: one `Surface` per lock format next to its validator; the validator calls `check_json` /
`check_toml` per entry with the operator's `config_key_allow`. Steps 5-7 are described in their
criteria and get implementation notes here as they land.
