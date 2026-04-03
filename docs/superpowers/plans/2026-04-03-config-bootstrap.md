# Config Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicit config bootstrap modes so greenfield repos get ecosystem-specific starter policies, existing repos can seed config from current code, and the default template becomes neutral instead of shipping fake org/example policy.

**Architecture:** Extend `init` with two new modes: `--greenfield --ecosystem <eco>` and `--from-current`. Keep config files outside the repo, reuse existing registry/config-home flows for safe placement, and add a discovery layer that inspects the current repo for internals, trusted scopes/package roots, and candidate canonicals while preserving human review for low-confidence policy.

**Tech Stack:** Rust, Clap CLI parsing, existing config/template/registry modules, serde JSON serialization, cargo test/clippy/fmt.

---

## Files In Scope

- [ ] Modify [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs) for new `init` mode flags, validation, and safe bootstrap UX.
- [ ] Modify [src/config/mod.rs](/Users/brenn/dev/sloppy-joe/src/config/mod.rs) for neutral template generation, ecosystem-specific greenfield presets, and discovery helpers.
- [ ] Add or extend tests in [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs) and [src/config/mod.rs](/Users/brenn/dev/sloppy-joe/src/config/mod.rs).
- [ ] Update [README.md](/Users/brenn/dev/sloppy-joe/README.md) and [CONFIG.md](/Users/brenn/dev/sloppy-joe/CONFIG.md) to document the new bootstrap modes.

## Task 1: Add failing CLI tests for bootstrap modes

**Files:**
- Modify: [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs)

- [ ] **Step 1: Write failing CLI tests**
  Add tests for:
  - `init --greenfield --ecosystem npm`
  - `init --from-current`
  - missing `--ecosystem` with `--greenfield` is rejected
  - `--greenfield` conflicts with `--from-current`
  - `--greenfield`/`--from-current` conflict with `--global`

- [ ] **Step 2: Run targeted tests to verify they fail**

  Run:
  ```bash
  cargo test --quiet --bin sloppy-joe init_
  ```

- [ ] **Step 3: Add minimal CLI parsing support**
  Add the new flags and conflict rules to `Commands::Init`.

- [ ] **Step 4: Re-run targeted tests**

  Run:
  ```bash
  cargo test --quiet --bin sloppy-joe init_
  ```

## Task 2: Replace the generic example template with a neutral baseline

**Files:**
- Modify: [src/config/mod.rs](/Users/brenn/dev/sloppy-joe/src/config/mod.rs)

- [ ] **Step 1: Write failing template tests**
  Add tests proving the default template:
  - does not contain fake org data like `@yourorg/*`
  - does not contain sample allowlisted packages
  - does not contain opinionated npm/Python canonicals by default

- [ ] **Step 2: Run targeted tests to verify they fail**

  Run:
  ```bash
  cargo test --quiet template_
  ```

- [ ] **Step 3: Implement the neutral baseline template**
  Make plain `init` a manual starter, not a disguised policy pack.

- [ ] **Step 4: Re-run targeted tests**

  Run:
  ```bash
  cargo test --quiet template_
  ```

## Task 3: Add ecosystem-specific greenfield presets

**Files:**
- Modify: [src/config/mod.rs](/Users/brenn/dev/sloppy-joe/src/config/mod.rs)
- Modify: [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs)

- [ ] **Step 1: Write failing preset tests**
  Add tests for:
  - `greenfield_config("npm")` emits npm-focused starter policy only
  - `greenfield_config("cargo")` emits Cargo-focused starter policy only
  - unsupported ecosystems are rejected with a clear error

- [ ] **Step 2: Run targeted tests to verify they fail**

  Run:
  ```bash
  cargo test --quiet greenfield_
  ```

- [ ] **Step 3: Implement `greenfield_config` and wire it into `init --greenfield`**
  Keep config placement safe by reusing the current out-of-repo write path.

- [ ] **Step 4: Re-run targeted tests**

  Run:
  ```bash
  cargo test --quiet greenfield_
  ```

## Task 4: Add `--from-current` repo discovery

**Files:**
- Modify: [src/config/mod.rs](/Users/brenn/dev/sloppy-joe/src/config/mod.rs)
- Modify: [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs)

- [ ] **Step 1: Write failing discovery tests**
  Add tests for discovery helpers that:
  - infer likely npm internal scopes from local/workspace packages
  - infer Cargo internal/local provenance from workspace/path crates
  - derive trusted similarity roots/scopes from current package usage
  - produce reviewable candidate canonical groups instead of hard-enforcing them

- [ ] **Step 2: Run targeted tests to verify they fail**

  Run:
  ```bash
  cargo test --quiet from_current_
  ```

- [ ] **Step 3: Implement minimal discovery helpers**
  Scope the first pass to data already available from repo manifests and bindings. Do not fetch online metadata.

- [ ] **Step 4: Wire discovery into `init --from-current`**
  Output a safe external config and register it automatically for the current git root.

- [ ] **Step 5: Re-run targeted tests**

  Run:
  ```bash
  cargo test --quiet from_current_
  ```

## Task 5: Update messaging and docs

**Files:**
- Modify: [src/main.rs](/Users/brenn/dev/sloppy-joe/src/main.rs)
- Modify: [README.md](/Users/brenn/dev/sloppy-joe/README.md)
- Modify: [CONFIG.md](/Users/brenn/dev/sloppy-joe/CONFIG.md)

- [ ] **Step 1: Update `sloppy-joe init --help` text**
  Document:
  - neutral default template
  - `--greenfield --ecosystem <eco>`
  - `--from-current`
  - safe config placement outside the repo

- [ ] **Step 2: Update README quickstart**
  Make the safe onboarding path obvious and short.

- [ ] **Step 3: Update CONFIG docs**
  Document what each bootstrap mode does, and what `--from-current` intentionally does not auto-enforce.

## Task 6: Final verification

- [ ] **Step 1: Run targeted binary tests**

  Run:
  ```bash
  cargo test --quiet --bin sloppy-joe
  ```

- [ ] **Step 2: Run focused library tests**

  Run:
  ```bash
  cargo test --quiet template_
  cargo test --quiet greenfield_
  cargo test --quiet from_current_
  ```

- [ ] **Step 3: Run full verification**

  Run:
  ```bash
  cargo test --quiet
  cargo clippy --all-targets --all-features -- -D warnings
  cargo fmt --check
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add src/main.rs src/config/mod.rs README.md CONFIG.md
  git commit -m "Add config bootstrap modes"
  ```
