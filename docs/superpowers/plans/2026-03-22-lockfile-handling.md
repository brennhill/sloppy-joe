# Lockfile Handling Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add lockfile-aware exact version resolution for npm and Cargo so metadata and OSV checks use trusted resolved versions when available.

**Architecture:** Keep manifest parsing as the source of direct dependency names and policy tiers. Add a focused `lockfiles` module that resolves exact direct versions from supported lockfiles, returns blocking `resolution/*` issues when resolution is untrustworthy, and feeds resolved versions only into version-sensitive checks.

**Tech Stack:** Rust, `tokio`, `serde_json`, `toml`, existing parser/check/registry modules

---

## Chunk 1: Resolution Model and Contracts

### Task 1: Add failing tests for resolution types and issue contracts

**Files:**
- Create: `src/lockfiles/mod.rs`
- Modify: `src/report.rs`
- Test: `src/lockfiles/mod.rs`

- [ ] **Step 1: Write the failing tests**
- [ ] **Step 2: Run focused tests to verify they fail**
  Run: `cargo test lockfiles:: -- --nocapture`
- [ ] **Step 3: Add minimal resolution types**
- [ ] **Step 4: Re-run focused tests to verify they pass**
- [ ] **Step 5: Commit**

### Task 2: Add scan-report support for resolution issues

**Files:**
- Modify: `src/report.rs`
- Modify: `src/lib.rs`
- Test: `src/report.rs`

- [ ] **Step 1: Write the failing tests for merged resolution issues**
- [ ] **Step 2: Run focused tests to verify they fail**
  Run: `cargo test report::tests:: -- --nocapture`
- [ ] **Step 3: Add minimal report merge support**
- [ ] **Step 4: Re-run focused tests to verify they pass**
- [ ] **Step 5: Commit**

## Chunk 2: npm Lockfile Resolution

### Task 3: Add failing tests for `package-lock.json` and `npm-shrinkwrap.json`

**Files:**
- Modify: `src/lockfiles/mod.rs`
- Test: `src/lockfiles/mod.rs`

- [ ] **Step 1: Write failing tests for**
  - v2/v3 `packages["node_modules/<name>"].version`
  - v1 `dependencies[<name>].version`
  - out-of-sync exact pin
  - missing direct dependency
  - malformed lockfile
- [ ] **Step 2: Run focused tests to verify they fail**
  Run: `cargo test lockfiles::tests::npm -- --nocapture`
- [ ] **Step 3: Implement minimal npm resolver**
- [ ] **Step 4: Re-run focused tests to verify they pass**
- [ ] **Step 5: Commit**

### Task 4: Wire npm resolved versions into metadata and OSV checks

**Files:**
- Modify: `src/checks/metadata.rs`
- Modify: `src/checks/malicious.rs`
- Modify: `src/lib.rs`
- Test: `src/lib.rs`

- [ ] **Step 1: Write failing integration tests proving resolved npm versions remove unresolved-version issues**
- [ ] **Step 2: Run focused tests to verify they fail**
  Run: `cargo test scan_with_ -- --nocapture`
- [ ] **Step 3: Implement minimal orchestration and check wiring**
- [ ] **Step 4: Re-run focused tests to verify they pass**
- [ ] **Step 5: Commit**

## Chunk 3: Cargo.lock Resolution

### Task 5: Add failing tests for Cargo direct-version resolution

**Files:**
- Modify: `src/lockfiles/mod.rs`
- Test: `src/lockfiles/mod.rs`

- [ ] **Step 1: Write failing tests for**
  - single locked version
  - exact manifest match among multiple locked versions
  - ambiguous multiple locked versions
  - missing direct dependency
  - malformed `Cargo.lock`
- [ ] **Step 2: Run focused tests to verify they fail**
  Run: `cargo test lockfiles::tests::cargo -- --nocapture`
- [ ] **Step 3: Implement minimal Cargo resolver**
- [ ] **Step 4: Re-run focused tests to verify they pass**
- [ ] **Step 5: Commit**

### Task 6: Integrate Cargo resolution into scan orchestration

**Files:**
- Modify: `src/lib.rs`
- Modify: `src/checks/metadata.rs`
- Modify: `src/checks/malicious.rs`
- Test: `src/lib.rs`

- [ ] **Step 1: Write failing scan tests for Cargo lockfile-backed exact versions**
- [ ] **Step 2: Run focused tests to verify they fail**
  Run: `cargo test scan_ -- --nocapture`
- [ ] **Step 3: Implement minimal integration**
- [ ] **Step 4: Re-run focused tests to verify they pass**
- [ ] **Step 5: Commit**

## Chunk 4: Verification and Cleanup

### Task 7: Verify conservative fallback and document behavior

**Files:**
- Modify: `README.md` (only if behavior needs user-facing note)
- Test: `src/lib.rs`
- Test: `src/lockfiles/mod.rs`

- [ ] **Step 1: Add any missing fallback tests**
- [ ] **Step 2: Run full test suite**
  Run: `cargo test`
- [ ] **Step 3: Run lint gate**
  Run: `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] **Step 4: Make minimal cleanup changes if needed**
- [ ] **Step 5: Commit**
