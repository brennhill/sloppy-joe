# Python Hardening Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add trusted `uv.lock` support and trusted pip-tools `requirements*.txt` support when the file is exact-pinned and fully hash-locked.

**Architecture:** Extend Python manifest classification so `pyproject.toml` can resolve to Poetry or uv, and so `requirements*.txt` can be promoted to a trusted pip-tools install target only when the file is fully hash-locked. Add a uv lockfile parser that fails closed on unsupported schema or missing source/artifact identity, keep legacy requirements behavior unchanged, and update docs/tests/fixtures so the new trusted paths are explicit.

**Tech Stack:** Rust, existing `toml`/`serde_json` parsing, fixture corpus, `cargo test`, `cargo clippy`, `cargo fmt`

---

## Guardrails

- Keep this phase limited to `uv.lock` trust and pip-tools hash-locked requirements trust. Do not start phase-2 source/index allowlists or editable/local provenance work.
- Preserve legacy `requirements*.txt`, `Pipfile`, `setup.cfg`, and `setup.py` scanning behavior unless a file is explicitly promoted to trusted pip-tools mode.
- Fail closed on unsupported uv schema, stale uv lock/manifest mismatches, and requirements files that do not have full hash coverage.
- Do not add new CLI flags unless a red test proves the phase cannot be completed without one.

## Prerequisites / Ambiguities

- The recommended uv detection signal is `pyproject.toml` containing `[tool.uv]`. If the repo wants a different signal, swap that classifier before implementation.
- Mixed Poetry + uv metadata in the same `pyproject.toml` should be treated as ambiguous and blocked unless a single authoritative rule is explicitly agreed first.
- Trusted pip-tools should remain a trusted install mode, not a universal project graph. This plan assumes a standalone compiled requirements file is the selected Python root unless a stronger `pyproject.toml` root already exists in the same directory.
- Existing `python_enforcement` naming is still Poetry-centric. Phase 1 should expand trusted behavior without introducing a new user-visible enforcement mode unless a test forces that change.

## Chunk 1: Trusted `uv.lock`

### Task 1: Add failing tests and fixtures for uv trust

**Files:**
- Modify: `src/lib_tests.rs`
- Create: `fixtures/python/uv-pass/pyproject.toml`
- Create: `fixtures/python/uv-pass/uv.lock`
- Create: `fixtures/python/uv-pass/fixture.json`
- Create: `fixtures/python/uv-stale-fail/pyproject.toml`
- Create: `fixtures/python/uv-stale-fail/uv.lock`
- Create: `fixtures/python/uv-stale-fail/fixture.json`
- Create: `fixtures/python/uv-schema-fail/pyproject.toml`
- Create: `fixtures/python/uv-schema-fail/uv.lock`
- Create: `fixtures/python/uv-schema-fail/fixture.json`
- Modify: `fixtures/python/README.md`
- Modify: `fixtures/README.md`

- [ ] **Step 1: Write the failing tests**
  Add red tests that prove:
  - a uv-managed project is classified as trusted when `[tool.uv]` is present
  - `uv.lock` is used instead of `poetry.lock` when both files exist and the project is uv-managed
  - a stale `uv.lock` out of sync with `pyproject.toml` blocks
  - a uv lockfile entry missing source/artifact identity fields blocks
  - the fixture corpus has a trusted uv pass case and two fail cases

- [ ] **Step 2: Run the focused tests to verify they fail**

  Run:
  ```bash
  cargo test --quiet python_uv_
  ```

  Expected: fail because uv is still Poetry-only or legacy-treated.

- [ ] **Step 3: Commit the failing tests and fixture scaffolding**

  ```bash
  git add src/lib_tests.rs fixtures/python/README.md fixtures/README.md fixtures/python/uv-pass fixtures/python/uv-stale-fail fixtures/python/uv-schema-fail
  git commit -m "Add red tests for trusted uv.lock"
  ```

### Task 2: Implement uv classification and lockfile parsing

**Files:**
- Modify: `src/parsers/pyproject_toml.rs`
- Modify: `src/parsers/mod.rs`
- Modify: `src/lib.rs`
- Modify: `src/lockfiles/mod.rs`
- Create: `src/lockfiles/uv.rs`

- [ ] **Step 1: Keep the failing tests red while you add the smallest uv classifier**
  Add a `Uv` pyproject classification based on `[tool.uv]`, keep Poetry detection intact, and make mixed Poetry/uv metadata fail closed if needed to preserve a single authoritative mode.

- [ ] **Step 2: Add `uv.lock` selection and resolution plumbing**
  Route `PyProjectUv` to `uv.lock` in the lockfile dispatcher, add a uv parser that extracts exact package/version pairs, and validate the source/artifact identity fields required for trust.

- [ ] **Step 3: Re-run the focused uv tests**

  Run:
  ```bash
  cargo test --quiet python_uv_
  ```

  Expected: pass, including the stale-lock and schema-fail cases.

- [ ] **Step 4: Commit the uv implementation**

  ```bash
  git add src/parsers/pyproject_toml.rs src/parsers/mod.rs src/lib.rs src/lockfiles/mod.rs src/lockfiles/uv.rs
  git commit -m "Trust uv.lock for Python projects"
  ```

## Chunk 2: Trusted pip-tools with hashes

### Task 3: Add failing tests and fixtures for hash-locked requirements

**Files:**
- Modify: `src/lib_tests.rs`
- Modify: `src/parsers/requirements.rs`
- Create: `fixtures/python/pip-tools-pass/requirements.txt`
- Create: `fixtures/python/pip-tools-pass/fixture.json`
- Create: `fixtures/python/pip-tools-missing-hash-fail/requirements.txt`
- Create: `fixtures/python/pip-tools-missing-hash-fail/fixture.json`
- Create: `fixtures/python/pip-tools-nonexact-fail/requirements.txt`
- Create: `fixtures/python/pip-tools-nonexact-fail/fixture.json`
- Modify: `fixtures/python/README.md`
- Modify: `fixtures/README.md`

- [ ] **Step 1: Write the failing tests**
  Add red tests that prove:
  - a compiled requirements file with exact pins and hashes is promoted to trusted pip-tools mode
  - a requirements file with exact pins but a missing `--hash=` on any installable line stays legacy
  - a requirements file with a non-exact requirement stays legacy
  - included requirements files are also checked for hash coverage
  - the fixture corpus includes one trusted pip-tools pass case and two fail cases

- [ ] **Step 2: Run the focused tests to verify they fail**

  Run:
  ```bash
  cargo test --quiet pip_tools_
  ```

  Expected: fail because the current code still treats every requirements file as legacy.

- [ ] **Step 3: Commit the failing tests and fixture scaffolding**

  ```bash
  git add src/lib_tests.rs src/parsers/requirements.rs fixtures/python/README.md fixtures/README.md fixtures/python/pip-tools-pass fixtures/python/pip-tools-missing-hash-fail fixtures/python/pip-tools-nonexact-fail
  git commit -m "Add red tests for trusted pip-tools requirements"
  ```

### Task 4: Implement trusted pip-tools classification and trust routing

**Files:**
- Modify: `src/parsers/requirements.rs`
- Modify: `src/parsers/mod.rs`
- Modify: `src/lib.rs`
- Modify: `src/config/mod.rs`

- [ ] **Step 1: Keep the failing tests red while you add a trusted-requirements classifier**
  Add a small requirements-file classifier that distinguishes trusted pip-tools files from legacy requirements using exact pins plus full hash coverage after recursive include expansion.

- [ ] **Step 2: Route trusted requirements through the trusted Python path**
  Add a `PyRequirementsTrusted` kind, make `selected_lockfile_path` return the requirements file itself for that kind so cache/state hashes notice changes, skip the legacy warning for that kind, and keep `poetry_only` blocking all non-Poetry Python kinds.

- [ ] **Step 3: Update detection and pruning rules**
  Classify `requirements*.txt` as trusted only when the file qualifies, keep untrusted requirements in the legacy path, and make include pruning apply to trusted requirements too so nested files do not get double-scanned.

- [ ] **Step 4: Re-run the focused pip-tools tests**

  Run:
  ```bash
  cargo test --quiet pip_tools_
  ```

  Expected: pass, with hashless and non-exact files remaining legacy.

- [ ] **Step 5: Commit the pip-tools implementation**

  ```bash
  git add src/parsers/requirements.rs src/parsers/mod.rs src/lib.rs src/config/mod.rs
  git commit -m "Trust hash-locked pip-tools requirements"
  ```

## Chunk 3: Docs, corpus, and verification

### Task 5: Update user-facing Python docs and fixture notes

**Files:**
- Modify: `docs/ecosystems/PYTHON.md`
- Modify: `docs/ecosystems/README.md`
- Modify: `README.md`
- Modify: `CONFIG.md`
- Modify: `fixtures/python/README.md`
- Modify: `fixtures/README.md`

- [ ] **Step 1: Update the docs to match the new trusted Python surface**
  Document Poetry, uv, and hash-locked pip-tools as trusted Python modes; keep legacy manifests documented as warning/legacy paths; and make the `python_enforcement` wording reflect the broader trusted behavior even if the enum name does not change yet.

- [ ] **Step 2: Make the fixture corpus description accurate**
  Add uv and pip-tools cases to the fixture README files so future regressions are obvious.

- [ ] **Step 3: Commit the documentation updates**

  ```bash
  git add docs/ecosystems/PYTHON.md docs/ecosystems/README.md README.md CONFIG.md fixtures/python/README.md fixtures/README.md
  git commit -m "Document trusted uv and pip-tools Python modes"
  ```

### Task 6: Final verification

**Files:**
- Verify: `src/lib_tests.rs`
- Verify: `src/parsers/requirements.rs`
- Verify: `src/lockfiles/mod.rs`
- Verify: `src/lockfiles/uv.rs`

- [ ] **Step 1: Run the focused Python tests**

  Run:
  ```bash
  cargo test --quiet python_uv_
  cargo test --quiet pip_tools_
  cargo test --quiet python_fixture_contracts_hold
  ```

- [ ] **Step 2: Run the full test suite**

  Run:
  ```bash
  cargo test --quiet
  ```

- [ ] **Step 3: Run lint and formatting gates**

  Run:
  ```bash
  cargo clippy --all-targets --all-features -- -D warnings
  cargo fmt --check
  ```

- [ ] **Step 4: Stop only if a failing test points to a scope mismatch**
  If a failure asks for source/index allowlists, editable locals, or artifact-hash identity beyond hash-locked requirements, stop and re-scope instead of pulling in phase-2 work.

## Suggested Commit Strategy

- Commit 1: uv red tests and fixture scaffolding
- Commit 2: uv parser/classifier implementation
- Commit 3: pip-tools red tests and fixture scaffolding
- Commit 4: pip-tools classifier and trust routing
- Commit 5: docs and fixture notes
- Final polish commit only if verification forces a small cleanup

## Risks To Watch

- Do not let uv be inferred from `uv.lock` presence alone; the trusted mode must come from explicit `pyproject.toml` metadata.
- Do not let a hashless compiled requirements file accidentally upgrade to trusted mode.
- Do not let `poetry_only` start accepting uv or pip-tools by accident.
- Do not let included requirements files bypass hash coverage checks.
- Do not let the new Python trust paths pull in the later index/local/editable provenance work from the full spec.
