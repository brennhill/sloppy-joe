# Python Index Allowlists Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add exact normalized Python index allowlists for Poetry and uv so non-PyPI sources are trusted only when manifest intent and lockfile provenance agree, with unused repo-visible sources warning but not blocking.

**Architecture:** Extend the config model with exact normalized `trusted_indexes.pypi`, add repo-visible source extraction for Poetry and uv from `pyproject.toml`, and validate authoritative lockfile provenance in the existing Python trusted preflight path. Keep the scope narrow: Poetry/uv only, implicit normalized PyPI trust, and fail closed on hidden or ambiguous source state.

**Tech Stack:** Rust, serde, TOML parsing, existing `sloppy-joe` preflight/report pipeline, fixture-driven tests in `src/lib_tests.rs`

---

## File map

**Core code**

- Modify: `src/config/mod.rs`
  - Add `trusted_indexes` config support, normalization helpers, validation, and lookup accessors.
- Modify: `src/parsers/pyproject_toml.rs`
  - Add repo-visible source extraction for Poetry and uv plus dependency-to-source intent helpers.
- Modify: `src/lockfiles/python.rs`
  - Parse Poetry lockfile package source provenance and validate it against manifest intent + allowlists.
- Modify: `src/lockfiles/uv.rs`
  - Extend uv provenance checks to validate exact normalized source URLs against manifest intent + allowlists.
- Modify: `src/lib.rs`
  - Wire Python trusted-source validation into preflight and emit warning-only issues for unused declared sources.

**Tests and fixtures**

- Modify: `src/lib_tests.rs`
  - Add integration tests for trusted/blocked/warned Poetry and uv source cases.
- Create: `fixtures/python/poetry-source-pass/*`
- Create: `fixtures/python/poetry-source-block/*`
- Create: `fixtures/python/poetry-source-mismatch-fail/*`
- Create: `fixtures/python/poetry-unused-source-warn/*`
- Create: `fixtures/python/uv-source-pass/*`
- Create: `fixtures/python/uv-source-block/*`
- Create: `fixtures/python/uv-source-mismatch-fail/*`
- Create: `fixtures/python/uv-unused-source-warn/*`
- Modify: `fixtures/python/README.md`
- Modify: `fixtures/README.md`

**Docs**

- Modify: `README.md`
- Modify: `CONFIG.md`
- Modify: `docs/ecosystems/PYTHON.md`

---

## Chunk 1: Config and URL normalization

### Task 1: Add failing config tests for trusted Python indexes

**Files:**
- Modify: `src/config/mod.rs`

- [ ] **Step 1: Write the failing tests**

Add tests covering:

```rust
#[test]
fn parses_trusted_python_indexes() {
    let cfg = parse_config_content(
        r#"{"trusted_indexes":{"pypi":["https://download.pytorch.org/whl/cu124"]}}"#,
        "inline",
    )
    .unwrap();
    assert_eq!(
        cfg.trusted_indexes("pypi"),
        ["https://download.pytorch.org/whl/cu124/"]
    );
}

#[test]
fn normalizes_trailing_slash_for_python_indexes() {
    let cfg = parse_config_content(
        r#"{"trusted_indexes":{"pypi":["https://packages.example.com/simple"]}}"#,
        "inline",
    )
    .unwrap();
    assert!(cfg.is_trusted_index("pypi", "https://packages.example.com/simple/"));
}

#[test]
fn rejects_empty_trusted_python_index() {
    let err = parse_config_content(
        r#"{"trusted_indexes":{"pypi":["  "]}}"#,
        "inline",
    )
    .unwrap_err();
    assert!(err.contains("trusted_indexes"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet parses_trusted_python_indexes normalizes_trailing_slash_for_python_indexes rejects_empty_trusted_python_index`  
Expected: FAIL because `trusted_indexes` does not exist yet.

- [ ] **Step 3: Implement config support**

Add:

- `trusted_indexes: HashMap<String, Vec<String>>` to `SloppyJoeConfig`
- validation for supported ecosystems, initially only `pypi`
- normalization helper, for example:

```rust
pub(crate) fn normalize_python_index_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    format!("{trimmed}/")
}
```

- accessors:

```rust
pub fn trusted_indexes(&self, ecosystem: &str) -> &[String]
pub fn is_trusted_index(&self, ecosystem: &str, url: &str) -> bool
```

- implicit PyPI trust helper:

```rust
pub(crate) fn normalized_default_pypi_index() -> &'static str {
    "https://pypi.org/simple/"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet parses_trusted_python_indexes normalizes_trailing_slash_for_python_indexes rejects_empty_trusted_python_index`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/config/mod.rs
git commit -m "Add trusted Python index config"
```

---

## Chunk 2: Poetry source extraction and trust validation

### Task 2: Extract Poetry source declarations and dependency intent

**Files:**
- Modify: `src/parsers/pyproject_toml.rs`
- Test: `src/parsers/pyproject_toml.rs`

- [ ] **Step 1: Write the failing parser tests**

Add tests for:

```rust
#[test]
fn poetry_extracts_declared_sources() {
    // [[tool.poetry.source]]
    // name = "pytorch"
    // url = "https://download.pytorch.org/whl/cu124"
}

#[test]
fn poetry_extracts_dependency_source_intent() {
    // torch = { version = "==2.6.0", source = "pytorch" }
}

#[test]
fn poetry_rejects_source_binding_to_unknown_source_name() {
    // dependency references a missing source alias
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet poetry_extracts_declared_sources poetry_extracts_dependency_source_intent poetry_rejects_source_binding_to_unknown_source_name`  
Expected: FAIL because source metadata is currently rejected or ignored.

- [ ] **Step 3: Implement source extraction**

Add focused structs:

```rust
pub(crate) struct PythonSourceDecl {
    pub name: String,
    pub normalized_url: String,
}

pub(crate) struct PythonDependencySourceIntent {
    pub package: String,
    pub source_name: String,
    pub normalized_url: String,
}
```

Add helpers:

- `parse_poetry_sources(path: &Path) -> Result<Vec<PythonSourceDecl>>`
- `parse_poetry_source_intents(path: &Path) -> Result<Vec<PythonDependencySourceIntent>>`

Important rules:

- normalize URLs through the shared config helper
- keep rejecting non-registry/path/git/url dependency shapes
- stop treating `source = "name"` as automatically unsupported; instead model it
- block if a dependency references an undeclared source name

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet poetry_extracts_declared_sources poetry_extracts_dependency_source_intent poetry_rejects_source_binding_to_unknown_source_name`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/parsers/pyproject_toml.rs
git commit -m "Extract Poetry source declarations"
```

### Task 3: Validate Poetry lockfile source provenance

**Files:**
- Modify: `src/lockfiles/python.rs`
- Modify: `src/lib.rs`
- Modify: `src/lib_tests.rs`
- Create: `fixtures/python/poetry-source-pass/*`
- Create: `fixtures/python/poetry-source-block/*`
- Create: `fixtures/python/poetry-source-mismatch-fail/*`
- Create: `fixtures/python/poetry-unused-source-warn/*`

- [ ] **Step 1: Write the failing integration tests**

Add integration tests for:

- allowlisted alternate Poetry source passes
- non-allowlisted alternate Poetry source blocks
- dependency bound to source A but locked to source B blocks
- declared-but-unused alternate Poetry source warns only
- normalized trailing slash match passes

Example test skeleton:

```rust
#[test]
fn poetry_allowlisted_alternate_source_passes() {
    let dir = ecosystem_fixture_dir("python", "poetry-source-pass");
    let config = config_with_trusted_indexes([
        "https://download.pytorch.org/whl/cu124",
    ]);
    let warnings = preflight_scan_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    assert!(warnings.is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet poetry_allowlisted_alternate_source_passes poetry_non_allowlisted_source_blocks poetry_source_mismatch_blocks poetry_unused_source_warns_only`  
Expected: FAIL because Poetry lockfile source provenance is not checked yet.

- [ ] **Step 3: Implement minimal Poetry provenance logic**

In `src/lockfiles/python.rs` add helpers to:

- extract each package’s resolved source/provenance from `poetry.lock`
- normalize those URLs
- map package name -> resolved source URL

Add validation entry point, for example:

```rust
pub(crate) fn validate_trusted_sources(
    parsed: &toml::Value,
    declared_sources: &[PythonSourceDecl],
    source_intents: &[PythonDependencySourceIntent],
    trusted_indexes: &[String],
    source_path: &Path,
) -> Result<Vec<Issue>>
```

Rules:

- normalized PyPI simple is implicitly allowed
- any other resolved source must be in `trusted_indexes.pypi`
- if manifest binds a dependency to a named source, resolved source must match that source URL
- if declared non-PyPI source is unused, emit warning issue rather than error
- if lockfile source provenance is missing or ambiguous for a non-PyPI package, block

In `src/lib.rs`, call this during trusted Poetry preflight after lockfile parse/sync validation.

- [ ] **Step 4: Add the fixtures**

Create minimal Poetry fixtures:

- `poetry-source-pass`
- `poetry-source-block`
- `poetry-source-mismatch-fail`
- `poetry-unused-source-warn`

Each should contain:

- `pyproject.toml`
- `poetry.lock`
- `fixture.json`

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --quiet poetry_allowlisted_alternate_source_passes poetry_non_allowlisted_source_blocks poetry_source_mismatch_blocks poetry_unused_source_warns_only python_fixture_contracts_hold`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/lockfiles/python.rs src/lib.rs src/lib_tests.rs fixtures/python
git commit -m "Validate Poetry alternate sources"
```

---

## Chunk 3: uv source extraction and trust validation

### Task 4: Extract repo-visible uv sources and dependency intent

**Files:**
- Modify: `src/parsers/pyproject_toml.rs`
- Test: `src/parsers/pyproject_toml.rs`

- [ ] **Step 1: Write the failing uv parser tests**

Add tests for:

- extracting repo-visible uv source/index declarations
- extracting dependency-level uv source intent if present
- rejecting ambiguous source aliases

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet uv_extracts_declared_sources uv_extracts_dependency_source_intent`  
Expected: FAIL because uv source metadata is not extracted yet.

- [ ] **Step 3: Implement uv source extraction**

Add helpers mirroring the Poetry structures:

- `parse_uv_sources(path: &Path) -> Result<Vec<PythonSourceDecl>>`
- `parse_uv_source_intents(path: &Path) -> Result<Vec<PythonDependencySourceIntent>>`

Keep the same exact-URL normalization and undeclared-source failure behavior.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet uv_extracts_declared_sources uv_extracts_dependency_source_intent`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/parsers/pyproject_toml.rs
git commit -m "Extract uv source declarations"
```

### Task 5: Validate uv lockfile source provenance

**Files:**
- Modify: `src/lockfiles/uv.rs`
- Modify: `src/lib.rs`
- Modify: `src/lib_tests.rs`
- Create: `fixtures/python/uv-source-pass/*`
- Create: `fixtures/python/uv-source-block/*`
- Create: `fixtures/python/uv-source-mismatch-fail/*`
- Create: `fixtures/python/uv-unused-source-warn/*`

- [ ] **Step 1: Write the failing integration tests**

Add tests for:

- allowlisted alternate uv source passes
- non-allowlisted alternate uv source blocks
- dependency bound to source A but lockfile source is B blocks
- unused alternate uv source warns only
- trailing slash normalized match passes

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet uv_allowlisted_alternate_source_passes uv_non_allowlisted_source_blocks uv_source_mismatch_blocks uv_unused_source_warns_only`  
Expected: FAIL because uv alternate source allowlists are not checked yet.

- [ ] **Step 3: Implement uv provenance validation**

Extend `src/lockfiles/uv.rs`:

- extract package name -> normalized source URL from `source.registry`
- validate non-PyPI resolved URLs against trusted indexes
- validate dependency source intent against resolved lockfile source
- emit warning-only issues for declared-but-unused non-PyPI sources

Add a focused validator such as:

```rust
pub(crate) fn validate_index_trust(
    parsed: &toml::Value,
    declared_sources: &[PythonSourceDecl],
    source_intents: &[PythonDependencySourceIntent],
    trusted_indexes: &[String],
    source_path: &Path,
) -> Result<Vec<Issue>>
```

Wire it into `read_validated_uv_lockfile(...)` or adjacent trusted uv preflight logic in
`src/lib.rs`.

- [ ] **Step 4: Add the fixtures**

Create:

- `uv-source-pass`
- `uv-source-block`
- `uv-source-mismatch-fail`
- `uv-unused-source-warn`

Each with:

- `pyproject.toml`
- `uv.lock`
- `fixture.json`

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --quiet uv_allowlisted_alternate_source_passes uv_non_allowlisted_source_blocks uv_source_mismatch_blocks uv_unused_source_warns_only python_fixture_contracts_hold`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/lockfiles/uv.rs src/lib.rs src/lib_tests.rs fixtures/python
git commit -m "Validate uv alternate sources"
```

---

## Chunk 4: Warnings, docs, and full verification

### Task 6: Surface unused-source warnings clearly

**Files:**
- Modify: `src/lib.rs`
- Modify: `src/lib_tests.rs`

- [ ] **Step 1: Write the failing warning-shape tests**

Add tests asserting the warning message contains:

- source URL
- “unused”
- “remove”
- “clarity and maintenance”

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet poetry_unused_source_warning_recommends_removal uv_unused_source_warning_recommends_removal`  
Expected: FAIL if message text is too weak or absent.

- [ ] **Step 3: Implement concise warning text**

Use a preflight warning issue with message/fix text along the lines of:

```text
Declared Python source '<url>' is not used by the locked dependency graph.
Fix: Remove the unused source for clarity and maintenance, or keep it only if you expect to use it soon.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet poetry_unused_source_warning_recommends_removal uv_unused_source_warning_recommends_removal`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs src/lib_tests.rs
git commit -m "Warn on unused Python alternate sources"
```

### Task 7: Update docs and examples

**Files:**
- Modify: `README.md`
- Modify: `CONFIG.md`
- Modify: `docs/ecosystems/PYTHON.md`
- Modify: `fixtures/python/README.md`
- Modify: `fixtures/README.md`

- [ ] **Step 1: Update docs**

Add:

- `trusted_indexes.pypi` config example
- statement that normalized PyPI simple is implicitly trusted
- statement that Poetry/uv non-PyPI sources require exact allowlisting
- statement that unused declared sources warn but do not block

Suggested config example:

```json
{
  "trusted_indexes": {
    "pypi": [
      "https://download.pytorch.org/whl/cu124",
      "https://packages.example.com/simple"
    ]
  }
}
```

- [ ] **Step 2: Run a doc grep sanity check**

Run: `rg -n "trusted_indexes|download.pytorch.org|unused source|PyPI" README.md CONFIG.md docs/ecosystems/PYTHON.md fixtures/python/README.md fixtures/README.md`  
Expected: matching updated references only.

- [ ] **Step 3: Commit**

```bash
git add README.md CONFIG.md docs/ecosystems/PYTHON.md fixtures/python/README.md fixtures/README.md
git commit -m "Document Python index allowlists"
```

### Task 8: Full verification

**Files:**
- No new files; verify whole tree

- [ ] **Step 1: Run focused Python coverage**

Run:

```bash
cargo test --quiet python_uv_
cargo test --quiet pip_tools_
cargo test --quiet poetry_allowlisted_alternate_source_passes
cargo test --quiet uv_allowlisted_alternate_source_passes
cargo test --quiet python_fixture_contracts_hold
```

Expected: PASS

- [ ] **Step 2: Run full suite**

Run:

```bash
cargo test --quiet
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

Expected: PASS

- [ ] **Step 3: Final commit if verification-only changes occurred**

```bash
git status --short
```

If docs or tests changed during verification, commit them:

```bash
git add <paths>
git commit -m "Polish Python source allowlist verification"
```

---

Plan complete and saved to `docs/superpowers/plans/2026-04-05-python-index-allowlists.md`. Ready to execute?
