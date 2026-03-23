# Architecture v2 Specification

**Created**: 2026-03-23
**Status**: Accepted
**Input**: "Reorganize internal architecture for extensibility, testability, and performance."

## Context

### Problem / Why Now

After four review/fix cycles, the codebase has correct behavior and good test coverage
(238 tests), but the internal architecture has grown organically. The main orchestrator
(`scan_with_services_inner`) is a 200-line function that sequences all checks imperatively.
Checks are tightly coupled to the orchestrator. Adding a new check (e.g., license scanning)
requires modifying the orchestrator. Lockfiles are parsed multiple times. Error tracking is
local to each check. The mutation generators are hardcoded functions rather than composable
units.

This refactor restructures the internals without changing any external behavior or CLI flags.

### Expected Outcomes

- New checks can be added by implementing a trait, not editing the orchestrator.
- Lockfiles are parsed once.
- Registry errors are tracked globally across all checks.
- Mutation generators are composable and extensible.
- Cache is a service trait, enabling in-memory testing and future Redis support.
- All existing tests continue to pass unchanged.

### Alternatives Considered

- **Leave as-is**: Works, but every new feature requires touching the orchestrator and
  adding more parameters. Maintenance cost grows linearly with feature count.
- **Full ECS/plugin architecture**: Over-engineered for a CLI tool with 5 checks.
- **This spec (trait-based pipeline)**: Minimal abstraction that solves the actual problems
  without framework overhead.

---

## Acceptance Criteria

### 1. Explicit scan pipeline

- **Given** the existing `scan_with_services_inner` function,
  **When** the refactor is complete,
  **Then** the scan is orchestrated as a sequence of stages:
  `Parse -> Classify -> [Check, Check, ...] -> Report`.
- **Given** a new `Check` implementation,
  **When** it is registered with the pipeline,
  **Then** it runs alongside existing checks without modifying orchestrator code.
- **Given** the `Check` trait,
  **Then** it has the signature:
  ```rust
  #[async_trait]
  trait Check: Send + Sync {
      fn name(&self) -> &str;
      async fn run(&self, ctx: &CheckContext) -> Result<Vec<Issue>>;
  }
  ```
  where `CheckContext` provides deps, config, registry, resolution, cache, and error budget.

### 2. Single lockfile parse

- **Given** a project with a lockfile,
  **When** the scan runs,
  **Then** the lockfile is read from disk exactly once.
- **Given** the parsed lockfile data,
  **Then** it provides both `resolve_versions()` and `transitive_deps()` from the
  same in-memory structure.
- **Given** an npm project with `package-lock.json`,
  **When** the scan resolves versions and extracts transitive deps,
  **Then** the file content is identical for both operations (no TOCTOU).

### 3. Cache as a service

- **Given** the `CacheService` trait,
  **Then** it has methods:
  ```rust
  trait CacheService: Send + Sync {
      fn read<T: DeserializeOwned>(&self, key: &str, ttl_secs: u64) -> Option<T>;
      fn write<T: Serialize>(&self, key: &str, data: &T) -> Result<()>;
  }
  ```
- **Given** the existing disk cache behavior,
  **When** the `DiskCacheService` is used,
  **Then** it preserves symlink protection, atomic writes, and 0o600 permissions.
- **Given** a test,
  **When** it uses `InMemoryCacheService`,
  **Then** no disk I/O occurs and the test runs deterministically.

### 4. Global error budget

- **Given** the `ErrorBudget` struct,
  **Then** it tracks total errors and total queries across all checks.
- **Given** registry errors from similarity, existence, and metadata checks,
  **When** the combined error count exceeds the threshold (>5 errors OR >10% rate),
  **Then** the scan emits a single blocking `scan/registry-unreachable` issue and
  stops further registry-dependent checks.
- **Given** the error budget is not exceeded,
  **Then** individual check errors are counted but do not independently block.

### 5. Composable mutation generators

- **Given** the `MutationGenerator` trait:
  ```rust
  trait MutationGenerator: Send + Sync {
      fn name(&self) -> &str;
      fn generate(&self, name: &str, ecosystem: &str) -> Vec<String>;
  }
  ```
  **When** the similarity check runs,
  **Then** it iterates over a `Vec<Box<dyn MutationGenerator>>` instead of
  calling hardcoded functions.
- **Given** the existing generators (separator-swap, collapse-repeated,
  version-suffix, word-reorder, adjacent-swap, delete-one-char, homoglyph,
  confused-forms),
  **Then** each is a struct implementing `MutationGenerator`.
- **Given** a new generator is added to the vector,
  **Then** it participates in similarity checking without modifying
  `check_similarity` or `generate_mutations`.

### 6. Registry split: exists vs metadata

- **Given** the current `Registry` trait has both `exists()` and `metadata()`,
  **When** the refactor is complete,
  **Then** these are separate traits: `RegistryExistence` and `RegistryMetadata`.
- **Given** the similarity check,
  **Then** it depends only on `RegistryExistence`.
- **Given** a future batch existence API (e.g., npm search),
  **Then** it can be implemented as a `BatchRegistryExistence` trait with
  `batch_exists(&[String]) -> Vec<(String, Result<bool>)>` without changing
  the similarity check interface.

---

## Constraints

- All 238 existing tests must pass without modification (behavior-preserving refactor).
- No new external dependencies.
- No changes to CLI flags, output format, or exit codes.
- `#![forbid(unsafe_code)]` is preserved.
- All caches continue to use `cache.rs` shared utilities.
- The `Check` trait must support both sync-only checks (canonical, scope-squatting)
  and async checks (similarity, existence, metadata, OSV).

---

## Scope Boundaries

### In Scope

- Restructure `scan_with_services_inner` into a pipeline of `Check` impls.
- Unify lockfile parsing into a single-pass `LockfileData` struct.
- Extract `CacheService` trait + `DiskCacheService` + `InMemoryCacheService`.
- Extract `ErrorBudget` struct shared across checks.
- Extract mutation generators into `MutationGenerator` trait impls.
- Split `Registry` into `RegistryExistence` + `RegistryMetadata`.

### Out of Scope

- New CLI flags or features.
- New check types (license scanning, etc.) -- this refactor enables them.
- Redis or remote cache implementations.
- Batch registry API implementations -- this refactor enables them.
- Changes to output format or error messages.

---

## I/O Contracts

### CheckContext (input to all checks)

```rust
struct CheckContext<'a> {
    deps: &'a [Dependency],            // classified deps for this check
    all_deps: &'a [Dependency],        // all parsed deps (for intra-manifest)
    config: &'a SloppyJoeConfig,
    registry: &'a dyn RegistryExistence,
    registry_meta: &'a dyn RegistryMetadata,
    lockfile: &'a LockfileData,
    cache: &'a dyn CacheService,
    error_budget: &'a ErrorBudget,
    ecosystem: &'a str,
    opts: &'a ScanOptions<'a>,
    similarity_flagged: &'a HashSet<String>,
}
```

### LockfileData (single-parse lockfile)

```rust
struct LockfileData {
    resolution: ResolutionResult,
    transitive_deps: Vec<Dependency>,
}
```

### ErrorBudget (shared error tracking)

```rust
struct ErrorBudget {
    errors: AtomicUsize,
    queries: AtomicUsize,
}

impl ErrorBudget {
    fn record_success(&self);
    fn record_error(&self);
    fn is_exceeded(&self) -> bool; // >5 errors OR >10% rate
    fn summary(&self) -> (usize, usize); // (errors, total)
}
```

---

## Context Anchors

- `src/lib.rs` -- current orchestrator, becomes thin pipeline runner
- `src/checks/similarity.rs` -- becomes `SimilarityCheck` implementing `Check`
- `src/checks/existence.rs` -- becomes `ExistenceCheck` implementing `Check`
- `src/checks/metadata.rs` -- becomes `MetadataCheck` implementing `Check`
- `src/checks/malicious.rs` -- becomes `MaliciousCheck` implementing `Check`
- `src/checks/canonical.rs` -- becomes `CanonicalCheck` implementing `Check`
- `src/cache.rs` -- gains `CacheService` trait, `DiskCacheService`, `InMemoryCacheService`
- `src/lockfiles/mod.rs` -- gains `LockfileData::parse()` single-pass constructor
- `src/registry/mod.rs` -- `Registry` splits into `RegistryExistence` + `RegistryMetadata`

---

## Architecture

### Pipeline flow

```
1. Parse:     parse_dependencies() -> Vec<Dependency>
2. Lockfile:  LockfileData::parse() -> { resolution, transitive_deps }
3. Classify:  partition into internal / allowed / checkable
4. Budget:    ErrorBudget::new()
5. Checks:    for check in checks { check.run(&ctx) }
              - CanonicalCheck (sync, no registry)
              - SimilarityCheck (async, RegistryExistence + cache)
              - ExistenceCheck (async, RegistryExistence via metadata)
              - MetadataCheck (async, RegistryMetadata)
              - MaliciousCheck (async, OsvClient)
6. Budget:    if error_budget.is_exceeded() { emit blocking issue }
7. Transitive: repeat steps 5-6 for transitive deps (per opts.deep)
8. Report:    mark sources, build ScanReport
```

### Check registration

```rust
let checks: Vec<Box<dyn Check>> = vec![
    Box::new(CanonicalCheck),
    Box::new(SimilarityCheck::new(generators)),
    Box::new(ExistenceCheck),
    Box::new(MetadataCheck),
    Box::new(MaliciousCheck::new(osv_client)),
];
```

### Mutation generator registration

```rust
let generators: Vec<Box<dyn MutationGenerator>> = vec![
    Box::new(SeparatorSwap),
    Box::new(CollapseRepeated),
    Box::new(VersionSuffix),
    Box::new(WordReorder),
    Box::new(AdjacentSwap),
    Box::new(DeleteOneChar),
    Box::new(HomoglyphNormalize),
    Box::new(ConfusedForms),
];
```

New generators (trigram, phonetic) are added here without touching similarity logic.
