# sloppy-joe Development Rules

## Commit discipline
- COMMIT AFTER EVERY ROUND OF FIXES. Never leave working changes uncommitted.
- Worktree agents start from HEAD. Uncommitted changes are invisible to them. If you don't commit, agents build on stale code and their work can't be merged cleanly.
- Commit before launching worktree agents. Commit after merging their results.

## TDD by default
- Write failing tests FIRST, then implement until tests pass.
- Every new function gets a test. Every bug fix gets a regression test.
- Run `cargo test` after every change. Never commit with failing tests.
- Use `FakeRegistry` for async similarity/existence tests. Use temp dirs with `unique_dir()` for file-based tests.

## Security tool rules
- This is a supply chain security tool. Silent degradation is a bug.
- If a check can't run, emit a blocking error. Never fail open.
- All caches must use `cache.rs` shared utilities (symlink protection, atomic writes, 0o600 permissions).
- Validate package names before URL construction (`validate_package_name` in registry/mod.rs).
- Registry errors must be tracked and fail closed above threshold (>5 errors OR >10% failure rate).

## Architecture
- Similarity is registry-based and async: `check_similarity(registry, deps, ecosystem) -> Result<Vec<Issue>>`. No corpus.
- Three-tier dep classification: internal (skip all) > allowed (skip existence/similarity) > checkable (full checks).
- `source` field on Issues: `"direct"` or `"transitive"`.
- `--deep` enables similarity on transitive deps. Default: existence + metadata + OSV only for transitives.
- Cache flags: `--no-cache` disables disk cache reads. `--cache-dir` overrides location.

## Specs
- All specs live in `docs/specs/` and use the UPFRONT format (Context, Acceptance Criteria, Constraints, Scope Boundaries, I/O Contracts, Context Anchors, Architecture).
- Before implementing a feature, read its spec. Before building a spec, ask questions about it first.
- Spec'd acceptance criteria are the requirements. No FR-xxx numbering.
