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
- Registry errors must be tracked and fail closed: any registry error blocks (`has_query_errors` in `checks/mod.rs`). There is no error-rate threshold.

## Architecture
- Similarity is registry-based and async: `check_similarity(registry, deps, ecosystem) -> Result<Vec<Issue>>`. No corpus.
- Three-tier dep classification: internal (skip all) > allowed (skip existence/similarity) > checkable (full checks).
- `source` field on Issues: `"direct"` or `"transitive"`.
- `--deep` enables similarity on transitive deps. Default: existence + metadata + OSV only for transitives.
- Cache flags: `--no-cache` disables disk cache reads. `--cache-dir` overrides location.

## Architecture guardrails
- `cargo test --test architecture` enforces layer direction, 800 lines per file, cyclomatic complexity 15 per function, and that `src/lib.rs` does not grow (spec: `docs/specs/architecture-guardrails.md`).
- Existing violations are listed in `tests/architecture_baseline.txt` and may only shrink. Never baseline a new violation: split the file or function instead.
- New ecosystem-specific logic goes in its own module, not in `src/lib.rs`.
- After reducing a violation, tighten the baseline: `UPDATE_ARCH_BASELINE=1 cargo test --test architecture`.

## Specs
- All specs live in `docs/specs/` and use the UPFRONT format (Context, Acceptance Criteria, Constraints, Scope Boundaries, I/O Contracts, Context Anchors, Architecture).
- Before implementing a feature, read its spec. Before building a spec, ask questions about it first.
- Spec'd acceptance criteria are the requirements. No FR-xxx numbering.
