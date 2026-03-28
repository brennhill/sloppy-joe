# Progress: Config Registry

> Spec: `specs/config-registry.md`
> Plan: `specs/config-registry-plan.md`

## Completed Phases

## Phase 1: Module split + registry core — COMPLETE

**What changed:** `src/config.rs` → `src/config/mod.rs` + new `src/config/registry.rs`, new `atomic_write_json_checked` in `src/cache.rs`
**TDD cycles:** 14 red-green-refactor cycles
**Review findings:** 6 MUST FIX items resolved (silent write failures, missing symlink checks, .git worktree handling, read-time canonicalization, existence validation, global default canonicalization). BTreeMap for stable output. config_home() returns Result instead of /tmp fallback.
**Surprises:** `cache::atomic_write_json` silently swallows all errors — needed a new `_checked` variant. `config_home()` had to become fallible (returns Result) which propagates to all callers.
**Learnings for future phases:**
- `config_home()` returns `Result<PathBuf, String>` — callers must handle the error
- `register()` and `unregister()` use global `config_home()` for registry path — tests that need isolation use `_from`/`_to` internal variants
- `lookup()` canonicalizes all returned paths and validates existence
- Registry uses `BTreeMap<String, String>` for deterministic JSON output

## Learnings

- `atomic_write_json` (fire-and-forget) vs `atomic_write_json_checked` (fallible) — use checked for anything that needs fail-closed semantics
- `find_git_root` uses `.exists()` not `.is_dir()` to support worktrees/submodules where `.git` is a file
