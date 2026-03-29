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

## Phase 2: CLI commands + updated resolution — COMPLETE

**What changed:** `src/main.rs` (new Register, Unregister, List commands; updated Init with --register/--global flags; updated Check/Cache handlers to use resolve_config_source with fail-closed behavior), `src/config/mod.rs` (updated resolve_config_source signature to accept project_dir and return Result<Option<String>, String>; added template_json() and template_config() helpers; refactored print_template() to use shared template)
**TDD cycles:** 5 red-green-refactor cycles for resolve_config_source tests
**Verification:** 429 tests pass, clippy clean (4 pre-existing warnings), fmt clean
**Key decisions:**
- Kept `env = "SLOPPY_JOE_CONFIG"` on clap fields — env var flows through as cli_config (step 1), making step 2 in resolve_config_source a safety net for non-clap callers
- `resolve_config_source` returns `Result<Option<String>, String>` — Err for registry errors (corrupted file, symlink), None for "no config found"
- Check and Cache both require config — Ok(None) from resolve_config_source triggers blocking error with exit(2)
- `init --register` finds git root first and errors if not in a git repo
- `register` without `--config` defaults to `{config_home}/{dirname}/config.json` but requires the file to already exist
- Registry-resolved paths flow through `ensure_config_outside_project` via the existing `load_config_from_source` → `load_config_with_project` pipeline
**Learnings for future phases:**
- `std::env::remove_var` is unsafe in Rust — can't use it in tests with `#![forbid(unsafe_code)]`
- The clap `env` attribute means env var comes through as cli_config; the resolve_config_source step 2 check is only hit by non-clap callers (lib API)

## Learnings

- `atomic_write_json` (fire-and-forget) vs `atomic_write_json_checked` (fallible) — use checked for anything that needs fail-closed semantics
- `find_git_root` uses `.exists()` not `.is_dir()` to support worktrees/submodules where `.git` is a file
- `std::env::remove_var` is unsafe — parallel test isolation for env vars requires different strategies (e.g., accept non-determinism or use process-level isolation)
