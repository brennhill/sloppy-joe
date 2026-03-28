# Decisions

## 2026-03-28 — Config Registry
**Decision:** Add a per-project config registry so `sloppy-joe check` resolves the right config without `--config` flags.
**Key choices:**
- Fail closed when no config is found (no silent degradation to unprotected scan)
- XDG config home with `~/.sloppy-joe/` legacy fallback
- New `config::registry` module (split `config.rs` into module directory)
**Rejected alternatives:** eslint-style config cascade (ambiguous for monorepos), convention-based dirname matching (breaks on rename/move), inlining registry logic into existing resolve function (bloats it).
**Risks accepted:** Registry file writable by user (CI uses explicit `--config`, not registry). Path canonicalization needs care at read and write time.
