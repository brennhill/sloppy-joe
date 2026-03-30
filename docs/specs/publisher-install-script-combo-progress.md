# Progress: Publisher + Install Script Temporal Combo

> Spec: `docs/specs/publisher-install-script-combo.md`
> Plan: `docs/specs/publisher-install-script-combo-plan.md`

## Completed Phases

### Phase 1: Data model + extraction
- Added `VersionRecord` struct to `registry/mod.rs` (Debug, Clone, Serialize)
- Added `version_history: Vec<VersionRecord>` field to `PackageMetadata`
- Implemented `build_version_history` in `npm.rs` — extracts publisher, install scripts, and date from npm `versions` object with 12-month age filter
- All 7 other registries default to `version_history: Vec::new()`
- 10 new tests: struct construction, field presence, npm extraction, 12-month filtering, missing `_npmUser`/`scripts`/`time` graceful handling, non-npm empty default
- 455 tests pass, 0 clippy warnings

## Learnings

- `age_in_hours` in `checks/metadata.rs` is `pub(crate)` and reusable for date filtering — no need to duplicate date math.
- Rust 1.93 supports `if let` chains, which clippy prefers over nested `if let` statements.
- `PackageMetadata` is constructed in 10+ places across the codebase (registries, test helpers, fake registries). Adding a field requires touching all of them. A `Default` impl or builder pattern would reduce this burden for future fields.
