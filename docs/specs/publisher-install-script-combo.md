# Publisher + Install Script Temporal Combo

**Created**: 2026-03-30
**Status**: Draft

## Context

### Problem / Why Now

Supply chain attacks separate the compromise from the payload. The attacker gains publish
access (publisher change), then deploys the payload later — often by adding install scripts
in a subsequent version.

- **event-stream (2018)**: New maintainer waited 2.5 months before injecting malicious code.
- **SolarWinds (2020)**: Access gained months before the malicious build was injected.
- **ua-parser-js (2021)**: Compromised account published malicious install scripts.

sloppy-joe currently compares publishers between the current and previous version only.
If the attacker publishes one clean version after the takeover, the publisher change scrolls
out of the one-version window and becomes invisible. The install script check fires
independently but doesn't know about the recent publisher change — it only flags scripts
on new/low-download/similarity-flagged packages.

Adding an install script to a mature, high-download package is fine. Adding an install
script to a package whose publisher changed 6 months ago is suspicious. The combo is the
signal, not either event alone.

### Expected Outcomes

- A new check detects when install scripts are added to a package whose publisher changed
  within the last 12 months.
- This catches the event-stream pattern where clean versions separate the takeover from
  the payload.
- The existing `check_maintainer_change` (current vs previous version) remains unchanged.
- The existing `check_install_script_risk` remains unchanged.

### Alternatives Considered

- **Widen `check_maintainer_change` to 12-month lookback**: Changes the existing check's
  semantics. A publisher change alone isn't the problem — it's the combo with scripts.
  The existing check at one-version lookback is correct for its purpose (alerting on any
  publisher change).
- **Same-version combo only**: Misses the deliberate gap between takeover and payload.
- **Always flag publisher change + scripts regardless of age**: A publisher change from
  3 years ago with scripts added today is noise — the new maintainer is established.

---

## Acceptance Criteria

- The check requires version history: publisher and install-script presence per version,
  with publish dates. This data is extracted from the SAME registry API response already
  fetched (npm `versions` object has `_npmUser` and `scripts` per version).
- The check triggers when ALL of these are true:
  1. The publisher changed at some point in the version history within the last 12 months.
  2. Install scripts are present in the current version.
  3. Install scripts were NOT present in the version immediately before the publisher
     change (i.e., scripts were added after the takeover).
- If install scripts existed before the publisher change too, still flag but note in the
  message that scripts pre-date the change (new publisher inherited control of existing
  scripts — different risk profile, still worth flagging).
- Emits `metadata/publisher-script-combo` at Error severity.
- The issue message states:
  - The publisher changed from X to Y in version V on date D.
  - Install scripts were added in version W (or were already present).
  - This matches known supply chain attack patterns.
- The fix: "Wait 30 days after the install scripts were added. Audit the install scripts.
  Verify the publisher change was legitimate. If verified, add to the allowed list."
- If no publisher change occurred in the last 12 months, do not flag.
- If the current version has no install scripts, do not flag.
- Allowed-list packages still receive this check — the event-stream attack targeted exactly this category of trusted packages. Only internal packages (first-party code) skip this check.
- Skipped when `unresolved_version` is true.

---

## Constraints

- New field on `PackageMetadata`: version history records going back 12 months. Extracted
  from the existing registry response — no new network calls.
- Only supported on registries that expose per-version publisher and script data:
  - npm: `versions[v]._npmUser.name` + `versions[v].scripts` + `time[v]` — all available.
  - crates.io: `versions[].published_by` + `versions[].created_at` — available, but
    install script presence is not per-version (Cargo doesn't have install scripts in the
    npm sense). Flag as unsupported.
  - PyPI: per-version publisher data not reliably available. Flag as unsupported.
- The 12-month lookback and 30-day wait are hardcoded constants, not configurable.

---

## Scope Boundaries

### In Scope
- New `VersionRecord` struct and `version_history` field on `PackageMetadata`
- Extract version history from npm registry responses
- New signal `check_publisher_script_combo` in `signals.rs`
- New constant `METADATA_PUBLISHER_SCRIPT_COMBO` in `names.rs`
- Wire into metadata evaluation pipeline

### Out of Scope
- Changing existing `check_maintainer_change` or `check_install_script_risk`
- Version history extraction for crates.io/PyPI (future work when APIs support it)
- Configurable time windows
- Publisher identity verification

---

## I/O Contracts

**Input**: `MetadataLookup` + `PackageMetadata` (with new `version_history` field)

**Output**: `Option<Issue>` with check name `metadata/publisher-script-combo`, severity Error

**New types**:
```rust
#[derive(Debug, Clone, Serialize)]
pub struct VersionRecord {
    pub version: String,
    pub publisher: Option<String>,
    pub has_install_scripts: bool,
    pub date: Option<String>, // ISO 8601
}
```

**New PackageMetadata field**:
```rust
/// Recent version history for temporal signal correlation.
/// Chronologically ordered (oldest first). Only versions within
/// the last 12 months are included.
pub version_history: Vec<VersionRecord>,
```

**Trigger logic**:
1. Walk `version_history` chronologically.
2. Find the most recent version where publisher differs from the prior version's publisher.
3. Check that this publisher change is within 12 months.
4. Check that install scripts are present in the current version.
5. Check whether install scripts were present before the publisher change.
6. Emit issue. Message varies based on whether scripts are new or inherited.

---

## Architecture

### Registry changes (npm only for v1)

In `npm.rs` `metadata_from_body`: after the existing version iteration, build
`version_history` by iterating the `versions` object. For each version within 12 months
of now, extract `_npmUser.name`, check `scripts` for install/preinstall/postinstall/prepare,
and get the date from the `time` object. This data is already in the response body — we
just iterate more of it.

Other registries return an empty `version_history` (the field defaults to `Vec::new()`).

### Signal function

New `check_publisher_script_combo` in `signals.rs`. ~40 lines. Walks version history,
finds publisher change, checks script state, emits issue.

### Pipeline integration

Called from metadata evaluation alongside existing signal checks. No ordering dependency
beyond needing `version_history` populated (which happens during metadata fetch).
