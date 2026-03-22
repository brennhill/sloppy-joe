# Config Injection Resistance Specification

**Created**: 2026-03-22
**Status**: Accepted Design / Current State

## Context

### Problem / Why Now

Config loading is part of the trust boundary of `sloppy-joe`.

If a coding agent or compromised contributor can rewrite the policy file that controls
`internal`, `allowed`, canonical mappings, or version-age settings, the scanner can be
made to approve the dependency it should block. That makes config resolution a security
decision, not a convenience feature.

The accepted design is simple: policy must come from outside the project being scanned,
must use secure transport when remote, and must fail closed when broken.

### Expected Outcomes

- In-repo config tampering is blocked by design.
- CI pipelines can use centrally managed policy files from outside the repo or via HTTPS.
- Broken config sources fail closed with actionable error messages.
- Config semantics for `internal`, `allowed`, `canonical`, and `min_version_age_hours`
  are preserved.

### Alternatives Considered

- **Auto-discover config from the repo**: Creates the exact injection vector this
  design prevents.
- **Allow `http://` remote config**: Downgrades transport security for convenience.
- **Silent fallback to defaults on broken config**: Creates the illusion of protection.

---

## Acceptance Criteria

### In-repo config tampering is blocked

- **Given** a config path inside the project directory, **When** the scan starts,
  **Then** config loading fails with an explicit trust-boundary error.
- **Given** a nested path under the repo that resolves through canonicalization,
  **When** the scan starts, **Then** the scanner still rejects it as project-local.

### CI can use centrally managed policy

- **Given** a config path outside the scanned repo, **When** the scan starts,
  **Then** config is loaded and applied.
- **Given** a valid `https://` config URL, **When** the scan starts, **Then** config is
  fetched and applied.

### Broken config does not silently weaken policy

- **Given** an unreadable config file, **When** the scan starts, **Then** the command
  fails with a fix-oriented error message.
- **Given** malformed JSON, **When** the scan starts, **Then** the command fails and
  points to the JSON problem.
- **Given** a remote URL returning non-success HTTP, **When** the scan starts,
  **Then** the command fails and names the returned status.

### Config source precedence

- **Given** both `--config` flag and `SLOPPY_JOE_CONFIG` env var are set, **When** the
  scan starts, **Then** the `--config` flag wins.
- **Given** no `--config` flag but `SLOPPY_JOE_CONFIG` is set, **When** the scan
  starts, **Then** the env var is used.
- **Given** neither `--config` nor `SLOPPY_JOE_CONFIG`, **When** the scan starts,
  **Then** safe defaults are used and the repo is not searched for config.

### Edge cases

- No config source is provided: use safe defaults and do not search the repo.
- `http://` is provided: reject it outright instead of downgrading security.
- Config path canonicalization fails: compare with the best available path information
  and still enforce the trust boundary.
- The operator intentionally points to a weak config outside the repo: this design
  protects against injection, not operator intent.

---

## Constraints

### Operational

- A broken explicit config source must never silently fall back to default config.
- The trust boundary must hold even when path canonicalization is imperfect.
- Config must be resolved before any dependency checks run.

### Security

- In-repo config files must never be treated as trusted policy.
- Remote config transport must never downgrade to plain HTTP.
- The scanner MUST never auto-discover config from the project directory.

---

## Scope Boundaries

In scope:
- Config source resolution (CLI flag, env var, defaults).
- Trust boundary enforcement (project-local config rejection).
- Remote config transport security (HTTPS only).
- Fail-closed behavior on broken config.
- Config semantics for `internal`, `allowed`, `canonical`, `min_version_age_hours`.

Out of scope:
- Signature verification or pinned-digest verification for remote config.
- Preventing an operator from intentionally choosing a weak config outside the repo.
- Auto-discovery of organization-wide config by repo convention.
- Secret management for private remote config sources.

---

## I/O Contracts

### CLI signatures

```
sloppy-joe check [--config PATH_OR_URL] [existing flags...]
```

- `--config`: Explicit config source. Must be a path outside the project directory or
  an `https://` URL.
- `SLOPPY_JOE_CONFIG` env var: Alternative to `--config` with lower precedence.

### Config source precedence

1. `--config` CLI flag
2. `SLOPPY_JOE_CONFIG` environment variable
3. Default safe config (no file search)

### Config schema

```json
{
  "internal": ["@my-org/internal-lib"],
  "allowed": ["fast-xml-parser"],
  "canonical": { "colors": "chalk" },
  "min_version_age_hours": 72
}
```

### Error message contract

Config errors MUST include:
- The specific problem (trust boundary violation, malformed JSON, HTTP status, etc.)
- The config source that failed
- A fix-oriented directive (e.g., "move config outside the project directory" or
  "check JSON syntax at line N")

### Data shapes

- **Config Source**: Explicit source string from CLI or environment.
- **Project Directory**: Repository being scanned; defines the trust boundary.
- **SloppyJoeConfig**: Parsed JSON policy object with `internal`, `allowed`,
  `canonical`, and `min_version_age_hours` fields.
- **Trust Boundary**: Rule that policy must come from outside the scanned project.

---

## Context Anchors

- `src/config.rs` — source resolution, trust-boundary enforcement, fetch, and parse.
  Contains `resolve_config_source()`, `ensure_config_outside_project()`,
  `load_config_from_source()`, and `parse_config_content()`.
- `src/lib.rs` and `src/main.rs` — passing project context and selected source.
- `SloppyJoeConfig::default()` — safe defaults when no config source is provided.
- `reqwest` via `crate::registry::http_client()` — remote fetches (HTTPS only).

---

## Architecture

### Data Sources

- CLI `--config` flag
- `SLOPPY_JOE_CONFIG` environment variable
- Local filesystem paths outside the repo
- Remote `https://` JSON config

### Modules

- `src/config.rs` for source resolution, trust-boundary enforcement, fetch, and parse
- `src/lib.rs` and `src/main.rs` for passing project context and selected source

### Dependencies

- `reqwest` via `crate::registry::http_client()` for remote fetches
- `serde_json` for config parsing
- Filesystem canonicalization and read APIs from `std::fs`

### Outputs

- Parsed `SloppyJoeConfig`
- Explicit user-facing config errors
- Deterministic tiering effects on `internal`, `allowed`, and canonical policy
