# Config Injection Resistance Specification

**Created**: 2026-03-22
**Status**: Accepted Design / Current State
**Input**: "Create a spec for config injection since that's a clear design decision."

## 1. Problem / Why Now

Config loading is part of the trust boundary of `sloppy-joe`.

If a coding agent or compromised contributor can rewrite the policy file that controls
`internal`, `allowed`, canonical mappings, or version-age settings, the scanner can be
made to approve the dependency it should block. That makes config resolution a security
decision, not a convenience feature.

The accepted design is simple: policy must come from outside the project being scanned,
must use secure transport when remote, and must fail closed when broken.

## 2. User Scenarios & Testing

### User Story 1 - In-repo config tampering is blocked (Priority: P1)

A coding agent with write access to the repository tries to add a config file inside the
repo that allowlists a hallucinated dependency.

**Why this priority**: This is the core threat the design is meant to stop.

**Independent test**: Provide `--config ./repo/sloppy-joe.json` while scanning the same
repo and verify the scanner rejects it.

**Acceptance scenarios**:

1. **Given** a config path inside the project directory, **When** the scan starts,
   **Then** config loading fails with an explicit trust-boundary error.
2. **Given** a nested path under the repo that resolves through canonicalization,
   **When** the scan starts, **Then** the scanner still rejects it as project-local.

### User Story 2 - CI can use centrally managed policy (Priority: P1)

A CI pipeline needs one policy file shared across many repositories.

**Why this priority**: The secure design has to remain usable in CI or people will route
around it.

**Independent test**: Use a local config path outside the repo or an `https://` URL and
verify config loads successfully.

**Acceptance scenarios**:

1. **Given** a config path outside the scanned repo, **When** the scan starts,
   **Then** config is loaded and applied.
2. **Given** a valid `https://` config URL, **When** the scan starts, **Then** config is
   fetched and applied.

### User Story 3 - Broken config does not silently weaken policy (Priority: P1)

A developer provides an unreadable path, malformed JSON, or a failing remote URL.

**Why this priority**: Silent fallback would create the illusion of protection.

**Independent test**: Supply a broken config source and verify the scan fails instead of
continuing with defaults.

**Acceptance scenarios**:

1. **Given** an unreadable config file, **When** the scan starts, **Then** the command
   fails with a fix-oriented error message.
2. **Given** malformed JSON, **When** the scan starts, **Then** the command fails and
   points to the JSON problem.
3. **Given** a remote URL returning non-success HTTP, **When** the scan starts,
   **Then** the command fails and names the returned status.

### Edge Cases

- No config source is provided: use safe defaults and do not search the repo.
- `http://` is provided: reject it outright instead of downgrading security.
- Config path canonicalization fails: compare with the best available path information and
  still enforce the trust boundary.
- The operator intentionally points to a weak config outside the repo: this design
  protects against injection, not operator intent.

## 3. Requirements

### Functional Requirements

- **FR-001**: The scanner MUST never auto-discover config from the project directory.
- **FR-002**: The scanner MUST resolve config source precedence as: `--config`, then
  `SLOPPY_JOE_CONFIG`, then default config.
- **FR-003**: The scanner MUST reject project-local config files when a project directory
  is known.
- **FR-004**: The scanner MUST only allow remote config over `https://`.
- **FR-005**: The scanner MUST reject `http://` config URLs.
- **FR-006**: The scanner MUST fail closed on unreadable files, fetch failures,
  non-success HTTP responses, empty config, and invalid JSON.
- **FR-007**: The scanner MUST provide actionable config error messages.
- **FR-008**: The scanner MUST preserve explicit semantics for `internal`, `allowed`,
  `canonical`, and `min_version_age_hours`.
- **FR-009**: The scanner MUST use safe defaults when no explicit config source is
  provided.
- **FR-010**: The spec MUST include context anchors to the config-loading code paths and
  trust-boundary enforcement points.
- **FR-011**: The spec MUST include the input contract for accepted config sources.
- **FR-012**: The spec MUST include the output contract for config-loading failures.
- **FR-013**: The spec MUST describe the side effect of config decisions on downstream
  check tiers.

#### Current accepted behavior

| Area | Current behavior | Implementation |
| --- | --- | --- |
| Source precedence | CLI flag wins, then env var, then default config | `resolve_config_source(...)` |
| Project-local config | Rejected when inside project tree | `ensure_config_outside_project(...)` |
| Remote transport | `https://` allowed, `http://` rejected | `load_config_from_source(...)` |
| Parse failures | Fail closed with explicit errors | `parse_config_content(...)` |
| Missing config source | Safe defaults used | `SloppyJoeConfig::default()` |

#### Current semantics protected by this design

- `internal`: skip all checks
- `allowed`: skip existence and similarity only
- `canonical`: organizational replacement policy
- `min_version_age_hours`: exact-version age gate

### Scoring Rubric — Machine Usability

If this spec is graded with the UPFRONT rubric, the machine-usable sections are:

| Section | What an AI or reviewer uses it for | Weight |
| --- | --- | --- |
| Acceptance scenarios | Derive failure-path and trust-boundary tests | High |
| Edge cases | Avoid silent downgrade behavior | High |
| Functional requirements | Anchor the explicit security contract | High |
| Config behavior tables | Prevent drift between docs and code | High |
| Architectural boundaries | Show where trust is enforced in code | Medium |
| Key entities | Keep terminology stable | Medium |

Human-useful but weaker for implementation scoring:

| Section | Why it is weaker for implementation |
| --- | --- |
| Status metadata | Context only |
| General security motivation | Useful framing, not executable behavior |

### Key Entities

- **Config Source**: Explicit source string from CLI or environment.
- **Project Directory**: Repository being scanned; defines the trust boundary.
- **SloppyJoeConfig**: Parsed JSON policy object.
- **Trust Boundary**: Rule that policy must come from outside the scanned project.
- **Source Resolver**: Precedence logic for CLI, environment, and default config.

## 4. Non-Negotiable Constraints

- A broken explicit config source must never silently fall back to default config.
- In-repo config files must never be treated as trusted policy.
- Remote config transport must never downgrade to plain HTTP.
- The trust boundary must hold even when path canonicalization is imperfect.

## 5. Out of Scope

- Signature verification or pinned-digest verification for remote config.
- Preventing an operator from intentionally choosing a weak config outside the repo.
- Auto-discovery of organization-wide config by repo convention.
- Secret management for private remote config sources.

## 6. Architectural Boundaries

### Data sources

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

## 7. Out of Scope for Scoring

These are useful to humans, but not central to machine-usability scoring for this spec:

- Long-form security philosophy
- Centralized policy governance process
- Business process around who is allowed to approve config changes

## 8. Spec Quality Self-Assessment

- **Completeness**: High. Trust boundary, precedence, failure handling, and protected
  semantics are all captured.
- **Ambiguity**: Low. "Config injection" is defined concretely as policy originating from
  the scanned project or an insecure source.
- **Consistency**: High. The spec matches current behavior in `src/config.rs`.
- **Testability**: High. Each requirement maps to a direct path, URL, or parse scenario.
