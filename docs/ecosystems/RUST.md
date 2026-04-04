# Rust

This guide covers the current Rust / Cargo support surface in `sloppy-joe`.

## Quick Start

Required project state:

- `Cargo.toml`
- authoritative `Cargo.lock`

Recommended commands:

```bash
sloppy-joe check
sloppy-joe check --full
sloppy-joe check --ci
```

If the crate is in a workspace, scan the workspace root when possible.

## What sloppy-joe checks

- `Cargo.lock` is required and can be taken from the authoritative workspace root when the manifest belongs to a workspace member.
- `workspace = true` dependencies are resolved from the nearest in-scope `[workspace.dependencies]` entry.
- Local `path` dependencies are supported when they are:
  - inside the scan root, or
  - exact allowlisted external crate directories
- Private registries are supported when both are allowlisted:
  - the manifest-side registry alias
  - the exact `Cargo.lock` source URL
- Git dependencies are supported only in reduced-confidence mode:
  - `cargo_git_policy = "warn_pinned"`
  - exact pinned revisions only
  - repo URL must be allowlisted in `trusted_git_sources.cargo`
- Repo-visible provenance rewrites through `[patch]`, `[replace]`, and repo-local `.cargo/config*` are resolved and checked against the same trust rules as any other Cargo dependency source.

## What blocks

- Missing or unreadable `Cargo.lock`.
- Ambiguous dependency provenance in `Cargo.toml`.
- `workspace = true` entries that cannot be resolved from an in-scope workspace root.
- External `path` dependencies that are not exactly allowlisted.
- Registry aliases or lockfile source URLs that are not allowlisted.
- Git dependencies by default.
- Floating git refs such as branches or tags, even in reduced-confidence git mode.
- Rewrites whose effective target provenance is not trusted exactly.

## Current limitations

- External local paths must be allowlisted exactly; broad directory trust is not supported.
- Git is blocked by default. The only supported relaxation is exact pinned revisions from allowlisted repo URLs in `warn_pinned` mode.
- Registry trust requires both the manifest alias and the exact lockfile source URL; one without the other is not enough.
- Host-local Cargo state outside the repo is not part of repo-trusted CI provenance.

## Recommended workflow

- Commit `Cargo.lock` and scan from the workspace root when the repo uses workspaces.
- Prefer crates.io or explicitly allowlisted private registries.
- Use local `path` dependencies for first-party crates and review any external paths carefully.
- Keep git dependencies rare, pinned, and explicitly allowlisted if you must use them.
