# JavaScript

This guide covers the current JavaScript support surface in `sloppy-joe`: `npm`, `pnpm`, `Yarn`, and `Bun`.

## Quick Start

Commit `package.json` plus the authoritative lockfile for the manager that actually owns the project:

- `npm`: `package-lock.json` or `npm-shrinkwrap.json`
- `pnpm`: `pnpm-lock.yaml`
- `Yarn`: `yarn.lock`
- `Bun`: `bun.lock`

Recommended commands:

```bash
sloppy-joe check
sloppy-joe check --full
sloppy-joe check --ci
```

If the project is a workspace or monorepo, scan the workspace root when possible.

## What sloppy-joe checks

- `package.json` is required.
- `sloppy-joe` binds each project to the authoritative JavaScript manager and root lockfile instead of trusting per-package shadow lockfiles.
- Exact direct and transitive versions are resolved from the authoritative manager lockfile when that lockfile is trusted.
- Local `workspace:`, `file:`, and `link:` dependencies are validated against real in-repo package directories and the lockfile’s recorded local target.
- Registry entries are provenance-checked:
  - lockfile entries must carry the expected identity
  - integrity metadata is required where the manager exposes it
  - tarball URLs must match the locked package identity and version exactly
- Alias dependencies are preserved under their real published identity instead of being flattened into the alias name.
- JavaScript transitives get similarity coverage in the trusted path, because JS typosquats often hide below the direct dependency layer.

## What blocks

- Missing, unreadable, or malformed authoritative lockfiles.
- Lockfiles that do not match `package.json`.
- Shadow or conflicting lockfiles that disagree with the authoritative manager/root model.
- Local bindings that point at the wrong directory or the wrong local package identity.
- Non-standard or untrusted tarball provenance in the lockfile.
- Manager-specific unsupported trust surfaces, including:
  - npm `overrides`
  - bundled npm payloads (`bundled` / `inBundle`)
  - legacy npm `lockfileVersion: 1` by default
  - Bun binary lockfiles (`bun.lockb`)
  - unsupported Yarn protocols such as `portal:` and `patch:`

## Current limitations

- Private or non-standard JavaScript registry tarball sources currently fail closed instead of being modeled as a separate trusted-registry surface.
- npm `overrides` are not trusted yet because they rewrite the resolved graph.
- Bundled npm payloads are not trusted from lockfile metadata alone.
- `bun.lockb` is not supported; commit the text `bun.lock` instead.
- Unsupported manager-specific protocols fail closed rather than degrading silently.

## Recommended workflow

- Keep one authoritative manager per project area and commit its real lockfile.
- Scan the workspace root for workspace-managed repos.
- Use `sloppy-joe check` as the fast local guardrail and `sloppy-joe check --ci` in CI.
- If you are on legacy npm v5/v6 and must keep `lockfileVersion: 1`, turn on `allow_legacy_npm_v1_lockfile: true` only temporarily and expect reduced-confidence warnings.
