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

## Independent install roots

A repository can contain separate npm, pnpm, Yarn, or Bun projects alongside a backend in another language. Each project's dependency chain uses its selected lockfile; versions from one install root do not resolve dependencies in another.

For npm/pnpm workspace detection, an ancestor declaration alone does not claim a child with its own lockfile. If the ancestor has no explicit `packageManager` and its lockfile does not record that child, Sloppy Joe scans the child independently and emits `resolution/independent-install-root`. A root that explicitly selects its manager retains ownership, and malformed ancestor lockfiles remain errors. Existing Yarn/Bun workspace ownership rules remain conservative. An active workspace still rejects conflicting child lockfiles.

Results include a `projects` array with each manifest, manager, selected lockfile, package count, and status (`passed`, `blocked`, or `unsupported`). Findings carry a `project` manifest path. Outcomes describe the selected mode: `passed` in fast mode does not mean online checks ran. Shared dependencies may be checked in more than one project context.

Once projects are identified, binding, preflight, and scan errors are isolated per project. Multi-project scans retain completed results and return exit 2 if any project is unsupported; ordinary blocking findings return exit 1. An incomplete scan is never recorded as a successful full scan. Repository discovery failures that prevent safe project enumeration remain fatal. The scanner does not execute or infer arbitrary CI scripts; keep the selected install roots and managers aligned with the actual build.

## What sloppy-joe checks

- `package.json` is required.
- `sloppy-joe` binds each project to the authoritative JavaScript manager and root lockfile instead of trusting per-package shadow lockfiles.
- Exact direct and transitive versions are resolved from the authoritative manager lockfile when that lockfile is trusted. npm workspace members resolve dependencies from their own location upward, so nested installed versions take precedence over hoisted copies.
- Local `workspace:`, `file:`, and `link:` dependencies are validated against real in-repo package directories and the lockfile’s recorded local target. Every npm `link: true` entry is checked, including transitive links; external, unscanned, or incorrectly named targets make the scan unsupported.
- Registry entries are provenance-checked:
  - lockfile entries must carry the expected identity
  - integrity metadata is required where the manager exposes it
  - public tarball URLs must match the locked package identity and version exactly
  - configured private npm/pnpm tarballs must stay within their declared HTTPS registry origin and path; their contents and identity remain unvetted
- Alias dependencies are preserved under their real published identity instead of being flattened into the alias name.
- JavaScript transitives get similarity coverage in the trusted path, because JS typosquats often hide below the direct dependency layer.

## What blocks

- Missing, unreadable, or malformed authoritative lockfiles.
- Lockfiles that do not match `package.json`.
- Shadow or conflicting lockfiles that disagree with the authoritative manager/root model.
- Local bindings that point at the wrong directory or the wrong local package identity.
- Non-standard or untrusted tarball provenance in the lockfile.
- Manager-specific unsupported trust surfaces, including:
  - npm `overrides`, Yarn `resolutions`, and package-local `pnpm` settings
  - pnpm workspace configuration beyond `packages` membership
  - unsupported `.npmrc` keys, plus manager-specific `.yarnrc`, `.yarnrc.yml`, `.pnpmfile.cjs`, and `bunfig.toml` configuration
  - bundled npm payloads (`bundled` / `inBundle`)
  - legacy npm `lockfileVersion: 1` by default
  - Bun binary lockfiles (`bun.lockb`)
  - unsupported Yarn protocols such as `portal:` and `patch:`

## Current limitations

- Custom registry routing in `.npmrc` is supported for npm and pnpm with explicit unvetted warnings. Private routing for Yarn/Bun and other manager configuration formats remains unsupported.
- npm `overrides` are not trusted yet because they rewrite the resolved graph.
- Bundled npm payloads are not trusted from lockfile metadata alone.
- `bun.lockb` is not supported; commit the text `bun.lock` instead.
- Unsupported manager-specific protocols fail closed rather than degrading silently.

## Recommended workflow

- Keep one authoritative manager per project area and commit its real lockfile.
- Scan the workspace root for workspace-managed repos.
- Use `sloppy-joe check` as the fast local guardrail and `sloppy-joe check --ci` in CI.
- If you are on legacy npm v5/v6 and must keep `lockfileVersion: 1`, turn on `allow_legacy_npm_v1_lockfile: true` only temporarily and expect reduced-confidence warnings.

## Private registries

npm and pnpm projects can retain their project-local `.npmrc` with default or scoped HTTPS registry routes:

```ini
@company:registry=https://gitlab.example/api/v4/projects/${PROJECT_ID}/packages/npm/
//gitlab.example/:_authToken=${PACKAGE_TOKEN}
```

Supported routing follows [npm's default and scoped registry syntax](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/). Registry settings come from the selected install root's `.npmrc`; an unrelated parent or workspace member `.npmrc` does not change that install root. A scope-specific route wins over the default registry. A `${NAME}` placeholder can occupy an entire registry path segment, such as a CI project ID. Hostname placeholders and other interpolation forms report an unsupported scan. The scanner does not read user/global npm configuration or model installer command-line/environment registry overrides; CI must keep effective install routing consistent with committed project configuration.

Credentials are ignored without environment expansion and are never used for network requests. Registry URLs with embedded credentials, HTTP routes, unsupported configuration keys, and mismatched lockfile sources report errors with values redacted. The parser also accepts comments, quoted registry values, registry-scoped authentication settings, and the non-routing keys `always-auth`, `strict-ssl`, `audit`, `fund`, `ignore-scripts`, `save-exact`, and `engine-strict`.

Each direct or transitive package routed to a non-default registry produces a non-blocking `resolution/private-registry-unvetted` warning. This applies to private registries and public-registry mirrors alike: the scanner cannot establish that a mirror serves the same package contents. CI can pass with these warnings. Public package checks continue, including checks on public dependencies pulled in by private packages.

Private identities are not queried against public npm or OSV. Existence, name similarity, metadata, publication age, publisher changes, and vulnerability coverage for those packages are unvetted. Lockfile consistency, required integrity metadata, and declared source origin/path checks remain active. An integrity field is not proof that the payload is safe, and private hosting does not guarantee an uncompromised release. Review registry access and package provenance separately.

For CI, scan a clean checkout and preserve the installer's actual source configuration. Do not remove `.npmrc` or add broad `internal` rules to manufacture a passing result. npm `overrides` and other unsupported graph rewrites remain unsupported even when private registry routing is accepted.
