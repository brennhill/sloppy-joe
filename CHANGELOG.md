# Changelog

## Unreleased

- bun.lock: resolve dependencies from the nearest nested entry (`parent/child`, `member/child`) before the top-level copy, as Bun installs them, so a nested version can no longer be swapped for the hoisted one; accept nested keys whose last segment matches the locked package and block malformed ones. When bun.lock has no root workspace, every workspace scans entries nothing reaches.
- Pipenv: reconcile a committed `Pipfile.lock` with the Pipfile in both directions. Every package in `[packages]`, `[dev-packages]`, and custom categories must be locked in the matching section with an exact `==` pin and hashes, and must satisfy its Pipfile specifier; lock-only entries are scanned as transitive dependencies at their locked versions. Entries from `git`/`path`/`file`/`editable` sources or a non-PyPI index, and lock sources outside `trusted_indexes.pypi` or not declared in the Pipfile, block.
- Scan the lockfile of a project whose manifest declares no dependencies instead of skipping it: npm, pnpm, Yarn, Bun, Cargo, Bundler, Composer, Poetry and uv lockfile packages are now validated and scanned (or flagged as stale), and Gradle/NuGet lockfiles with packages still block. pnpm now reports packages no importer reaches as `lockfile/orphan-entries` warnings for a standalone lockfile and scans them from the root importer of a workspace or when the graph cannot be fully resolved.

- Python: scan every dependency group and extra by default (Poetry groups, PEP 735 `[dependency-groups]`, uv dev dependencies, optional dependencies; PDM/Hatch environments as unlocked tooling). `--python-groups`/`--python-extras` now narrow the selection and warn about the groups and extras they exclude. Resolve PEP 735 `include-group` entries, blocking on cycles, unknown groups, and malformed include tables.
- uv.lock: read root `optional-dependencies`, `dev-dependencies`, and `requires-dev`, follow locked package extras transitively, and check lock and manifest in both directions. A locked root dependency/extra/group entry missing from pyproject.toml, or a declared group dependency missing from uv.lock, now blocks.
- Verify npm tarballs against registry metadata for new, recent, low-download and flagged versions (all versions with `--paranoid`): hash-check the tarball, read its `package.json` under size limits, and block when its install scripts or dependencies differ from the registry metadata. Download, hash and limit failures for a selected version block instead of being skipped.
- Mark a typosquat finding HIGH CONFIDENCE only when the dependency has few downloads and the package it resembles has many; the reverse is noted as LOW CONFIDENCE without lowering severity.

- GitHub Action: download and extract the release in a fresh temp directory, verify the archive against its published `.sha256`, and never install or put on PATH files from the PR checkout.

- Reject unknown and duplicate keys in sloppy-joe config and local overlay files instead of silently ignoring them.

- Reject cache directories inside the scanned repository (or scan root), including symlinked and not-yet-created paths, and ignore relative `XDG_CACHE_HOME`/`HOME` values; committed cache files can no longer forge OSV or similarity results.

- Report `yarn.lock` entries no dependency reaches as a non-blocking `lockfile/orphan-entries` warning instead of leaving them silently unscanned; when reachability is uncertain (workspace roots, unresolved edges), scan them instead. Block yarn and pnpm lockfile entries with invalid package names and duplicate `yarn.lock` selectors, and resolve Yarn transitive dependencies by their locked identity.

- In `--ci`, block repository `.npmrc` registry routes not allowlisted under `trusted_registries.npm` in the out-of-repo config. Routed package names stay private: they are never sent to the public registry or OSV.

- Reject transitive npm links to external, unscanned, or incorrectly named local targets before a full scan can pass or save a success fingerprint.
- Resolve npm workspace dependencies from the member directory upward, preserve nested versions in vulnerability checks, and use the same lookup for aliases and local links.
- Check ancestor workspace membership before validating manager conflicts, so unrelated parent errors do not suppress independent child scans.

- Scan independent install roots in mixed-manager repositories without treating an incomplete ancestor npm/pnpm workspace declaration as authoritative.
- Report each project and its lockfile separately, retain completed sibling results when another project is unsupported, and return exit 2 for incomplete repository scans.
- Keep registry routing scoped to the selected install root and preserve each chain's direct and transitive version selections.

- Ignore `.planning` during recursive project discovery by default; add the external-policy `ignore_dirs` setting for custom directory exclusions.

- Support default and scoped HTTPS npm registry routing in project-local `.npmrc` for npm and pnpm.
- Report private/custom-registry packages as unvetted with non-blocking warnings; retain public package checks and local lockfile/source validation.
- Keep private identities and authentication values out of public registry/advisory requests, and redact rejected registry source credentials.
- Invalidate scan guidance when effective registry routing changes.
- Resolve npm workspace dependency ranges from the authoritative root lockfile.

## 1.2.0

### Security and correctness

- Close dependency parsing and source-policy bypasses across Python, JavaScript, Ruby, Go, JVM, Cargo, and .NET projects.
- Preserve trusted policy boundaries when scanning subdirectories or relative paths.
- Keep metadata and vulnerability checks active for transitive dependencies and respect cache selection and bypass options.
- Reject future-dated security caches, preserve cache expiry on reuse, and record successful full scans only after passing checks.
- Enforce version-age policy when publication dates are missing or invalid, and account for timezone offsets.
- Bound package-name lengths before typo mutation generation.
- Avoid reporting Cargo hyphen/underscore spellings of the same crate as typosquats.
- Discard invalid generated package names before similarity queries instead of misreporting them as registry outages.
- Accept legacy registry UTC publication timestamps while preserving timezone-aware age checks.
- Include legacy Python build and test dependencies.
- Recognize packaged uv project roots and uv lockfiles without redundant tool metadata.
- Verify supported uv version ranges against exact locked selections instead of requiring redundant manifest pins, using PEP 440 parsing for prerelease, postrelease, and local versions.
- Follow OSV advisory pagination and reject malformed or incomplete query responses.
- Separate maintenance-only unmaintained notices from vulnerability records; retain blocking unsoundness advisories.
- Update affected direct and transitive dependencies to patched versions before release.
- Refresh README coverage against primary-source supply-chain incident reports and document heuristic limits.

### Compatibility notes

- Inputs whose dependency graph or source policy cannot be verified report an unsupported scan (exit 2).
- Legacy setup.py scanning accepts a restricted literal grammar. Executable setup logic, computed arguments, and custom source encodings are unsupported.
- Package names are limited to 214 bytes for npm and 1,024 bytes for other ecosystems.
