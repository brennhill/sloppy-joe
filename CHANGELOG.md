# Changelog

## Unreleased

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
