<p align="center">
  <picture>
    <img src="https://raw.githubusercontent.com/brennhill/sloppy-joe/main/assets/sloppy-joe.svg?v=3" alt="sloppy-joe" width="400"/>
  </picture>
</p>

<h3 align="center">Catch hallucinated, typosquatted, and non-canonical dependencies<br/>before they reach production.</h3>

<p align="center">
  <code>cargo install sloppy-joe</code>
</p>

---

> Compromised releases can use a legitimate package name. The [LiteLLM maintainer report](https://github.com/BerriAI/litellm-docs/blob/main/blog/security_update_march_2026/index.md) identifies malicious versions 1.82.7 and 1.82.8 in March 2026. sloppy-joe's default 72-hour publication-age gate can reject newly published versions when you scan the resolved dependency graph with `--ci` or `--full` **before installation**. This is a timing policy, not inspection of the malicious payload.

Research documents [package hallucinations in generated code](https://arxiv.org/abs/2406.10279). sloppy-joe checks dependency names and metadata before installation; existence alone cannot establish that a registered package is safe.

Package names are limited to 214 bytes for npm and 1,024 bytes for other ecosystems to bound typo-analysis work. Longer names report `Scan not supported` (exit 2).

## How to Use

```bash
# Install (single static binary, no runtime dependencies)
cargo install sloppy-joe

# Or download a prebuilt binary archive from GitHub Releases
# https://github.com/brennhill/sloppy-joe/releases

# Fast local guardrail — auto-detects ecosystem from manifest files
sloppy-joe check

# Strict online scan (recommended before push / release)
sloppy-joe check --full

# Strict CI-oriented scan
sloppy-joe check --ci

# Check a specific directory
sloppy-joe check --dir ./my-project

# Check only npm dependencies
sloppy-joe check --type npm

# Python: every dependency group and extra is scanned by default.
# Narrow to the groups/extras your install actually uses (others are reported as not scanned)
sloppy-joe check --python-groups dev,test --python-version 3.12
sloppy-joe check --python-extras docs --python-platform linux --python-version 3.12

# Enforce canonical rules and org standards via config
sloppy-joe check --config /etc/sloppy-joe/config.json

# Config from a URL (useful in CI — no secrets to manage)
sloppy-joe check --config https://raw.githubusercontent.com/yourorg/security-configs/main/sloppy-joe.json

# JSON output for CI pipelines
sloppy-joe check --json

# Review exact maintainer-change exceptions with evidence
sloppy-joe check --review-exceptions

# Create and register a safe per-repo config outside the repo
sloppy-joe init --register

# Create an ecosystem-specific greenfield starter policy
sloppy-joe init --greenfield --ecosystem npm

# Print review-only bootstrap suggestions for an npm or Cargo repo
sloppy-joe init --from-current

# Or write/register those suggestions safely outside the repo
sloppy-joe init --from-current --register

# Or write a config manually to a secure path outside the repo
sloppy-joe init > /secure/location/sloppy-joe.json
```

### Nix

```bash
nix profile install github:brennhill/sloppy-joe
```

The flake on `main` pins the published binary release and its checksums.

**Scan modes:**
- `sloppy-joe check` runs the fast local guardrail. It always enforces manifest parsing, lockfile/sync, provenance, and unsupported-source policy. If dependency or policy state changed, or the last successful full scan is older than 24 hours, it recommends `sloppy-joe check --full`.
- `sloppy-joe check --full` runs the strict online scan and refreshes the recorded successful full-scan state.
- `sloppy-joe check --ci` runs the same strict coverage as `--full`, with CI-oriented intent.
- For Python, `sloppy-joe check` scans every declared dependency group (Poetry groups, PEP 735 `[dependency-groups]` including `include-group`, uv/PDM dev dependencies, Hatch environments) and every extra by default, because uv and Poetry install groups without extra flags. `--python-groups` and `--python-extras` narrow the scan to the named groups/extras and warn (`resolution/python-groups-not-scanned`) about the declared ones they leave out. Environment markers are evaluated for the current host unless you pass `--python-platform`, `--python-arch`, or `--python-version`; sloppy-joe warns when markers were evaluated implicitly.
- Human-readable plain `sloppy-joe check` output always reminds you to use `--ci` or `--full` for CI and production gating.

**Exit codes:** `0` = no blocking issues found in the selected mode, `1` = blocking findings, `2` = unsupported scan input or runtime error. Unsupported syntax/configuration is not a malware finding.

**Supports:** JavaScript (`npm`, `pnpm`, `Yarn`, `Bun`), Python, Rust, Go, Ruby, PHP, JVM (Gradle/Maven), and .NET — auto-detected from manifest files.

**Ecosystem guides:** see [docs/ecosystems/README.md](docs/ecosystems/README.md) for the current trust model, supported features, and fail-closed limits for each ecosystem.

- [JavaScript](docs/ecosystems/JAVASCRIPT.md)
- [Python](docs/ecosystems/PYTHON.md)
- [Rust](docs/ecosystems/RUST.md)
- [Go](docs/ecosystems/GO.md)
- [Ruby](docs/ecosystems/RUBY.md)
- [PHP / Composer](docs/ecosystems/PHP.md)
- [JVM](docs/ecosystems/JVM.md)
- [.NET / NuGet](docs/ecosystems/DOTNET.md)

| Ecosystem | Required manifest | Trusted lockfile / project state |
|---|---|---|
| JavaScript / npm | `package.json` | `package-lock.json` or `npm-shrinkwrap.json`; legacy npm v1 blocked by default |
| JavaScript / pnpm | `package.json` | `pnpm-lock.yaml` |
| JavaScript / Yarn | `package.json` | `yarn.lock` |
| JavaScript / Bun | `package.json` | `bun.lock` |
| Python | `pyproject.toml`, `requirements*.txt`, `Pipfile`, `setup.cfg`, or `setup.py` | trusted Poetry path uses `poetry.lock`, trusted uv path uses `uv.lock`, and fully hash-locked pip-tools is trusted only when the committed requirements graph binds `--index-url` and any `--extra-index-url` values exactly; repo-visible Python indexes can be allowlisted via `trusted_indexes.pypi`, and any `--index-url`/`--extra-index-url` in a requirements file that is not PyPI or allowlisted blocks (`resolution/untrusted-registry-source`); trusted Python modes evaluate one selected install profile at a time (`runtime` by default, explicit groups/extras/platform/arch/version via CLI); legacy manifests allowed with warnings by default |
| Rust | `Cargo.toml` | `Cargo.lock` |
| Go | `go.mod` | `go.sum` required for external deps |
| Ruby | `Gemfile` | `Gemfile.lock` |
| PHP / Composer | `composer.json` | `composer.lock` |
| JVM / Gradle | `build.gradle` or `build.gradle.kts` | `gradle.lockfile` |
| JVM / Maven | `pom.xml` | warning-only: no trusted project-local lockfile path yet |
| .NET / NuGet | `.csproj` | `packages.lock.json` |

**Scan scope:** recursive scans ignore `.planning` by default. Configure `"ignore_dirs": [".planning", "experiments"]` in the external policy to exclude other directory names, or use `"ignore_dirs": []` to disable configurable exclusions. See [directory exclusions](CONFIG.md#ignore_dirs).

**Repositories with multiple projects:** Sloppy Joe runs each discovered project's dependency chain separately and combines the results. A backend, UI, admin app, and tools can use different managers and lockfiles. An incomplete ancestor npm/pnpm workspace declaration does not claim an independently locked child unless the ancestor explicitly declares `packageManager`; Sloppy Joe reports that selection as a warning. Active workspaces retain their shared-lockfile checks. Human and JSON reports identify each manifest, manager, lockfile, package count, and outcome. In multi-project scans, an unsupported project produces an incomplete result (exit 2) while other independently bound projects still run. Package counts include each project's coverage, so shared dependencies can appear in multiple project runs.

**Private npm registries (npm and pnpm):** project-local `.npmrc` default and scoped HTTPS registry routes are supported. Because `.npmrc` is repository-controlled, `--ci` blocks packages routed through a route that is not allowlisted under `trusted_registries.npm` in the out-of-repo config (`resolution/untrusted-registry-source`). Packages routed through an allowlisted route, and all routed packages outside `--ci`, produce non-blocking `resolution/private-registry-unvetted` warnings. Public packages, including public dependencies of private packages, keep their normal checks. Private package identities are not sent to public registries or OSV; their existence, typo similarity, release age, publisher history, and vulnerabilities are unvetted. Lockfile consistency, integrity metadata, and declared registry source boundaries still apply. The scanner never expands or sends registry credentials. See the [JavaScript guide](docs/ecosystems/JAVASCRIPT.md#private-registries).

**Config sources:** local file path, HTTPS URL, or `SLOPPY_JOE_CONFIG` env var. Config is never read from the project directory (see [CONFIG.md](CONFIG.md) for why).

**Onboarding:** use the bootstrap mode that matches the repo:
- `sloppy-joe init --greenfield --ecosystem <eco>` prints an ecosystem-specific starter policy for new projects. Today, greenfield presets are implemented for `npm`, `pypi`, and `cargo`; other ecosystems fail with a “not supported yet” error. Add `--register` to write it outside the repo and register it safely.
- `sloppy-joe init --from-current` inspects the current repo and prints review-only bootstrap suggestions. Today, `--from-current` is implemented only for repos whose first-party code is `npm` and/or `cargo`; other ecosystems fail closed with a “not implemented yet” error. Add `--register` to write and register the generated config.
- `sloppy-joe init` with no mode prints a neutral manual template.

---

## Why sloppy-joe?

sloppy-joe combines package existence, name-similarity heuristics, canonical package policy, publication-age gates, metadata risk signals, and OSV advisory queries in one Rust binary.

Full and CI scans include metadata and vulnerability checks for supported locked transitive dependencies; `--deep` also checks transitive name similarity. Supported manifest, lockfile, source, and policy-boundary validation runs in fast mode too. Unsupported input stops verification instead of producing a clean scan.

Name similarity and metadata signals can flag legitimate packages. Review findings and use narrowly scoped exceptions in trusted configuration. Keep that configuration outside the scanned repository so repository edits cannot directly weaken it.

---

## How Each Attack Works (and How sloppy-joe Blocks It)

### 1. Hallucinated packages

**The attack:** AI generates `import ai_json_helper`. The package doesn't exist. An attacker registers `ai-json-helper` on PyPI with malware. Next time someone runs `pip install`, they get the malicious package.

**How sloppy-joe blocks it:** The existence check hits the PyPI API and gets a 404. Build blocked.

```
ERROR ai-json-helper [existence]
      Package 'ai-json-helper' does not exist on the pypi registry.
      It may be hallucinated by an AI code generator.
 Fix: Remove 'ai-json-helper' from your dependencies.
```

### 2. Typosquatting (registry-backed mutations)

**The attack:** An attacker registers `expresz` on npm — one character from `express`. AI generates it, or a developer fat-fingers it. The package exists, passes the existence check, and installs malware.

**How sloppy-joe flags it:** Generates name mutations and checks whether candidate names exist in the registry or the same manifest. Scope/namespace checks use edit distance against known scopes. Segment-overlap rules also use selected popular package roots, and dropped-character squats (`expres` for `express`, `similarity/missing-char`) are matched locally against those popular roots and the exact names in your config. These are review signals, not proof of malware; there is no general package-name edit-distance fallback.
```
ERROR expresz [similarity/keyboard-proximity]
      'expresz' is 1 character away from 'express'. This could be a typosquat.
 Fix: If you meant 'express', fix the name in your manifest.
```

### 3. Repeated characters

**The attack:** `expresss` (extra s) or `reeact` (extra e). These are common AI hallucination patterns — the model generates plausible-looking names with repeated characters.

**How sloppy-joe blocks it:** The repeated-character check collapses one duplicate at a time and checks if the result matches a known package. `expresss` → remove one `s` → `express` → match.

```
ERROR expresss [similarity/repeated-chars]
      'expresss' matches 'express' after removing a repeated character.
 Fix: Use 'express' — remove the repeated characters.
```

### 4. Separator confusion

**The attack:** `python-dateutil` vs `python_dateutil` vs `pythondateutil`. On some registries, these are different packages. An attacker registers the variant.

**How sloppy-joe blocks it:** Normalizes all separators (`-`, `_`, `.`) before comparison. If the normalized form matches a known package, it's flagged.

```
ERROR socket_io [similarity/separator-confusion]
      'socket_io' matches 'socket.io' after normalizing separators.
 Fix: Use the canonical name 'socket.io' with the correct separators.
```

### 5. Word reordering

**The attack:** `parse-json` vs `json-parse`. Levenshtein distance is 8 — invisible to edit-distance checks. But an attacker can register the reordered name.

**How sloppy-joe blocks it:** Splits on separators, generates all permutations of the segments, and checks each against the registry. `parse-json` → permute → `json-parse` → match.

```
ERROR parse-json [similarity/word-reorder]
      'parse-json' is a reordering of 'json-parse'.
 Fix: Use 'json-parse' — the segments are in the wrong order.
```

### 6. Adjacent character swaps

**The attack:** `reqeust` instead of `request`. Two adjacent characters transposed — a common typo that attackers weaponize.

**How sloppy-joe blocks it:** Generates all adjacent-swap variants of the dependency name and checks each against the registry.

```
ERROR reqeusts [similarity/char-swap]
      'reqeusts' matches 'requests' with two adjacent characters swapped.
 Fix: Use 'requests' — two characters are transposed.
```

### 7. Omitted characters

**The attack:** `reqests` (missing `u`) instead of `requests`. The AI drops a character and the result is a valid-looking name.

**How sloppy-joe blocks it:** Inserts every a-z character at every position in the name and checks if any result matches a known package. `reqests` + `u` at position 3 → `requests` → match.

```
ERROR reqests [similarity/omitted-char]
      'reqests' matches 'requests' with one character inserted.
 Fix: Use 'requests' — a character appears to be missing.
```

### 8. Homoglyphs (visual lookalikes)

**The attack:** `rеquests` with a Cyrillic `е` (U+0435) instead of Latin `e` (U+0065). Visually identical. The package name looks exactly like `requests` but resolves to a different, malicious package.

**How sloppy-joe blocks it:** Replaces 17 known homoglyph characters (Cyrillic, fullwidth, script variants) with their Latin equivalents and checks if the result matches a known package.

```
ERROR rеquests [similarity/homoglyph]
      'rеquests' contains characters that look identical to 'requests'
      but are different Unicode codepoints (homoglyphs).
 Fix: Replace the lookalike characters with standard ASCII.
```

### 9. Ecosystem confused forms

**The attack:** `py-utils` vs `python-utils`. On PyPI, these are different packages. AI generates one when you meant the other. Similarly, `github.com` vs `gitlab.com` in Go modules.

**How sloppy-joe blocks it:** Applies ecosystem-specific substitution rules (py↔python for PyPI, github↔gitlab for Go) and checks if any variant matches a known package.

```
ERROR py-flask [similarity/confused-form]
      'py-flask' is a confused form of 'flask'.
 Fix: Use the canonical name 'flask'.
```

### 10. Case-variant attacks (case-sensitive registries)

**The attack:** On Go, Maven, and Ruby, `Rails` and `rails` are different packages. An attacker registers the capitalized variant.

**How sloppy-joe blocks it:** On case-sensitive registries, any case variant of a known package is flagged as an error. On case-insensitive registries (npm, PyPI, Cargo, NuGet, PHP), case variants are safe and skipped.

```
ERROR Rails [similarity/case-variant]
      'Rails' differs from 'rails' only in letter casing.
      On case-sensitive registries (ruby) these resolve to different packages.
 Fix: Use the exact casing 'rails' in your manifest.
```

### 11. Version suffix squatting

**The attack:** `requests2` or `lodash-4`. The AI appends a version number to the package name instead of specifying the version properly.

**How sloppy-joe blocks it:** Strips trailing digits and separators and checks if the base name matches a known package.

```
ERROR requests2 [similarity/version-suffix]
      'requests2' looks like 'requests' with a version suffix appended.
 Fix: Use 'requests' and specify the version in your manifest's version field.
```

### 12. Scope squatting (npm, PHP, Go, JVM)

**The attack:** An attacker registers `@typos/lodash` on npm — one character from `@types/lodash`. Or `larvael/framework` on Packagist — two characters from `laravel/framework`. Or `github.com/gooogle/protobuf` on Go — one extra `o`. The scope looks legitimate at a glance. The package resolves. The malware installs.

This is rare but plausible — and "rare but plausible" is exactly what sloppy-joe exists for. The `ua-parser-js` incident in 2021 was scope-related. If it can happen to a package with millions of weekly downloads, it can happen to yours.

**How sloppy-joe blocks it:** Extracts the scope/namespace from the dependency name and compares it against a list of known-good scopes using edit distance. Works on npm (`@scope`), PHP (`vendor/`), Go (`github.com/org`), and JVM (`com.group`).

```
ERROR @typos/lodash [similarity/scope-squatting]
      Scope '@typos' is 1 character away from the known scope '@types'.
      Scope squatting is a known supply chain attack vector.
 Fix: If you meant '@types/lodash', fix the scope in your manifest.
```

```
ERROR github.com/gooogle/protobuf [similarity/scope-squatting]
      Scope 'github.com/gooogle' is 1 character away from 'github.com/google'.
 Fix: If you meant 'github.com/google/protobuf', fix the org name.
```

### 13. Non-canonical packages (not an attack — a consistency gate)

**The attack:** Not an attack — a consistency problem. AI picks `moment` because it was popular in training data, but your team uses `dayjs`. Different teams using different packages for the same job creates maintenance debt and dependency bloat.

**How sloppy-joe blocks it:** Your config maps each canonical package to its rejected alternatives. If a dependency matches an alternative, the build fails.

```
ERROR moment [canonical]
      'moment' is not the approved package for this purpose.
      Your team uses 'dayjs'.
 Fix: Replace 'moment' with 'dayjs' in your manifest file.
```

### 14. Too-new versions (supply chain time bomb)

**The attack:** An attacker compromises a package maintainer's account (or a maintainer goes rogue) and publishes a malicious patch version. It looks like a normal update. If your CI installs it immediately, you're compromised before anyone notices.

**How sloppy-joe blocks it:** The version age gate blocks any dependency whose version was published less than `min_version_age_hours` ago (default: 72 hours). This gives maintainers and security researchers time to identify malicious versions. Resolved versions with missing, invalid, or future publication dates fail the enabled age gate; setting `min_version_age_hours` to zero explicitly disables it.

```
ERROR react [metadata/version-age]
      Version '^19.0.0' of 'react' was published 6 hours ago (minimum: 72 hours).
      New versions need time for the community and security scanners to review them.
 Fix: Wait until the version is at least 72 hours old, or pin to an older version.
```

### 15. Brand-new packages

**The attack:** A package created yesterday with 3 downloads that has a name similar to a popular package. High probability of being a typosquat or a placeholder for a future attack.

**How sloppy-joe blocks it:** Flags any package created less than 30 days ago.

```
ERROR sketchy-lib [metadata/new-package]
      'sketchy-lib' was first published 2 days ago.
      New packages are higher risk.
 Fix: Verify 'sketchy-lib' at its registry page and source repository.
```

### 16. Low-download packages

**The attack:** A package with 12 downloads that happens to be one character away from `requests`. This warrants review; download counts alone do not establish malicious intent.

**How sloppy-joe blocks it:** Flags packages with fewer than 100 downloads (where the registry provides download data — currently npm, crates.io, RubyGems).

```
ERROR requsets [metadata/low-downloads]
      'requsets' has only 12 downloads.
 Fix: Verify 'requsets' is the package you intend to use.
```

---

## Additional supply-chain coverage

| Attack or failure class | What sloppy-joe checks | Practical limit |
|---|---|---|
| Install-time script risk | npm lifecycle-script flags combined with package age, download, name-similarity, or repository signals; publisher/script-history combinations | Reads metadata; does not execute, sandbox, or inspect script contents. |
| Maintainer or publisher change | Changes in publisher identity between versions where metadata is available | A stolen account can publish under the same identity. Legitimate transfers can also be flagged. |
| Malicious transitive injection | Supported lockfile graphs expose transitive packages to metadata and OSV checks; `--deep` adds name similarity | A single added dependency is not necessarily a dependency-explosion finding. That heuristic requires at least ten additions. |
| Known vulnerable versions | Queries OSV by ecosystem, package, and resolved version; follows pagination and fails closed on incomplete results | Depends on published advisories and cache freshness. Maintenance-only `unmaintained` notices are not classified as vulnerabilities; unsoundness advisories remain blocking. An empty result is not a clean bill of health. |
| Dependency confusion or source substitution | Checks supported source/provenance policy, manifest/lock consistency, and exact trusted-index allowlists | Unsupported source configurations stop the scan. An `internal` name pattern does not authenticate the installer source: a prefix match (`acme-*`) keeps internal treatment only when the public registry confirms the name is not published there, otherwise `resolution/internal-source-unproven` blocks and the package is scanned normally. Exact `internal` names are trusted as listed. |
| Registered hallucinated names (slopsquatting) | `existence` blocks names nobody has registered; `new-package`, `low-downloads`, similarity and OSV apply to names an attacker already registered | A squat older than 30 days with downloads passes. No in-the-wild malicious slopsquat is documented in the sources reviewed. |
| Build-time and startup execution without install scripts | npm `binding.gyp` / `*.gyp` counts as an install script. For recent or flagged PyPI versions the wheels are read in memory: `*.pth` import lines and `sitecustomize`/`usercustomize` raise `metadata/python-startup-hook` | Hook code is only matched against a short token list; sdist `setup.py` is not inspected. Established versions are inspected only with `--paranoid`. |
| Release timing | `metadata/dormant-release` (a year of silence, then a recent release) and `metadata/release-burst` (5+ releases in a day), PyPI and npm | Warnings unless combined with install-time code or a publisher change. |
| Guessed package names | `steering/distribution-name` for PyPI names such as `sklearn`, `cv2`, `huggingface-cli` that are import or command names | Fixed table of well-known mismatches; established packages only warn. |
| Dependencies an assistant just added | With `--base-ref <REF>` (`HEAD` locally, `origin/main` in CI), `steering/new-dependency` singles out direct dependencies the manifest did not declare at that ref and runs deeper inspection on them | Opt-in. Direct manifest dependencies only; a manifest that needs sibling files at the ref cannot be compared. |
| Python lockfile tampering | `poetry.lock`, `uv.lock` and `Pipfile.lock` sha256 hashes must be ones PyPI publishes for that version | Entries from other indexes, git or paths are covered by source policy, not hash comparison. |
| Compromised maintainer accounts and worms | Version-age gate; publisher-change checks | A stolen account publishes under the same identity. Valid Sigstore/SLSA provenance is not a trust signal and is not read. |
| Lockfile and scanner bypass attempts | Rejects unsupported dependency expressions, unverifiable graphs, unsafe policy locations, and stale/future cache evidence | Validates supported metadata and policy; does not download every artifact and recompute its integrity digest. |

The [Axios maintainer postmortem](https://github.com/axios/axios/issues/10636) describes malicious releases adding `plain-crypto-js` as a transitive dependency. This illustrates why checking only direct package names is insufficient. [GitHub's Shai-Hulud analysis](https://github.blog/security/supply-chain-security/strengthening-supply-chain-security-preparing-for-the-next-malware-campaign/) describes lifecycle-script execution and stolen publishing credentials. These incidents motivate the checks above; they were not replayed as end-to-end prevention tests.

[pip explicitly warns about dependency confusion with `--extra-index-url`](https://pip.pypa.io/en/stable/cli/pip_install/#examples). Source policy and trusted configuration matter alongside package-name checks. See the [coverage research](docs/research/2026-10-23-supply-chain-coverage.md) for primary sources and implementation limits.

## Supported Ecosystems

| Ecosystem | Manifest | Lockfile Policy | Existence | Metadata | Age Gate |
|-----------|----------|-----------------|:---------:|:--------:|:--------:|
| npm | package.json | `package-lock.json` or `npm-shrinkwrap.json` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| PyPI | `pyproject.toml`, `requirements*.txt`, `Pipfile`, `setup.cfg`, `setup.py` | Poetry is trusted with `poetry.lock`, uv is trusted with `uv.lock`, fully hash-locked pip-tools is trusted only when the committed requirements graph binds `--index-url` and exact allowlisted `--extra-index-url` values, and repo-visible Poetry/uv custom indexes can be trusted only by exact `trusted_indexes.pypi` allowlist; legacy manifests warn every run unless `python_enforcement` is `poetry_only` | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Cargo | Cargo.toml | `Cargo.lock` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Go | go.mod | `go.sum` required for external deps; local/remote replacements and Go workspaces are unsupported | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Ruby | Gemfile | `Gemfile.lock` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| PHP | composer.json | `composer.lock` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| JVM (Gradle) | build.gradle / build.gradle.kts | `gradle.lockfile` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| JVM (Maven) | pom.xml | warning-only: no strict lockfile enforcement | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| .NET | *.csproj | `packages.lock.json` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |

All ecosystems get existence + similarity + canonical checks. Metadata and age gate depend on what the registry API exposes. Lockfile support enables transitive dependency scanning and exact version resolution where the ecosystem provides a trustworthy project-local lockfile model.

## Quick Start

```bash
# Install
cargo install sloppy-joe

# Check current project (auto-detects ecosystem)
sloppy-joe check

# Check with canonical enforcement and age gate
sloppy-joe check --config /etc/sloppy-joe/config.json

# Output as JSON for CI
sloppy-joe check --json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No blocking findings in the selected mode |
| `1` | Blocking findings |
| `2` | Unsupported scan input or runtime error |

## Config

```json
{
  "canonical": {
    "npm": {
      "lodash": ["underscore", "ramda", "lazy.js"],
      "dayjs": ["moment", "luxon"],
      "axios": ["request", "got", "node-fetch", "superagent"]
    },
    "pypi": {
      "httpx": ["urllib3", "requests"],
      "ruff": ["flake8", "pylint"]
    }
  },
  "internal": {
    "go": ["github.com/yourorg/*"],
    "npm": ["@yourorg/*"]
  },
  "allowed": {
    "npm": ["some-vetted-external-pkg"]
  },
  "similarity_exceptions": {
    "cargo": [
      {
        "package": "serde_json",
        "candidate": "serde",
        "generator": "segment-overlap"
      }
    ]
  },
  "metadata_exceptions": {
    "cargo": [
      {
        "package": "colored",
        "check": "metadata/maintainer-change",
        "version": "2.2.0",
        "previous_publisher": "kurtlawrence",
        "current_publisher": "hwittenborn"
      }
    ]
  },
  "min_version_age_hours": 72,
  "allow_legacy_npm_v1_lockfile": false,
  "python_enforcement": "prefer_poetry"
}
```

**`canonical`** — keys are approved packages; values are rejected alternatives.

**`internal`** — your org's packages. Keep OSV vulnerability checks; skip other package checks.

**`allowed`** — vetted external packages. Skip existence + similarity, but retain canonical, metadata, version-age, and OSV checks. These rules also apply to transitive dependencies.

**`similarity_exceptions`** — exact package/candidate/generator suppressions for reviewed similarity false positives. Use this when one specific similarity edge is wrong but you still want normal checks on the package.

**`metadata_exceptions`** — exact reviewed metadata suppressions. Currently this only supports `metadata/maintainer-change`, and it requires an exact package/version/previous-publisher/current-publisher match.

Use `sloppy-joe check --review-exceptions` when you need to review maintainer-change blockers. The scan still blocks normally, but human output adds a `REVIEW EXCEPTIONS` section with owners, repository URL, and a ready-to-paste `metadata_exceptions` snippet. `--json` includes the same data in a top-level `review_candidates` field.

**`min_version_age_hours`** — block any version published less than this many hours ago. Default: 72 (3 days). Set to 0 to disable. Internal packages are exempt.

**`allow_legacy_npm_v1_lockfile`** — allow `lockfileVersion: 1` npm lockfiles from npm v5/v6 in reduced-confidence mode. Default: `false`. Keep this off unless you are intentionally stuck on legacy npm and accept loud warnings plus reduced trusted npm transitive coverage.

**`python_enforcement`** — controls Python trust policy. `prefer_poetry` (default) trusts Poetry projects and uv projects, trusts fully hash-locked pip-tools requirements only when the committed requirements graph binds `--index-url` and any non-PyPI `--extra-index-url` values exactly, and otherwise downgrades pip-tools to reduced-confidence. Legacy manifests like unhashed `requirements*.txt`, `Pipfile`, `setup.cfg`, `setup.py`, and non-Poetry/non-uv `pyproject.toml` warn every run. `poetry_only` blocks those non-Poetry Python workflows and requires Poetry.

### Config Security

The config is **never read from the project directory**. An AI agent with shell access could rewrite an in-repo config to allowlist whatever it wants.

Config resolution:
1. `--config /path/to/config.json` — local file (CLI flag, highest priority)
2. `--config https://example.com/config.json` — fetch from URL
3. `SLOPPY_JOE_CONFIG=...` — env var (file path or URL)
4. No config = existence + similarity + metadata checks only

Malformed configs **fail hard** with actionable error messages — a broken config never silently falls back to no protection.

See [CONFIG.md](CONFIG.md) for full format reference, CI integration patterns, and examples.

Bootstrap config:
```bash
sloppy-joe init --greenfield --ecosystem npm
sloppy-joe init --from-current
sloppy-joe init --from-current --register
sloppy-joe init --register
```

## CI Integration

### GitHub Actions

The fastest way to add sloppy-joe to your CI pipeline — downloads a pre-built binary from GitHub Releases (no Rust toolchain required):

```yaml
# .github/workflows/deps.yml
name: Dependency Check
on: [push, pull_request]

jobs:
  sloppy-joe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: brennhill/sloppy-joe@v1.2
        with:
          config: https://raw.githubusercontent.com/yourorg/configs/main/sloppy-joe.json
```

#### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `config` | Config file path or HTTPS URL | *(none)* |
| `dir` | Project directory to scan | `.` |
| `type` | Ecosystem (`npm`, `pypi`, `cargo`, `go`, `ruby`, `php`, `jvm`, `dotnet`) | auto-detect |
| `deep` | Enable transitive dep similarity checks | `false` |
| `paranoid` | Enable bitflip mutations | `false` |
| `args` | Additional CLI arguments | *(none)* |
| `version` | sloppy-joe version to install | `latest` |

#### Examples

```yaml
# Minimal — CI-oriented scan, auto-detect ecosystem, no config
- uses: brennhill/sloppy-joe@v1.2

# With org config from a URL
- uses: brennhill/sloppy-joe@v1.2
  with:
    config: https://raw.githubusercontent.com/yourorg/configs/main/sloppy-joe.json

# Deep scan with paranoid mode
- uses: brennhill/sloppy-joe@v1.2
  with:
    config: ${{ secrets.SLOPPY_JOE_CONFIG }}
    deep: true
    paranoid: true

# Scan a subdirectory, pin to a specific version
- uses: brennhill/sloppy-joe@v1.2
  with:
    dir: ./packages/api
    version: '1.2.0'
```

### GitLab CI

```yaml
dependency-guard:
  script:
    - cargo install sloppy-joe
    - sloppy-joe check --ci --config $SLOPPY_JOE_CONFIG
```

### pre-commit

sloppy-joe works with the [pre-commit](https://pre-commit.com) framework.
Add it to your `.pre-commit-config.yaml`:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/brennhill/sloppy-joe
    rev: v1.2.0
    hooks:
      - id: sloppy-joe
```

The hook runs `sloppy-joe check` on every commit (and optionally on push).
It auto-detects your ecosystem from manifest files. Pass additional arguments
via `args`:

```yaml
      - id: sloppy-joe
        args: [--config, "https://example.com/config.json"]
```

Or use a simple shell hook without the framework:

```bash
#!/bin/sh
sloppy-joe check || exit 1
```

## Architecture

For name similarity, sloppy-joe generates mutations, queries registry candidates, and checks related names in the same manifest. Known scopes and selected popular roots add namespace and segment-overlap signals. Legitimate related packages can match these rules.

```
Pipeline (in order):
  1. Canonical check         — flag deps that violate org standards
  2. Similarity check        — name mutation generators + scope squatting
  3. Metadata check          — version age, new package, downloads, install scripts, dep explosion, maintainer change
  4. Existence check         — flag packages that don't exist on the registry
  5. Malicious check         — query OSV.dev for known vulnerabilities
```

Similarity runs 4 phases:
- **Phase 0: Scope squatting** — local check, no network. Compares scope/namespace against known-good scopes via Levenshtein distance.
- **Phase 1: Intra-manifest** — local check. Flags when two deps in the same manifest are mutations of each other.
- **Phase 2: Registry query** — generates mutations, batch-queries the registry for existence, caches results (7-day TTL).
- **Phase 3: Metadata enrichment** — fetches download counts and publish dates for matches to add evidence to reports.

Each mutation generator tags its output, so the reported check type (e.g., `similarity/homoglyph`) is deterministic — the highest-severity generator wins when multiple generators produce the same candidate.

## CI Reliability

sloppy-joe is designed for CI pipelines where flaky failures are unacceptable.

**Retry with backoff.** All registry HTTP calls retry 3 times with exponential backoff (200ms, 400ms, 800ms) on transient failures (5xx, timeouts, connection errors). A single network blip won't fail your build.

**Fail-closed on query errors.** If registry or OSV queries fail, sloppy-joe emits a blocking `registry-unreachable` error instead of silently skipping checks. The scan no longer relies on per-ecosystem thresholds or sample-size cutoffs before it blocks.

**Similarity cache.** Mutation existence results are cached for up to seven days, then refreshed. OSV results have a one-hour cache lifetime. `--no-cache` bypasses disk reads; future-dated caches are discarded. The cache directory (`--cache-dir`, or the user cache directory) must be outside the scanned repository's git root, or the scan root when there is no git root; otherwise the scan stops with an error, because committed files could forge cached results. A relative `XDG_CACHE_HOME` is ignored. A cache file is only trusted when it and its directory belong to the current user, are not group- or world-writable, and match the integrity record (HMAC-SHA256 under a per-user key in the sloppy-joe config directory, never in a cache directory) written with it; anything else, such as a hand-edited `osv-cache.json` or a cache directory copied from elsewhere, is discarded with a warning and fetched again. Code running as your own user can read the key, so this does not defend against that user. Full/CI scans still perform online work beyond similarity-cache hits.

**Lockfile-aware resolution.** When a supported lockfile is present and trustworthy (`package-lock.json`, `npm-shrinkwrap.json`, `Cargo.lock`, `Gemfile.lock`, `poetry.lock` for Poetry projects, `uv.lock` for uv projects, `composer.lock`, `gradle.lockfile`, `packages.lock.json`), sloppy-joe resolves exact versions from it instead of guessing from ranges. It never trusts a lockfile to settle a range for it: a direct dependency declared as a range (`^1`, `>=2`, `1.0`) is trusted from `Cargo.lock` when exactly one locked version satisfies it. In Composer, Gradle, Bundler, NuGet and Poetry projects a ranged direct dependency is still a blocking `resolution/no-trusted-lockfile-sync` error, and one that matches several locked versions is `resolution/ambiguous`; pin those exactly in the manifest. Fully hash-locked `requirements*.txt` can also provide exact pinned versions, and they become fully trusted when the committed requirements graph binds its own `--index-url` and exact allowlisted `--extra-index-url` values.

## Tests

The test suite covers similarity checks, metadata signals, OSV behavior, config parsing and validation, lockfile resolution, manifest and lockfile preflight policy, report formatting, and HTTP retry logic.

```bash
cargo test
```

## Built On

- [Typomania](https://github.com/rustfoundation/typomania) — Rust Foundation's typosquatting library, which inspired the generative mutation approach (sloppy-joe implements its own generators rather than using the crate directly)
- [strsim](https://crates.io/crates/strsim) — Levenshtein distance, used for scope squatting detection
- [reqwest](https://crates.io/crates/reqwest) — Async HTTP client with retry for registry queries
- [OSV.dev](https://osv.dev) — Known vulnerability database for malicious package detection

## Coverage limits

Run `--ci` or `--full` before installing dependencies. The default fast scan validates local dependency state and recommends a fresh full scan; it does not perform the online audit.

sloppy-joe evaluates dependency declarations, supported lockfiles, registry metadata, and advisory records. It does not inspect downloaded package contents, authenticate every publisher, detect arbitrary runtime behavior, or recover a machine after malicious code has run. Metadata heuristics can produce false positives, and unpublished attacks can evade advisory databases. Use reviewed installer/source policy, artifact verification, and runtime controls alongside these checks.

## License

Apache 2.0
