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

> **The [LiteLLM supply chain attack](https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html) (March 2026) compromised a package with 97M monthly downloads. Attackers stole publishing credentials, pushed malicious versions that harvested SSH keys, cloud credentials, and K8s secrets. sloppy-joe's default 72-hour version age gate would have blocked both poisoned versions — they were discovered within hours, well before the gate would have opened. If you run `sloppy-joe check` in CI, this attack fails.** [Full analysis](docs/blog/2026-03-24-litellm-attack-blocked.md)

AI code generators hallucinate package names [~20% of the time](https://arxiv.org/abs/2406.10279). Attackers register those names and wait. sloppy-joe catches them in CI before `npm install` or `pip install` runs.

## How to Use

```bash
# Install (single static binary, no runtime dependencies)
cargo install sloppy-joe

# Or download an auditable binary archive from GitHub Releases
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

**Scan modes:**
- `sloppy-joe check` runs the fast local guardrail. It always enforces manifest parsing, lockfile/sync, provenance, and unsupported-source policy. If dependency or policy state changed, or the last successful full scan is older than 24 hours, it recommends `sloppy-joe check --full`.
- `sloppy-joe check --full` runs the strict online scan and refreshes the recorded successful full-scan state.
- `sloppy-joe check --ci` runs the same strict coverage as `--full`, with CI-oriented intent.

**Exit codes:** `0` = no blocking issues found in the selected mode, `1` = blocking issues found, `2` = runtime error.

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
| Python | `pyproject.toml`, `requirements*.txt`, `Pipfile`, `setup.cfg`, or `setup.py` | trusted Poetry path uses `poetry.lock`; legacy manifests allowed with warnings by default |
| Rust | `Cargo.toml` | `Cargo.lock` |
| Go | `go.mod` | `go.sum` required for external deps |
| Ruby | `Gemfile` | `Gemfile.lock` |
| PHP / Composer | `composer.json` | `composer.lock` |
| JVM / Gradle | `build.gradle` or `build.gradle.kts` | `gradle.lockfile` |
| JVM / Maven | `pom.xml` | warning-only: no trusted project-local lockfile path yet |
| .NET / NuGet | `.csproj` | `packages.lock.json` |

**Config sources:** local file path, HTTPS URL, or `SLOPPY_JOE_CONFIG` env var. Config is never read from the project directory (see [CONFIG.md](CONFIG.md) for why).

**Onboarding:** use the bootstrap mode that matches the repo:
- `sloppy-joe init --greenfield --ecosystem <eco>` prints an ecosystem-specific starter policy for new projects. Today, greenfield presets are implemented for `npm`, `pypi`, and `cargo`; other ecosystems fail with a “not supported yet” error. Add `--register` to write it outside the repo and register it safely.
- `sloppy-joe init --from-current` inspects the current repo and prints review-only bootstrap suggestions. Today, `--from-current` is implemented only for repos whose first-party code is `npm` and/or `cargo`; other ecosystems fail closed with a “not implemented yet” error. Add `--register` to write and register the generated config.
- `sloppy-joe init` with no mode prints a neutral manual template.

---

## Why sloppy-joe?

**Single binary. 8 ecosystems. 16 attack types. Zero false positives on generative checks. Config that AI agents can't tamper with.**

Most dependency security tools check one or two things — existence, or edit distance. sloppy-joe checks 16 attack vectors in a single pass: hallucinated packages, 10 types of typosquatting (homoglyphs, scope squatting, repeated chars, separator confusion, word reordering, adjacent swaps, omitted chars, confused forms, case variants, version suffixes), canonical enforcement, version age gating, install script amplification, dependency explosion, maintainer changes, and known vulnerabilities via OSV.dev.

It runs as a single Rust binary with no runtime dependencies. It supports all 8 major package ecosystems. And its config is designed for security: never read from the project directory, loadable from a URL for CI, with clear error messages when something is wrong.

| | sloppy-joe | Socket.dev | GuardDog | Phantom Guard | antislopsquat |
|---|:---:|:---:|:---:|:---:|:---:|
| **Existence check** | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: | :white_check_mark: |
| **Similarity / typosquat** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| **Homoglyph detection** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Scope squatting** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Canonical enforcement** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Version age gate** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Install script amplifier** | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| **Dependency explosion** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Maintainer change** | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| **OSV vulnerability check** | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| **Config security (out-of-repo)** | :white_check_mark: | N/A | :x: | :x: | :x: |
| **Internal + allowed lists** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **npm** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| **PyPI** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Cargo** | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: | :x: |
| **Go** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: | :x: |
| **Ruby** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: | :x: |
| **PHP** | :white_check_mark: | :large_orange_diamond: | :x: | :x: | :x: |
| **JVM (Gradle/Maven)** | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| **.NET (NuGet)** | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| **Single binary** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Open source** | Apache 2.0 | Commercial | Apache 2.0 | MIT | OSS |
| **Language** | Rust | SaaS | Python | Python | Python |

:large_orange_diamond: = beta/experimental

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

### 2. Typosquatting (generative checks + edit distance fallback)

**The attack:** An attacker registers `expresz` on npm — one character from `express`. AI generates it, or a developer fat-fingers it. The package exists, passes the existence check, and installs malware.

**How sloppy-joe blocks it:** sloppy-joe runs 10 generative checks before falling back to edit distance. Each generative check produces a specific mutation of the dependency name (swap characters, collapse repeats, strip suffixes, reorder words, normalize separators, replace homoglyphs, check scopes) and tests for an exact match against known popular packages. This approach, inspired by the [Rust Foundation's Typomania](https://github.com/rustfoundation/typomania) library, has near-zero false positives because it only fires on exact matches after mutation.

Levenshtein edit distance runs last as a safety net for novel mutations that no specific check anticipated. Together, they cover both known attack patterns (precisely) and unknown ones (broadly).

```
ERROR expresz [similarity/edit-distance]
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

**How sloppy-joe blocks it:** Splits on separators, generates all permutations of the segments, and checks each against the corpus. `parse-json` → permute → `json-parse` → match.

```
ERROR parse-json [similarity/word-reorder]
      'parse-json' is a reordering of 'json-parse'.
 Fix: Use 'json-parse' — the segments are in the wrong order.
```

### 6. Adjacent character swaps

**The attack:** `reqeust` instead of `request`. Two adjacent characters transposed — a common typo that attackers weaponize.

**How sloppy-joe blocks it:** Generates all adjacent-swap variants of the dependency name and checks each against the corpus.

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

**How sloppy-joe blocks it:** The version age gate blocks any dependency whose version was published less than `min_version_age_hours` ago (default: 72 hours). This gives the community, Socket.dev, and other scanners time to flag malicious versions.

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

**The attack:** A package with 12 downloads that happens to be one character away from `requests`. Almost certainly a typosquat.

**How sloppy-joe blocks it:** Flags packages with fewer than 100 downloads (where the registry provides download data — currently npm, crates.io, RubyGems).

```
ERROR requsets [metadata/low-downloads]
      'requsets' has only 12 downloads.
 Fix: Verify 'requsets' is the package you intend to use.
```

---

## Supported Ecosystems

| Ecosystem | Manifest | Lockfile Policy | Existence | Metadata | Age Gate |
|-----------|----------|-----------------|:---------:|:--------:|:--------:|
| npm | package.json | `package-lock.json` or `npm-shrinkwrap.json` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| PyPI | `pyproject.toml`, `requirements*.txt`, `Pipfile`, `setup.cfg`, `setup.py` | Poetry is trusted with `poetry.lock`; legacy manifests warn every run unless `python_enforcement` is `poetry_only` | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Cargo | Cargo.toml | `Cargo.lock` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Go | go.mod | `go.sum` required for external deps; not required for stdlib-only or all-local `replace` | :white_check_mark: | :x: | :x: |
| Ruby | Gemfile | `Gemfile.lock` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| PHP | composer.json | `composer.lock` required | :white_check_mark: | :x: | :x: |
| JVM (Gradle) | build.gradle / build.gradle.kts | `gradle.lockfile` required | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| JVM (Maven) | pom.xml | warning-only: no strict lockfile enforcement | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| .NET | *.csproj | `packages.lock.json` required | :white_check_mark: | :x: | :x: |

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
| `0` | All checks passed |
| `1` | Issues found |
| `2` | Runtime error |

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

**`internal`** — your org's packages. Skip ALL checks. These change constantly.

**`allowed`** — vetted external packages. Skip existence + similarity, but still subject to the version age gate.

**`similarity_exceptions`** — exact package/candidate/generator suppressions for reviewed similarity false positives. Use this when one specific similarity edge is wrong but you still want normal checks on the package.

**`metadata_exceptions`** — exact reviewed metadata suppressions. Currently this only supports `metadata/maintainer-change`, and it requires an exact package/version/previous-publisher/current-publisher match.

Use `sloppy-joe check --review-exceptions` when you need to review maintainer-change blockers. The scan still blocks normally, but human output adds a `REVIEW EXCEPTIONS` section with owners, repository URL, and a ready-to-paste `metadata_exceptions` snippet. `--json` includes the same data in a top-level `review_candidates` field.

**`min_version_age_hours`** — block any version published less than this many hours ago. Default: 72 (3 days). Set to 0 to disable. Internal packages are exempt.

**`allow_legacy_npm_v1_lockfile`** — allow `lockfileVersion: 1` npm lockfiles from npm v5/v6 in reduced-confidence mode. Default: `false`. Keep this off unless you are intentionally stuck on legacy npm and accept loud warnings plus reduced trusted npm transitive coverage.

**`python_enforcement`** — controls Python trust policy. `prefer_poetry` (default) trusts Poetry projects and warns on every run for legacy manifests like `requirements*.txt`, `Pipfile`, `setup.cfg`, `setup.py`, and non-Poetry `pyproject.toml`. `poetry_only` blocks those legacy manifests and requires Poetry.

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
sloppy-joe init > /secure/location/config.json
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
      - uses: brennhill/sloppy-joe@v0.9.1
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
# Minimal — auto-detect ecosystem, no config
- uses: brennhill/sloppy-joe@v0.9.1

# With org config from a URL
- uses: brennhill/sloppy-joe@v0.9.1
  with:
    config: https://raw.githubusercontent.com/yourorg/configs/main/sloppy-joe.json

# Deep scan with paranoid mode
- uses: brennhill/sloppy-joe@v0.9.1
  with:
    config: ${{ secrets.SLOPPY_JOE_CONFIG }}
    deep: true
    paranoid: true

# Scan a subdirectory, pin to a specific version
- uses: brennhill/sloppy-joe@v0.9.1
  with:
    dir: ./packages/api
    version: '0.9.1'
```

### GitLab CI

```yaml
dependency-guard:
  script:
    - cargo install sloppy-joe
    - sloppy-joe check --config $SLOPPY_JOE_CONFIG
```

### pre-commit

sloppy-joe works with the [pre-commit](https://pre-commit.com) framework.
Add it to your `.pre-commit-config.yaml`:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/brennhill/sloppy-joe
    rev: v0.9.1
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

sloppy-joe uses a **registry-based generative** approach to similarity detection. Instead of comparing every dependency against a static corpus with edit distance (which produces false positives), it generates specific mutations of each dependency name, queries the registry to check if the mutation exists, and flags exact matches.

```
Pipeline (in order):
  1. Canonical check         — flag deps that violate org standards
  2. Similarity check        — 8 mutation generators + scope squatting
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

**Similarity cache.** Mutation existence results are cached for 7 days. After the first scan, most queries are served from cache with zero network calls. Only new dependencies trigger registry queries.

**Lockfile-aware resolution.** When a supported lockfile is present and trustworthy (`package-lock.json`, `npm-shrinkwrap.json`, `Cargo.lock`, `Gemfile.lock`, `poetry.lock` for Poetry projects, `composer.lock`, `gradle.lockfile`, `packages.lock.json`), sloppy-joe resolves exact versions from it instead of guessing from ranges.

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

## How sloppy-joe compares

| Feature | sloppy-joe | Socket.dev | cargo-deny | pip-audit | npm audit |
|---------|:---:|:---:|:---:|:---:|:---:|
| **Hallucinated package detection** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Typosquatting detection** | :white_check_mark: 11 generators | Partial | :x: | :x: | :x: |
| **Canonical name enforcement** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Known vulnerability scanning** | :white_check_mark: via OSV | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Install script analysis** | Basic (flag + no repo) | :white_check_mark: Deep analysis | :x: | :x: | :x: |
| **License compliance** | OOS: compliance, not security | :white_check_mark: | :white_check_mark: Excellent | OOS: compliance, not security | OOS: compliance, not security |
| **Multi-ecosystem** | 8 ecosystems | npm, PyPI, Go, Ruby, Java, .NET | Rust only | Python only | npm only |
| **AI agent safety** (out-of-repo config) | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Offline/CI friendly** | :white_check_mark: Runs anywhere | Requires Socket platform | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Free / open source** | Apache 2.0 | Free tier + paid | Apache 2.0 | Apache 2.0 | Built-in |

**Where others are stronger:** Socket.dev does deep install script analysis with behavioral detection that goes well beyond sloppy-joe's flag-based approach. cargo-deny has best-in-class license compliance checking, but that is intentionally out of scope for sloppy-joe because license policy is a compliance problem rather than a dependency security control. npm audit and pip-audit are zero-install options for single-ecosystem vulnerability scanning.

**Where sloppy-joe is different:** It's the only tool that verifies packages actually exist on registries (catching AI hallucinations), runs 11 typosquatting generators with near-zero false positives, enforces canonical package choices, and keeps its config outside the repo so AI agents can't weaken their own checks.

## License

Apache 2.0
