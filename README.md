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

AI code generators hallucinate package names [~20% of the time](https://arxiv.org/abs/2406.10279). Attackers register those names and wait. sloppy-joe catches them in CI before `npm install` or `pip install` runs.

## Why sloppy-joe?

| | sloppy-joe | Socket.dev | GuardDog | Phantom Guard | antislopsquat |
|---|:---:|:---:|:---:|:---:|:---:|
| **Existence check** | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: | :white_check_mark: |
| **Similarity / typosquat** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| **Homoglyph detection** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Canonical enforcement** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Version age gate** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Config security (out-of-repo)** | :white_check_mark: | N/A | :x: | :x: | :x: |
| **Allowed + internal lists** | :white_check_mark: | :x: | :x: | :x: | :x: |
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

### 2. Typosquatting (edit distance)

**The attack:** An attacker registers `expresz` on npm — one character from `express`. AI generates it, or a developer fat-fingers it. The package exists, passes the existence check, and installs malware.

**How sloppy-joe blocks it:** The Levenshtein distance check finds `expresz` is 1 character from `express`. Build blocked.

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

### 12. Non-canonical packages

**The attack:** Not an attack — a consistency problem. AI picks `moment` because it was popular in training data, but your team uses `dayjs`. Different teams using different packages for the same job creates maintenance debt and dependency bloat.

**How sloppy-joe blocks it:** Your config maps each canonical package to its rejected alternatives. If a dependency matches an alternative, the build fails.

```
ERROR moment [canonical]
      'moment' is not the approved package for this purpose.
      Your team uses 'dayjs'.
 Fix: Replace 'moment' with 'dayjs' in your manifest file.
```

### 13. Too-new versions (supply chain time bomb)

**The attack:** An attacker compromises a package maintainer's account (or a maintainer goes rogue) and publishes a malicious patch version. It looks like a normal update. If your CI installs it immediately, you're compromised before anyone notices.

**How sloppy-joe blocks it:** The version age gate blocks any dependency whose version was published less than `min_version_age_hours` ago (default: 72 hours). This gives the community, Socket.dev, and other scanners time to flag malicious versions.

```
ERROR react [metadata/version-age]
      Version '^19.0.0' of 'react' was published 6 hours ago (minimum: 72 hours).
      New versions need time for the community and security scanners to review them.
 Fix: Wait until the version is at least 72 hours old, or pin to an older version.
```

### 14. Brand-new packages

**The attack:** A package created yesterday with 3 downloads that has a name similar to a popular package. High probability of being a typosquat or a placeholder for a future attack.

**How sloppy-joe blocks it:** Flags any package created less than 30 days ago.

```
ERROR sketchy-lib [metadata/new-package]
      'sketchy-lib' was first published 2 days ago.
      New packages are higher risk.
 Fix: Verify 'sketchy-lib' at its registry page and source repository.
```

### 15. Low-download packages

**The attack:** A package with 12 downloads that happens to be one character away from `requests`. Almost certainly a typosquat.

**How sloppy-joe blocks it:** Flags packages with fewer than 100 downloads (where the registry provides download data — currently npm, crates.io, RubyGems).

```
ERROR requsets [metadata/low-downloads]
      'requsets' has only 12 downloads.
 Fix: Verify 'requsets' is the package you intend to use.
```

---

## Supported Ecosystems

| Ecosystem | Manifest | Existence | Metadata | Age Gate |
|-----------|----------|:---------:|:--------:|:--------:|
| npm | package.json | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| PyPI | requirements.txt | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Cargo | Cargo.toml | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Go | go.mod | :white_check_mark: | :x: | :x: |
| Ruby | Gemfile | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| PHP | composer.json | :white_check_mark: | :x: | :x: |
| JVM | build.gradle / pom.xml | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| .NET | *.csproj | :white_check_mark: | :x: | :x: |

All ecosystems get existence + similarity + canonical checks. Metadata and age gate depend on what the registry API exposes.

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
  "min_version_age_hours": 72
}
```

**`canonical`** — keys are approved packages; values are rejected alternatives.

**`internal`** — your org's packages. Skip ALL checks. These change constantly.

**`allowed`** — vetted external packages. Skip existence + similarity, but still subject to the version age gate.

**`min_version_age_hours`** — block any version published less than this many hours ago. Default: 72 (3 days). Set to 0 to disable. Internal packages are exempt.

### Config Security

The config is **never read from the project directory**. An AI agent with shell access could rewrite an in-repo config to allowlist whatever it wants.

Config resolution:
1. `--config /path/to/config.json` (CLI flag, highest priority)
2. `SLOPPY_JOE_CONFIG=/path/to/config.json` (env var)
3. No config = existence + similarity + metadata checks only

Generate a template:
```bash
sloppy-joe init > /secure/location/config.json
```

## CI Integration

### GitHub Actions

```yaml
name: Dependency Guard
on: [pull_request]

jobs:
  sloppy-joe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install sloppy-joe
        run: cargo install sloppy-joe
      - name: Check dependencies
        run: sloppy-joe check --config ${{ secrets.SLOPPY_JOE_CONFIG }}
```

### GitLab CI

```yaml
dependency-guard:
  script:
    - cargo install sloppy-joe
    - sloppy-joe check --config $SLOPPY_JOE_CONFIG
```

### Pre-commit Hook

```bash
#!/bin/sh
sloppy-joe check || exit 1
```

## Architecture

sloppy-joe uses a **generative-first** approach to similarity detection, inspired by the [Rust Foundation's Typomania](https://github.com/rustfoundation/typomania) library. Instead of comparing every dependency against every popular package with edit distance (which produces false positives), it generates specific mutations of each dependency name and checks if any mutation matches a known package.

```
For each dependency:
  1. Homoglyph normalization     → check against corpus
  2. Separator normalization     → check against corpus
  3. Repeated character collapse → check against corpus
  4. Version suffix stripping    → check against corpus
  5. Word reordering            → check against corpus
  6. Adjacent character swaps    → check against corpus
  7. Omitted character insertion → check against corpus
  8. Ecosystem confused forms    → check against corpus
  9. Case-variant detection      → check against corpus
  10. Levenshtein distance       → fallback for novel mutations
```

Generative checks fire only when a mutation produces an **exact match** to a known package — zero false positives. Levenshtein runs last as a safety net for mutations nobody anticipated.

## Built On

- [typomania](https://crates.io/crates/typomania) — Rust Foundation's typosquatting detection primitives
- [strsim](https://crates.io/crates/strsim) — String similarity metrics

## Tests

139 tests. Covers all similarity checks, metadata signals, config parsing, all 8 parsers, and report formatting.

```bash
cargo test
```

## License

Apache 2.0
