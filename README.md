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

AI code generators hallucinate package names [~20% of the time](https://arxiv.org/abs/2406.10279). Attackers register those names and wait. Sloppy-joe catches them in CI before `npm install` or `pip install` runs.

## Why sloppy-joe?

| | sloppy-joe | Socket.dev | GuardDog | Phantom Guard | antislopsquat |
|---|:---:|:---:|:---:|:---:|:---:|
| **Existence check** | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: | :white_check_mark: |
| **Similarity / typosquat** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| **Canonical enforcement** | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Config security (out-of-repo)** | :white_check_mark: | N/A | :x: | :x: | :x: |
| **Allowed list (glob patterns)** | :white_check_mark: | :x: | :x: | :x: | :x: |
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

**Four things only sloppy-joe does:**

1. **Canonical enforcement** -- your team picks one package per job (`dayjs`, not `moment`). AI picks whatever was popular in training data. Sloppy-joe rejects the alternatives.
2. **Config security** -- config is never read from the repo. An AI agent with shell access could rewrite an in-repo allowlist to approve its own hallucinated dependencies. Config comes from `--config` or a CI secret.
3. **8 ecosystems, single binary** -- one `cargo install`, zero runtime dependencies. No Python, no Node, no Docker. Runs anywhere Rust compiles.
4. **Allowed list with globs** -- private packages (`@yourorg/*`, `github.com/yourorg/*`) skip the existence check without weakening it for everything else.

## What It Checks

| Layer | What it catches | How |
|-------|----------------|-----|
| **Existence** | Hallucinated packages that don't exist on the registry | HTTP check against npm, PyPI, crates.io, pkg.go.dev, RubyGems, Packagist, Maven Central, NuGet |
| **Similarity** | Typosquats like `requsets` instead of `requests` | Levenshtein distance against popular packages, scaled by name length |
| **Canonical** | Non-standard alternatives (`moment` when your team uses `dayjs`) | Team-controlled allowlist, injected via `--config` |

## Supported Ecosystems

npm | PyPI | Cargo | Go | Ruby | PHP | JVM (Gradle/Maven) | .NET

Auto-detected from manifest files. Or specify with `--type npm`, `--type pypi`, etc.

## Quick Start

```bash
# Install
cargo install sloppy-joe

# Check current project (auto-detects ecosystem)
sloppy-joe check

# Check a specific directory
sloppy-joe check --dir ./my-project

# Check with canonical enforcement
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

## Canonical Config

The config maps each canonical package to a list of alternatives that should be rejected:

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
  "allowed": {
    "go": ["github.com/yourorg/*"],
    "npm": ["@yourorg/*"]
  }
}
```

**`canonical`** -- keys are the approved package; values are alternatives to reject. If a dependency matches an alternative, the build fails.

**`allowed`** -- known-good private packages that won't exist on public registries. Supports glob patterns. These skip the existence check.

### Generate a template

```bash
sloppy-joe init > /secure/path/config.json
```

## Config Security

The config is **never read from the project directory**. An AI agent with shell access could rewrite an in-repo config to allowlist whatever it wants.

Config resolution order:
1. `--config /path/to/config.json` (CLI flag, highest priority)
2. `SLOPPY_JOE_CONFIG=/path/to/config.json` (env var)
3. No config = existence + similarity checks only

Both must point outside the repo. In CI, use a secret:

```yaml
- run: sloppy-joe check --config ${{ secrets.SLOPPY_JOE_CONFIG }}
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

## Example Output

```
Packages not found on registry:
  x fake-json-parser
    Package 'fake-json-parser' was not found on the npm registry. This may be hallucinated.

Packages with suspiciously similar names:
  ~ requsets
    Name 'requsets' is suspiciously similar to popular package 'requests' (edit distance: 1)
    Did you mean: requests

Non-canonical packages (preferred alternatives exist):
  i moment
    'moment' is not the canonical choice. Use 'dayjs' instead.
    Suggested replacement: dayjs

Summary: 12 packages checked, 3 issues found
```

## How It Works

1. **Parse** -- reads `package.json`, `requirements.txt`, `Cargo.toml`, `go.mod`, `Gemfile`, `composer.json`, `build.gradle`/`pom.xml`, or `*.csproj`
2. **Filter** -- skips packages in the `allowed` list
3. **Check existence** -- async HTTP requests to registry APIs (10 concurrent)
4. **Check similarity** -- Levenshtein distance against top packages per ecosystem, with length-scaled thresholds to avoid false positives on short names
5. **Check canonical** -- reverse-lookup against the alternatives map from config
6. **Report** -- human-readable or JSON output, exit code 1 if any issues

## Built On

- [typomania](https://crates.io/crates/typomania) -- Rust Foundation's typosquatting detection primitives
- [strsim](https://crates.io/crates/strsim) -- String similarity metrics

## Tests

95 tests, 93.5% coverage.

```bash
cargo test
```

## License

Apache 2.0
