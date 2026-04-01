# sloppy-joe Configuration

sloppy-joe works with zero configuration. Config adds canonical enforcement (reject known-bad alternatives), internal package bypass (skip checks for your org's packages), allowed lists (skip existence/similarity for vetted packages), and Python workflow enforcement.

## Security Model

**Config is never read from the project directory.** An AI agent with shell access could rewrite an in-repo config to allowlist its own hallucinated dependencies. Config is only loaded from:

1. `--config /path/to/config.json` (CLI flag, highest priority)
2. `SLOPPY_JOE_CONFIG=/path/to/config.json` (environment variable)
3. `--config https://example.com/config.json` (URL — fetched at runtime)

If neither is set, sloppy-joe runs with default settings (no canonical rules, no internal/allowed lists, 72-hour version age gate, and `python_enforcement: "prefer_poetry"`).

## Config Format

JSON file with five top-level keys. All are optional.

```json
{
  "canonical": { ... },
  "internal": { ... },
  "allowed": { ... },
  "min_version_age_hours": 72,
  "python_enforcement": "prefer_poetry"
}
```

See [`config.example.json`](config.example.json) for a full working example.

## Fields

### `canonical`

Maps ecosystem → approved package → list of rejected alternatives.

```json
{
  "canonical": {
    "npm": {
      "lodash": ["underscore", "ramda"],
      "dayjs": ["moment", "luxon"]
    },
    "pypi": {
      "httpx": ["requests", "urllib3"]
    }
  }
}
```

**What it does:** If a dependency matches a rejected alternative, sloppy-joe blocks the build and suggests the canonical package instead.

**When to use:** When your team has standardized on specific packages and you want to prevent drift. This is organizational policy, not security — both packages may be legitimate, but you only want one in your codebase.

**Supported ecosystems:** `npm`, `pypi`, `cargo`, `go`, `ruby`, `php`, `jvm`, `dotnet`

### `internal`

Lists your organization's own packages by ecosystem. Supports glob patterns.

```json
{
  "internal": {
    "npm": ["@yourorg/*"],
    "go": ["github.com/yourorg/*"],
    "pypi": ["yourorg-*"],
    "jvm": ["com.yourorg:*"]
  }
}
```

**What it does:** Internal packages skip ALL checks — existence, similarity, canonical, version age, metadata, and vulnerability. They change constantly and are under your control.

**Pattern syntax:** Use `*` at the end for prefix matching. `@yourorg/*` matches `@yourorg/utils`, `@yourorg/core`, etc. Exact strings match exactly.

### `allowed`

Lists vetted external packages that should skip existence and similarity checks but still be subject to version age gating and vulnerability checks.

```json
{
  "allowed": {
    "npm": ["some-vetted-external-pkg"],
    "pypi": ["company-fork-of-requests"]
  }
}
```

**What it does:** Allowed packages skip existence and similarity checks (so they won't be flagged as hallucinated or typosquatted) but are still checked for:
- Version age (was this version published in the last N hours?)
- Known vulnerabilities (OSV.dev)
- Metadata signals (install scripts + other risk factors, dependency explosion, maintainer changes)

**When to use:** For legitimate external packages that trigger false positives on similarity checks (e.g., a package with a name close to a popular one that you've manually verified).

**Difference from internal:** Internal packages skip everything. Allowed packages skip only existence and similarity.

### `min_version_age_hours`

Minimum age (in hours) a package version must have before it's accepted. Default: `72` (3 days).

```json
{
  "min_version_age_hours": 48
}
```

**What it does:** If the specific version pinned in your manifest was published less than N hours ago, the build is blocked. This catches supply chain time bombs — packages that are registered as legitimate, then updated with malware days or weeks later.

**Note:** This checks the exact pinned version's publish date, not just the latest version. Internal packages are exempt. Allowed packages are NOT exempt.

Set to `0` to disable.

### `python_enforcement`

Controls how strictly sloppy-joe treats Python manifest workflows.

```json
{
  "python_enforcement": "prefer_poetry"
}
```

Valid values:

- `prefer_poetry` (default): trust Poetry projects (`pyproject.toml` with Poetry metadata plus `poetry.lock`). Legacy Python manifests such as `requirements*.txt`, `Pipfile`, `setup.cfg`, `setup.py`, and non-Poetry `pyproject.toml` are still scanned, but every run emits a warning encouraging migration to Poetry.
- `poetry_only`: block those legacy Python manifests and require Poetry for Python scans.

Legacy Python support still fails closed on unsafe forms. For example, direct URLs, editable requirements, local paths, VCS sources, and unsupported dynamic dependency declarations are rejected rather than silently skipped.

## Generating a Template

```bash
sloppy-joe init > config.json
```

This outputs a starter config with example values for all ecosystems.

## CI Integration

### GitHub Actions

Store config in a separate repo or as a secret, never in the project repo:

```yaml
# Option 1: Config from a separate repo
- uses: actions/checkout@v4
  with:
    repository: yourorg/security-configs
    path: security-configs
    token: ${{ secrets.CONFIG_REPO_TOKEN }}

- name: Check dependencies
  run: sloppy-joe check --config security-configs/sloppy-joe.json

# Option 2: Config from a URL
- name: Check dependencies
  run: sloppy-joe check --config https://raw.githubusercontent.com/yourorg/security-configs/main/sloppy-joe.json

# Option 3: Config from CI secret (write to temp file)
- name: Write config
  run: echo '${{ secrets.SLOPPY_JOE_CONFIG }}' > /tmp/sj-config.json

- name: Check dependencies
  run: sloppy-joe check --config /tmp/sj-config.json

# Option 4: Environment variable
- name: Check dependencies
  env:
    SLOPPY_JOE_CONFIG: /path/to/config.json
  run: sloppy-joe check
```

### GitLab CI

```yaml
dependency-check:
  image: rust:latest
  before_script:
    - cargo install sloppy-joe
  script:
    - sloppy-joe check --config $SLOPPY_JOE_CONFIG
  variables:
    SLOPPY_JOE_CONFIG: https://gitlab.com/yourorg/security-configs/-/raw/main/sloppy-joe.json
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit (or via pre-commit framework)
sloppy-joe check --config "$SLOPPY_JOE_CONFIG" || exit 1
```

## Common Patterns

### Monorepo with multiple ecosystems

One config file covers all ecosystems. sloppy-joe auto-detects which manifest files exist and only checks relevant ecosystems.

### Gradual rollout

Start with no config (catches hallucinated and non-existent packages). Add `allowed` entries for known false positives. Add `canonical` rules as your team standardizes. Add `internal` patterns for your org packages.

### Strict mode

Set `min_version_age_hours` to `168` (7 days) for maximum protection against supply chain time bombs. Add all your org patterns to `internal`. Use `canonical` to enforce package standards across the codebase.
