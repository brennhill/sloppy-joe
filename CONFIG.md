# sloppy-joe Configuration

sloppy-joe works with zero configuration. Config adds canonical enforcement (reject known-bad alternatives), internal package bypass (skip checks for your org's packages), allowed lists (skip existence/similarity for vetted packages), and Python workflow enforcement.

## Scan Modes

- `sloppy-joe check` is the fast local mode. It always enforces local trust boundaries such as manifest parsing, lockfile requirements, sync/provenance checks, and unsupported-source blocking.
- `sloppy-joe check --full` runs the strict online scan.
- `sloppy-joe check --ci` runs the same strict coverage as `--full`, intended for CI workflows.
- For Python, `sloppy-joe check` scans every declared dependency group (Poetry groups, PEP 735 `[dependency-groups]` including `include-group`, uv/PDM dev dependencies, Hatch environments) and every extra by default, because uv and Poetry install groups without extra flags. `--python-groups` and `--python-extras` narrow the scan to the named groups/extras and warn (`resolution/python-groups-not-scanned`) about the declared ones they leave out. Environment markers are evaluated for the current host unless you pass `--python-platform`, `--python-arch`, or `--python-version`; sloppy-joe warns when markers were evaluated implicitly.
- Human-readable plain `sloppy-joe check` output always reminds you to use `--ci` or `--full` for CI and production gating.

Fast mode does not auto-escalate into a full scan. Instead, it warns when you should run `sloppy-joe check --full`:

- there is no recorded successful full scan yet
- the last successful full scan is older than 24 hours
- dependency, lockfile, manager-binding, or effective policy state changed since the last successful full scan

## Security Model

**Config is never read from the project directory.** An AI agent with shell access could rewrite an in-repo config to allowlist its own hallucinated dependencies. Config is only loaded from:

1. `--config /path/to/config.json` (CLI flag, highest priority)
2. `SLOPPY_JOE_CONFIG=/path/to/config.json` (environment variable)
3. `--config https://example.com/config.json` (URL — fetched at runtime)

If neither is set, sloppy-joe runs with default settings (no canonical rules, no internal/allowed lists, no similarity exceptions, no metadata exceptions, 72-hour version age gate, `allow_legacy_npm_v1_lockfile: false`, and `python_enforcement: "prefer_poetry"`).

## Config Format

JSON file with optional top-level keys. The most common policy keys are:

```json
{
  "ignore_dirs": [".planning"],
  "canonical": { ... },
  "internal": { ... },
  "allowed": { ... },
  "trusted_indexes": { ... },
  "bootstrap_review": { ... },
  "similarity_exceptions": { ... },
  "metadata_exceptions": { ... },
  "min_version_age_hours": 72,
  "allow_legacy_npm_v1_lockfile": false,
  "python_enforcement": "prefer_poetry"
}
```

See [`config.example.json`](config.example.json) for a full working example.

## Fields

### `ignore_dirs`

Directory names excluded from recursive project discovery. Default: `[".planning"]`.

```json
{
  "ignore_dirs": [".planning", "experiments"]
}
```

The list replaces the default. Names match whole directory names at any depth, including symlink targets; paths and glob patterns are rejected. Use `"ignore_dirs": []` to include planning directories. A directory explicitly selected with `--dir` is still scanned, even if its own name appears in the list. `.git` remains excluded.

Exclusions prevent discovery of standalone projects; packages present in an included application's lockfile still receive dependency checks. Keep application/build directories out of the exclusion list. The setting follows the normal external-config policy and participates in scan-cache invalidation. `init --from-current` also skips `.planning` by default.

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

**What it does:** Internal packages retain OSV vulnerability checks and skip other package checks. This applies to direct and transitive packages; manifest, lockfile, and source validation still run.

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

**What it does:** Direct and transitive allowed packages skip existence and similarity checks (so they won't be flagged as hallucinated or typosquatted) but are still checked for:
- Version age (was this version published in the last N hours?)
- Known vulnerabilities (OSV.dev)
- Metadata signals (install scripts + other risk factors, dependency explosion, maintainer changes)

**When to use:** For legitimate external packages that trigger false positives on similarity checks (e.g., a package with a name close to a popular one that you've manually verified).

### `trusted_indexes`

Exact normalized allowlists for non-default Python package indexes used by trusted Poetry and uv projects.

```json
{
  "trusted_indexes": {
    "pypi": [
      "https://download.pytorch.org/whl/cu124",
      "https://packages.example.com/simple"
    ]
  }
}
```

**What it does:** Allows non-PyPI package index provenance only when:
- the project uses a trusted Poetry or uv workflow
- the manifest declares the source/index in repo-visible config
- the authoritative lockfile proves that the resolved package came from that exact normalized URL

PyPI itself is implicitly trusted as `https://pypi.org/simple/`.

**Exact matching:** sloppy-joe normalizes trailing slashes before comparison, but otherwise matches exact URLs only.

**Unused sources:** Declared non-PyPI Poetry/uv sources that are not used by the locked graph warn, but do not block. The warning suggests removing them for clarity and maintenance.

**Requirements files:** Every scanned `requirements*.txt` (hash-locked or not, including `-r`/`-c` includes) is checked too. An `--index-url`, `-i`, or `--extra-index-url` that is neither PyPI nor listed here blocks the project with a `resolution/untrusted-registry-source` error naming the index and the file that declared it. `--find-links` and `--no-index` are unsupported and also block.

**Current scope:** This covers repo-visible Poetry and uv source/index declarations, plus index options in requirements files. Hash-locked pip-tools still downgrades to reduced-confidence when the primary index is not explicitly file-bound, because pip source state can otherwise still come from host-local pip config or environment variables.

### `trusted_registries.npm`

Exact allowlist of project `.npmrc` registry routes. A route is named `default` (the unscoped `registry=` key) or by its `@scope`, and is bound to one exact HTTPS registry URL. A `${NAME}` placeholder may occupy a whole path segment.

```json
{
  "trusted_registries": {
    "npm": [
      { "name": "@company", "source": "https://npm.company.example/" }
    ]
  }
}
```

**What it does:** `.npmrc` lives in the scanned repository, so its routes are repository-controlled. In `--ci` mode, every package routed through a route that is not allowlisted here is a blocking `resolution/untrusted-registry-source` error. Routed packages are private either way: their names are never sent to the public registry or OSV, so allowlisting a route here is what lets CI accept packages that skip those checks. See the [JavaScript guide](docs/ecosystems/JAVASCRIPT.md#private-registries).

### `trusted_registries.jvm`

Exact allowlist of Gradle plugin repositories declared in `pluginManagement { repositories { maven { url = "..." } } }`. Each entry uses the name `gradle-plugins` and one exact repository URL (trailing slashes and host case are normalized).

```json
{
  "trusted_registries": {
    "jvm": [
      { "name": "gradle-plugins", "source": "https://plugins.company.example/m2" }
    ]
  }
}
```

**What it does:** the settings script is repository-controlled, so a custom plugin repository that is not allowlisted here blocks the Gradle project. When every custom plugin repository of a build is allowlisted, its plugins are reported as `resolution/private-registry-unvetted` warnings instead of being checked against the Gradle Plugin Portal. See the [JVM guide](docs/ecosystems/JVM.md#gradle-plugins).

### Python profile selection

Trusted Python modes evaluate one concrete install profile at a time.

- Default: every declared dependency group and every extra. This covers Poetry groups (optional ones too) and `dev-dependencies`, PEP 735 `[dependency-groups]` (with `include-group` resolved), `[tool.uv] dev-dependencies`, `[project.optional-dependencies]`, and Poetry extras. PDM `dev-dependencies` and Hatch environment dependencies are scanned as unlocked tooling, because neither `uv.lock` nor `poetry.lock` records them.
- Narrow groups: `--python-groups dev,test` scans the main dependencies plus only the named groups. Group names are matched after PEP 503 normalization, and selecting a group includes the groups it pulls in with `include-group`.
- Narrow extras: `--python-extras docs` scans only the named extras. The two flags narrow independently, so `--python-groups dev` alone still scans every extra.
- Explicit marker target: `--python-platform linux --python-arch aarch64 --python-version 3.12`

When `--python-groups` or `--python-extras` leaves declared groups or extras out, sloppy-joe reports them in a `resolution/python-groups-not-scanned` warning. When environment markers are evaluated without an explicit platform, arch, or version, it warns (`resolution/python-implicit-runtime-profile`) that the current host was used. Lockfile checks follow the same selection: a dependency declared in a scanned group but missing from `poetry.lock` or `uv.lock` blocks. Profile aliases/defaults are not configurable in `config.json` yet.

### `bootstrap_review`

Carries review-only bootstrap suggestions produced by `sloppy-joe init --from-current`.

```json
{
  "bootstrap_review": {
    "suggested_internal": {
      "npm": ["@acme/web", "@acme/ui"]
    },
    "suggested_trusted_local_paths": {
      "cargo": ["/opt/company/shared-crate"]
    },
    "candidate_canonical_groups": {
      "npm": [
        {
          "packages": ["dayjs", "moment"],
          "reason": "Multiple packages from the same solution family are already in use."
        }
      ]
    }
  }
}
```

**What it does:** Nothing at scan time. This section is informational only.

**When to use:** Keep it while reviewing bootstrap output from `--from-current`. Move reviewed decisions into `canonical` when you are ready to enforce them.

**Difference from internal:** Internal packages skip everything. Allowed packages skip only existence and similarity.

### `similarity_exceptions`

Exact suppressions for known-good similarity false positives. Unlike `allowed`, these only suppress one specific similarity match and do not mute metadata, OSV, canonical, or other similarity findings.

```json
{
  "similarity_exceptions": {
    "cargo": [
      {
        "package": "serde_json",
        "candidate": "serde",
        "generator": "segment-overlap",
        "reason": "serde_json is a legitimate companion crate in the serde ecosystem"
      }
    ]
  }
}
```

**What it does:** If sloppy-joe would flag exactly `package -> candidate` for the specified similarity `generator`, that single finding is suppressed.

**When to use:** For narrow, reviewed false positives where the package itself is still supposed to receive normal existence, metadata, age, canonical, and vulnerability checks.

**Why not `allowed`:** `allowed` skips all similarity checks for that package. `similarity_exceptions` suppresses only one exact edge.

### `metadata_exceptions`

Exact suppressions for reviewed metadata findings. This is narrower than `allowed`: it suppresses one exact metadata edge and leaves similarity, OSV, canonical, version-age, and every other metadata signal intact.

Currently only `metadata/maintainer-change` is supported.

```json
{
  "metadata_exceptions": {
    "cargo": [
      {
        "package": "colored",
        "check": "metadata/maintainer-change",
        "version": "2.2.0",
        "previous_publisher": "kurtlawrence",
        "current_publisher": "hwittenborn",
        "reason": "Reviewed upstream maintainer transfer"
      }
    ]
  }
}
```

**What it does:** Suppresses the maintainer-change finding only when all of these match exactly:
- ecosystem
- package
- check type
- version
- previous publisher
- current publisher

**When to use:** Only after a human review of a specific maintainer transfer on a specific version. This is an audit trail, not a trust shortcut.

**Why so strict:** A different version or a different publisher transition should still block. Maintainer exceptions are intentionally one reviewed edge at a time.

**Review workflow:** Run `sloppy-joe check --review-exceptions` to emit review-ready candidates for maintainer-change findings. Human output includes owners, repository URL, and a ready-to-paste config snippet. `sloppy-joe check --json --review-exceptions` includes the same data in a top-level `review_candidates` array so CI or tooling can surface it programmatically.

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

### `max_npm_tarball_verifications`

Maximum number of npm tarballs downloaded per scan to verify them against registry metadata. Default: `100`. Allowed range: `1` to `1000`; other values are rejected at load time.

```json
{
  "max_npm_tarball_verifications": 250
}
```

**What it does:** npm versions selected for tarball verification (flagged by any signal, published or created within 30 days, fewer than 1,000 downloads, or every version with `--paranoid`) are downloaded and checked against the packument. Cache hits do not count toward the limit. Selected versions beyond the limit are not skipped: each gets a blocking `metadata/tarball-unverified` error that names the limit and how many selected versions went unverified. Verified results are cached, so re-running a scan also makes progress.

**When to raise it:** large monorepos or `--paranoid` scans that hit the limit on a cold cache. Raising it costs more registry downloads per scan; it never weakens a check.

This key is only read from the out-of-repo config, not from the local overlay.

### `allow_legacy_npm_v1_lockfile`

Controls whether sloppy-joe will allow legacy npm v5/v6 `lockfileVersion: 1` lockfiles in reduced-confidence mode.

```json
{
  "allow_legacy_npm_v1_lockfile": true
}
```

Default: `false`

When `false`, sloppy-joe blocks npm v1 lockfiles with a message telling you to regenerate them using a modern npm. This is the recommended setting. When `true`, sloppy-joe keeps scanning but emits loud reduced-confidence warnings and disables trusted npm transitive coverage for that legacy lockfile. Only turn this on if you are intentionally pinned to legacy npm and accept weaker guarantees.

### `python_enforcement`

Controls how strictly sloppy-joe treats Python manifest workflows.

```json
{
  "python_enforcement": "prefer_poetry"
}
```

Valid values:

- `prefer_poetry` (default): trust Poetry projects (`pyproject.toml` with Poetry metadata plus `poetry.lock`) and uv projects (`pyproject.toml` with `tool.uv` plus `uv.lock`). Fully hash-locked pip-tools requirements are trusted only when the committed requirements graph binds its own `--index-url` and any `--extra-index-url` values exactly; otherwise they still scan in reduced-confidence mode. Legacy Python manifests such as unhashed `requirements*.txt`, `Pipfile`, `setup.cfg`, `setup.py`, and non-Poetry/non-uv `pyproject.toml` are still scanned, but every run emits a warning encouraging migration to a trusted Python mode.
- `poetry_only`: block those legacy Python manifests and require Poetry for Python scans.

Legacy Python support still fails closed on unsafe forms. For example, direct URLs, editable requirements, local paths, VCS sources, and unsupported dynamic dependency declarations are rejected rather than silently skipped.

### `config_key_allow`

Package-manager config files in the repository (uv settings in `pyproject.toml` / `uv.toml`, `poetry.toml`, the `config` object of `composer.json`, Gradle and Maven option files, `.npmrc`, `.yarnrc.yml`, `bunfig.toml`, `pnpm-workspace.yaml`, Cargo config and `nuget.config`) are checked against built-in allowlists. A setting that is not on a list blocks, because an unclassified setting may fetch from, cache in, or run something the lockfile never vouched for. When a repository legitimately needs such a setting, name it here, one exact key per entry:

```json
{
  "config_key_allow": [
    { "file": "uv", "key": "keyring-provider" },
    { "file": "composer.json", "key": "github-oauth.github.com" }
  ]
}
```

- `file` is the config surface: `uv` (`[tool.uv]` and `uv.toml`), `poetry.toml`, `composer.json` (its `config` object), `gradle.properties`, `gradle-daemon-jvm.properties`, `maven.config`, `jvm.config`, `cargo-config` (`.cargo/config.toml`), `.npmrc`, `.yarnrc.yml`, `bunfig.toml`, `pnpm-workspace.yaml`, `nuget.config`, `package-lock.json` or `composer.lock` (the keys of one lockfile entry; the key is the entry key name, for example `ideallyInert`; `transport-options` can never be allowed).
- `key` is the dotted path of the setting, with no wildcards. For flat files the key is the whole setting name, never split on dots: `org.gradle.configuration-cache` (`gradle.properties`), a JVM or Maven option such as `-XX:+UseZGC` (`jvm.config`, `maven.config`), `message` (`.npmrc`). For `nuget.config` it is `config:<key>` (lower-case) for a `<config>` setting, such as `config:defaultpushsource`. Each leaf setting is allowed on its own, so allowing one key in a table does not allow its siblings.
- Every applied entry is reported as a `config/key-allowed` warning (in the output and in `--json`) so the exception stays visible.
- Settings known to redirect a registry, move a cache, change TLS trust, or download and run code (for example uv `index-url`, `cache-dir`, `python-install-mirror`; Poetry `cache-dir`, `repositories.*`; Composer `cache-dir`, `cafile`) cannot be allowed this way, and neither can a value that fails its rule (for example Composer `disable-tls: true`).
- Like the rest of the policy, this is read only from the out-of-repo config; the local overlay cannot set it.

## Bootstrap Modes

```bash
sloppy-joe init --register
```

This creates a neutral starter config outside the repo and registers it for the current git root.

For new projects, use an ecosystem-specific greenfield starter:

```bash
sloppy-joe init --greenfield --ecosystem npm
sloppy-joe init --greenfield --ecosystem cargo --register
```

Greenfield presets are currently implemented for `npm`, `pypi`, and `cargo`. Other ecosystems fail with a clear “not supported yet” error instead of emitting an empty starter.

For existing repos, seed config from the current codebase:

```bash
sloppy-joe init --from-current
sloppy-joe init --from-current --register
```

`--from-current` currently supports only repos whose first-party code is `npm` and/or `cargo`. Other ecosystems fail with a clear “not implemented yet” error.

By default, `--from-current` prints review-only bootstrap output. Add `--register` to write the generated config outside the repo and register it for the current git root.

It populates:

- `bootstrap_review.suggested_internal` for discovered first-party local packages
- `bootstrap_review.suggested_trusted_local_paths` for discovered out-of-repo Cargo path dependencies
- `bootstrap_review.candidate_canonical_groups` suggestions for families that need human review before becoming enforced canonicals

Those `bootstrap_review` suggestions are informational. They do not change enforcement until you move them into `canonical`.

If you need to manage the file yourself, write it to a secure location outside the project directory:

```bash
sloppy-joe init > /secure/location/sloppy-joe.json
```

Do not write the config into the repo itself. sloppy-joe intentionally refuses in-repo config files.

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
  run: sloppy-joe check --ci --config security-configs/sloppy-joe.json

# Option 2: Config from a URL
- name: Check dependencies
  run: sloppy-joe check --ci --config https://raw.githubusercontent.com/yourorg/security-configs/main/sloppy-joe.json

# Option 3: Config from CI secret (write to temp file)
- name: Write config
  run: echo '${{ secrets.SLOPPY_JOE_CONFIG }}' > /tmp/sj-config.json

- name: Check dependencies
  run: sloppy-joe check --ci --config /tmp/sj-config.json

# Option 4: Environment variable
- name: Check dependencies
  env:
    SLOPPY_JOE_CONFIG: /path/to/config.json
  run: sloppy-joe check --ci
```

### GitLab CI

```yaml
dependency-check:
  image: rust:latest
  before_script:
    - cargo install sloppy-joe
  script:
    - sloppy-joe check --ci --config $SLOPPY_JOE_CONFIG
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
