# Threat model

What sloppy-joe protects, whom it distrusts, and which control answers which attack. Every row of
the mitigation tables names the code or spec that implements it; `cargo test --test threat_model`
fails when a path named here no longer exists, so this page cannot drift silently.

## What is protected

- **The build**: the set of packages a developer or CI job installs from a repository. The scanner
  decides whether that set is the one the lockfile and the registries vouch for.
- **The developer's machine and CI secrets**: install scripts, build plugins and package-manager
  hooks run with the installer's privileges.
- **The verdict**: a pass must mean "every input that changes what is installed was read and
  modeled". A scanner that passes by not understanding a file is worse than none.

## Trust boundaries

| Input | Trust | Why |
| --- | --- | --- |
| Files in the scanned repository (manifests, lockfiles, package-manager config, scripts) | **Untrusted** | A pull request or a compromised dependency can edit any of them. |
| Files in ancestor directories of the project (up to the repository root) | **Untrusted** | Package managers read parent config; a contributor can add it. |
| Registry and OSV responses | **Untrusted data, fail-closed** | A lookup error blocks; a response is parsed, never executed. |
| The scanner's own config (`--config`, outside the repository) | **Trusted** | The operator owns it. The repository's local overlay may only tighten. |
| Environment, `~/.npmrc`, `~/.gradle`, global package-manager config | **Out of scope** | The scanner cannot see another machine's files (see Non-goals). |

## Attacker capabilities

1. Edit any file in the repository, including lockfile entries, comments, line endings and encoding.
2. Add files a package manager reads but that look unrelated (`.python-version`, `.mvn/jvm.config`).
3. Publish packages with names close to popular ones, or take over an abandoned name.
4. Exploit a difference between how the scanner and the package manager read the same bytes.
5. Cannot: change the operator's scanner config, or alter what the registry truthfully returns.

## Mitigations

### Reading files the way the package manager does

| Attack | Control | Where |
| --- | --- | --- |
| A BOM, NUL, odd line terminator or duplicate key makes the tool and the scanner read different content | One gateway refuses what it cannot model | `src/untrusted.rs`, `tests/architecture/raw_reads.rs` |
| A new parser reads a file around the gateway | Architecture test forbids raw reads; the baseline only shrinks | `tests/architecture_baseline.txt`, `docs/specs/untrusted-input-hardening.md` |

### Settings that redirect, cache or execute

| Attack | Control | Where |
| --- | --- | --- |
| An unclassified config key fetches from another host or runs code | Allowlist per config file; unknown keys block unless the operator allows them | `src/config_surface.rs`, `docs/specs/untrusted-input-hardening.md` |
| A file the tool reads that the scanner never modeled | Declared table of inputs per ecosystem, checked for conformance | `src/ecosystems/ambient.rs`, `tests/architecture/ambient_surface.rs` |
| A tracked file that only matters when committed (`.venv`, `.pnp.cjs`) | Git index decides tracked or not; an undecidable index warns, errors in `--ci` | `src/gitindex.rs` |

### Lockfiles

| Attack | Control | Where |
| --- | --- | --- |
| A lock entry carries a field the tool honours but the scanner ignores (`mirrors`, extra tuple element) | Closed key schema per lock format; escape hatch is an operator `config_key_allow` | `docs/specs/verification-and-schemas.md`, `src/ecosystems/js/npm_lock_schema.rs`, `src/ecosystems/php/lock_schema.rs`, `src/ecosystems/cargo/lock_schema.rs`, `src/ecosystems/python/lock_schema.rs` |
| A lock points a package at an attacker's archive | Provenance checks on every entry's source | `src/lockfiles/composer.rs`, `src/lockfiles/pnpm.rs`, `src/lockfiles/yarn/validate.rs` |
| A skipped line hides a pinned dependency | Unrecognized lines block instead of being skipped | `src/lockfiles/gradle.rs` |
| A Python dependency gated by a marker that is false on the scanning host (`sys_platform == "win32"`) | Markers only pick the target's versions; source policy and package checks walk every environment, and an undecidable marker counts as true | `src/lockfiles/mod.rs`, `src/ecosystems/python/parse.rs`, `src/parsers/python_scope/marker.rs` |

### Packages and registries

| Attack | Control | Where |
| --- | --- | --- |
| Typosquat or hallucinated package name | Existence, similarity and metadata checks | `docs/specs/registry-similarity.md` |
| Startup hook in a PyPI wheel (`*.pth`, `sitecustomize`) | Recent or flagged versions' wheels are read in memory and hash-checked | `src/checks/wheel_verification.rs`, `docs/specs/python-supply-chain-signals.md` |
| A Python lockfile hash PyPI never served | Recorded sha256 must be published by PyPI | `src/checks/python_lockfile_hashes.rs`, `src/lockfiles/python_hashes.rs` |
| Release after long silence or in a burst | Cadence signals on recent versions | `src/checks/release_cadence.rs` |
| A guessed import or command name used as a package | Known-mismatch table, stricter when young | `src/checks/steering.rs` |
| A known-malicious package | OSV check | `docs/specs/vulnerability-coverage.md` |
| A malicious or hallucinated transitive dependency of a Python manifest with no lockfile (`requirements.txt`, `setup.py`) | The closure is projected from PyPI `Requires-Dist` (markers for every environment) and scanned as transitive, labeled projected; a failed lookup or an exceeded depth, package or fetch bound blocks; another index's or an `internal` package's dependencies are never asked of PyPI and warn | `src/ecosystems/python/projection.rs`, `docs/specs/transitive-scanning.md` |
| A registry or cache fails and the scan passes | Errors block; caches go through one module | `src/cache.rs`, `docs/specs/lockfile-handling.md` |
| A cache file is edited or planted to clear packages | Owner, permission and HMAC checks; untrusted entries are refetched | `src/cache/integrity.rs` |
| A public package carries an `internal` prefix | Prefix matches must be absent from the public registry, else block | `src/engine/internal_source.rs` |

### The lockfile fixer (`sloppy-joe fix-lockfile`)

The fixer is the one place sloppy-joe runs another program, and the lockfile it touches is the
security artifact. It trusts the package manager binary on the absolute, non-repository part of
`PATH` and nothing the repository supplies; the scratch copy limits what the tool can see, not
what it can do as the user, so the precondition list and the disabled-execution flags are the
defense (an OS sandbox is future work). Spec: `docs/specs/fix-lockfile.md`.

| Attack | Control | Where |
| --- | --- | --- |
| Regenerating the lockfile hides an integrity, source or provenance finding | Those findings are `human`: no tool runs; a candidate that changes any locked version, integrity or source of a reachable package is refused | `src/ecosystems/common/fixer.rs`, `src/engine/fix/verify.rs` |
| The regenerated lockfile pulls in something malicious or blocked | The candidate is rescanned with `check --full` semantics (fresh cache, no cached result trusted) and is written only if nothing blocks | `src/engine/fix/verify.rs`, `src/engine/fix/execute.rs` |
| The repository makes the tool run its code (pnpmfile, Yarn plugins or `yarnPath`, `.npmrc` script settings, Cargo wrappers, Composer VCS repositories, Poetry plugins, a Go `toolchain` line, git/exec/path dependencies) | The scanner's own policy and a per-tool precondition list refuse before the tool runs; scripts are disabled by flag and by environment | `src/ecosystems/js/lock_fixer.rs`, `src/ecosystems/cargo/lock_fixer.rs`, `src/ecosystems/go/lock_fixer.rs`, `src/ecosystems/php/lock_fixer.rs`, `src/ecosystems/python/lock_fixer.rs` |
| Resolution builds a source distribution, which runs it | uv runs with `--no-build`; Poetry, which has no such switch, only runs when every package is already locked with a wheel | `src/ecosystems/python/lock_fixer.rs` |
| A repository binary shadows the tool (`node_modules/.bin`, `.`) or tokens leak into it | Only absolute `PATH` entries outside the project and scratch directory are searched; the environment is built from nothing, with `HOME`, caches and config pointed into a fresh 0700 scratch directory; argv only, no shell, no stdin, a timeout and an output cap | `src/engine/fix/runner.rs`, `src/engine/fix/scratch.rs` |
| The tool rewrites a manifest, or the working tree changes while it runs | Inputs other than the lockfile must be byte-identical after the run; files are compared again before writing | `src/engine/fix/execute.rs`, `src/engine/fix/apply.rs` |
| A partial or symlinked write corrupts the tree | Atomic replace through a fresh temporary file, symlinks refused, the previous file kept as `<name>.sloppy-joe.bak` | `src/engine/fix/write.rs` |
| A manifest pin disagrees with the lockfile and the fixer picks a side | A pin the lockfile locks at another version stops the fix as a decision | `src/ecosystems/common/fixer.rs` |

### The scanner itself

| Attack | Control | Where |
| --- | --- | --- |
| Engine code special-cases an ecosystem and misses another | Layer, size and complexity rules | `docs/specs/architecture-guardrails.md`, `tests/architecture/main.rs` |

## Non-goals

- Environment variables, user-level package-manager config and files outside the repository.
- A compromised package-manager binary on the trusted `PATH`, and isolating `fix-lockfile`'s tool
  run from the rest of the user's account (no OS sandbox).
- Code inside an installed package: install-script risk is reported, not analyzed.
- A malicious operator config, or a compromised registry that lies consistently.
- Proving a lockfile is what a clean `install` would produce: the scanner checks that nothing in
  it contradicts the manifests and registries, not that it is minimal.
- Predicting pip's resolution without a lockfile: projected Python transitive versions model pip's
  choice from PyPI metadata (no constraint files, pip config or backtracking) and may differ from
  what an install picks. Only a lockfile gives exact transitive coverage.

## Reading a finding

Each finding names the file, the key or entry, why that input is risky and how to fix or allow
it. A finding that cannot say why it blocks is a defect in the scanner, not in the repository.
