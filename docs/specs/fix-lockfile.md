# Fix Lockfile

**Created**: 2026-10-25
**Status**: Implemented (2026-10-25)

## Context

### Problem / Why Now

`check` blocks on lockfiles it cannot model or trust: a pnpm lockfile that is not format
`9.0`, an npm `lockfileVersion: 1`, a missing or stale lockfile, a shadow lockfile under a
workspace member. Every block is correct, and every block leaves the user to find the right
command alone. Users who cannot fix it quickly turn the check off. A fixer that handles the
mechanical cases lets the scanner stay strict.

The danger is that a lockfile is the security artifact. Regenerating it re-resolves versions,
can run package-manager configuration and plugins from the repository, and can erase the very
mismatch the scanner flagged. The fixer must never launder a finding.

### Expected Outcomes

- `sloppy-joe fix-lockfile` explains every lockfile problem `check` would block on and, where a
  safe automatic fix exists, produces a candidate lockfile and a version diff.
- Nothing is written without `--write`, and a candidate that fails `check --full` is never written.
- Every ecosystem gets a result: an automatic fix, or the exact manual command and why
  automation is refused.
- Integrity, source and provenance findings are never auto-fixed.

### Alternatives Considered

- **Run the package manager inside `check`**: makes the read-only, CI-safe command execute
  repository-controlled configuration. Rejected.
- **Rewrite lockfiles ourselves**: a second implementation of every lock format, with the
  hashes and resolution rules we cannot reproduce. Rejected; delegate to the real tool.
- **Message only** (no command): done first as the cheap step (see Acceptance Criteria).

## Acceptance Criteria

### Command

- `sloppy-joe fix-lockfile [--dir D] [--type T] [--config C] [--write] [--json]` takes the same
  `--dir`, `--type`, `--config` and `--json` as `check`. Without `--write` it only reports the
  plan, runs the tool in a scratch copy and prints the version diff.
- Exit status: success when nothing needed fixing or the fix was verified (and written with
  `--write`); non-zero when problems remain, a fix was refused, or a tool failed. Refusal is
  never success. Implemented as `0` (success), `1` (a problem remains, a fix was refused or a
  tool failed) and `2` (runtime error: no config, unreadable directory, discovery refused).

### Plan

- The plan runs the same preflight and lockfile validation as `check` and lists each problem
  by its `check` name or error, the project, and one of: `fixable` (command shown),
  `guided` (manual command shown, automation refused with the reason), `human` (no safe fix).

### Fixability catalog (every known malformed or stale lockfile case)

| Problem (as `check` reports it) | Class | Action |
|---|---|---|
| pnpm `lockfileVersion` not `'9.0'`, unquoted, or missing | fixable | `pnpm install --lockfile-only --ignore-scripts --ignore-pnpmfile --no-frozen-lockfile` (pnpm 9.0); the old lockfile is read by a legacy reader for the comparison; a 5.x lockfile is refused (pnpm 9 cannot read it) |
| npm `lockfileVersion: 1` (legacy v5/v6) | fixable | `npm install --package-lock-only --ignore-scripts --lockfile-version 3` (npm 8.1.2: the flag landed in 8.1.0, its string value in 8.1.2); npm output "Could not fetch metadata" fails the fix |
| JS lockfile missing, or direct dependency missing from it | fixable | the manager's lockfile-only install with scripts disabled: `npm install --package-lock-only --ignore-scripts` (npm 7.0), the pnpm command above, `bun install --lockfile-only --ignore-scripts` (bun 1.1.43), Yarn Berry `yarn install --mode=update-lockfile` (Yarn 3.0) |
| `bun.lockb` binary lockfile | fixable | `bun install --save-text-lockfile --frozen-lockfile --lockfile-only --ignore-scripts` (bun 1.1.43, Bun's documented lossless migration); the old lockfile is read through `bun bun.lockb` (printed as a Yarn v1 lockfile) for the comparison, and `bun.lockb` is moved to `bun.lockb.sloppy-joe.bak` |
| Yarn `lockfile/orphan-entries` | fixable | Berry `yarn install --mode=update-lockfile`; prunes unreachable entries (a Yarn Classic lockfile is guided) |
| Yarn Classic (v1) lockfile | guided | `yarn install --ignore-scripts` (Yarn 1.22): no lockfile-only mode, and migration changes the package manager; user decides |
| Shadow lockfile under a workspace member | fixable | moved to `<name>.sloppy-joe.bak` (shown in the plan, never silent); no tool runs |
| `Cargo.lock` missing or stale | fixable | `cargo generate-lockfile` only when absent; otherwise `cargo update --workspace` (cargo 1.50; keeps every locked non-workspace version), registry access is required. `check` has no "lockfile version too old" finding, so that case never reaches the plan |
| `composer.lock` missing, or a direct dependency missing from it | fixable | `composer update --lock --no-install --no-scripts --no-plugins` (Composer 2.0; `--lock` pins every locked package); without a lockfile the same command without `--lock`. `check` does not compare `content-hash`, so that case never reaches the plan |
| `poetry.lock` missing or stale | fixable / guided | `poetry lock --no-plugins` (Poetry 2.0, which keeps locked versions). Poetry builds a source distribution when no wheel gives it the metadata and has no flag to forbid it, so it runs only when a `poetry.lock` exists, every direct dependency is already locked and every locked package has a wheel; otherwise guided |
| `uv.lock` missing or stale | fixable | `uv lock --no-build` (uv 0.3; no source distribution is built), refused when a locked package has no wheel, when the project metadata is dynamic, for uv workspaces and for git, path or URL sources |
| `Pipfile.lock` stale | guided | `pipenv lock` re-resolves everything; not version-preserving |
| `go.sum` missing entries | fixable | `go mod download all` (Go 1.21) with `GOTOOLCHAIN=local`, the public proxy only, no VCS tools, checksum database left on. A bare `go mod download` no longer records module content hashes since Go 1.17 |
| `requirements.txt` hash-locked drift | guided | `pip-compile --generate-hashes` runs resolution that may build sdists |
| `Gemfile.lock` | guided | Bundler evaluates `Gemfile` as Ruby, which executes repository code |
| Gradle `dependencyLocking` / `gradle.lockfile`, `verification-metadata.xml` | guided | `gradle dependencies --write-locks` executes build scripts |
| `packages.lock.json` (.NET) | guided | `dotnet restore --use-lock-file` evaluates MSBuild targets from the repository |
| Manifest pin differs from the lockfile (`resolution/lockfile-out-of-sync`, or a pin the lockfile locks at another version) | human | which side is right is a decision, not a format fix |
| `lockfile-integrity-mismatch`, `source-mismatch`, `untrusted-registry-source`, `untrusted-git-source`, `blocked-provenance-rewrite`, `private-registry-unvetted`, tarball and wheel integrity mismatches | human | regenerating would hide a possible attack |
| npm `overrides`, `resolutions`, `patchedDependencies` (in any workspace manifest) | human | rewrite configuration the scanner cannot verify |
| Any other blocking error | human | an error carries its fix as a typed remedy (`src/remedy.rs`); one without a remedy has no automatic fix |

Flags and minimum versions were confirmed against each vendor's documentation, release notes or
source, and every fixable row except Yarn Berry (not installed) and `bun.lockb` (Bun 1.4 no longer
writes one) was run against the installed tool with the real `check --full` rescan.

### Preconditions (refuse, do not degrade)

- The fixer refuses a project that contains a code-execution surface for its tool: pnpm
  `.pnpmfile.cjs`, Yarn `yarnPath` or plugins, `.npmrc`/Cargo/Composer/Poetry settings naming
  scripts, plugins, wrappers or build hooks, Poetry `requires-plugins`, a Cargo `build`-time
  `[source]` replacement outside the accepted registries, or a Go `toolchain` directive.
  Implemented as: pnpmfiles, `.yarnrc`, `.yarnrc.yml` `yarnPath`/`plugins` and committed
  `.yarn/plugins`, `.npmrc` script, shell, node-option, pnpmfile and self-update settings,
  `pnpm-workspace.yaml` config dependencies and rewrites, `bunfig.toml` preloads, a
  `packageManager` download URL, git, URL, local-path and `exec:`/`patch:` dependencies; Cargo
  configuration outside `registries.*.{index,protocol}`, `registry.default`, `net.retry`, `term`
  and `cargo-new` (so wrappers, build settings, aliases, credential providers, source
  replacement and git-over-CLI all refuse); Composer VCS, path, artifact and inline-package
  repositories; `uv.toml`, `poetry.toml`, dynamic metadata, uv workspaces and non-index uv
  sources; Poetry plugins; a Go `toolchain` line or local `replace`.
- The manifest and the tool's configuration files must pass the scanner's own policy (the
  same checks as `check`) before the tool runs.
- A required tool that is missing, too old, or whose version cannot be read is a refusal that
  names the tool and the minimum version.

### Verification (a candidate must pass all of these before `--write`)

- **Version preservation**: every `(name, version, integrity)` in the old lockfile that is still
  reachable appears unchanged in the candidate. Any changed version, changed integrity or
  changed source refuses the fix and lists the entries. Entries may be added only for direct
  dependencies the old lockfile lacked, and removed only when unreachable.
- **No laundering**: the candidate is rescanned with `check --full` semantics, including OSV,
  tarball and wheel verification; anything blocking means it is not written.
- **Format**: the candidate parses with the scanner's own parser and satisfies the same format
  gate (for pnpm, `lockfileVersion: '9.0'`).
- **Diff**: the version diff (added, removed, unchanged counts, and each added or removed
  package) is printed before any write; `--write` replaces files atomically and keeps the
  previous lockfile as `<name>.sloppy-joe.bak`.
- **All-or-nothing write**: before anything in the project changes, every file to replace or
  remove must be a regular file (or, for a new output, absent) and none of its backup paths may
  exist in any form. An existing `<name>.sloppy-joe.bak` (file, directory or symlink) is never
  overwritten and no other name is picked: the write fails, names that path, and asks for it to
  be moved or removed. Backups and fully written temporary files are then created with
  exclusive create; only after all of them exist are deletions removed (`bun.lockb` before
  `bun.lock` appears) and outputs renamed into place. A failure at any step undoes the steps
  before it, so the working tree is left as it was.
- The temporary directory is resolved (symlinks followed) before it is compared with the
  project directory; one that resolves inside the project, or cannot be resolved, is refused.

### Message step (ships first)

- Each blocking lockfile-format error names the exact manual command and the minimum tool
  version, and says to run `sloppy-joe fix-lockfile` once that command exists.

## Constraints

- No shell. Tools run as an argument vector, with a scrubbed environment (no inherited tokens,
  `HOME`, cache and config directories pointed at a private temp dir), a timeout, an output
  cap and no stdin.
- The tool runs in a scratch copy holding only the manifests, workspace manifests, tool
  configuration files that passed policy, and the old lockfile. Nothing runs in the user's
  working tree and the tool cannot write outside the scratch directory.
- Scripts, plugins, hooks and lifecycle execution are disabled by flag and by environment for
  every tool; a tool with no way to guarantee that is `guided`, not `fixable`.
- Registry access follows the scanner's registry policy; a tool configured with an unvetted
  registry or proxy is refused.
- Caches go through `cache.rs`; the scratch directory is `0700`, created fresh and removed
  on every exit path.
- Every failure is a visible refusal. A missing tool, timeout, or unreadable diff never falls
  back to writing anything.
- Tool names, flags and minimum versions in the catalog are to be confirmed against each
  tool's own documentation during implementation; a flag that does not do what this spec
  assumes moves that row to `guided`.

## Scope Boundaries

- Not covered: choosing or bumping versions, resolving manifest/lockfile disagreements,
  migrating package managers (Yarn Classic to Berry, npm to pnpm), regenerating manifests,
  Maven (no lockfile), Gradle and Bundler execution, an OS-level sandbox for the tool.
- No new config keys and no network service. New CLI surface is the subcommand above only.
- The scratch copy limits what the tool can see, not what it can do as the user; the
  precondition list and disabled-execution flags are the defense, and an OS sandbox is future
  work.

## I/O Contracts

- Input: project directory, optional config, the scanner's parsed project inputs and lockfile
  validation results.
- Output: a plan (problems, class, command, refusal reasons), a version diff, and with
  `--write` the replaced lockfiles plus `.sloppy-joe.bak` copies. `--json` emits the plan,
  diff and result per project.

## Context Anchors

- `src/ecosystems/js/lockfile_validate.rs`, `src/ecosystems/js/pnpm_lock_schema.rs`,
  `src/lockfiles/nesting.rs` (pnpm format gate), `src/ecosystems/js/managers.rs`
- `src/ecosystems/*/lock_schema.rs`, `src/lockfiles/*.rs`, `src/engine/` (scan pipeline)
- `docs/specs/lockfile-handling.md`, `docs/specs/untrusted-input-hardening.md`
- Implementation: `src/remedy.rs` (typed remedies on the blocking errors),
  `src/ecosystems/common/fixer.rs` (shared classification), `src/ecosystems/*/lock_fixer.rs`
  (per-ecosystem recipes and preconditions), `src/lockfiles/entries.rs` (locked packages from the
  parsed lockfile), `src/engine/fix/` (flow, runner, scratch, verification, write, output)

## Architecture

- Engine: `src/engine/fix.rs` holds the generic flow (preflight, scratch copy, tool run,
  diff, rescan, write) and the process runner. It names no ecosystem.
- Plugins: each ecosystem plugin under `src/ecosystems/<eco>/` exposes a `lockfile_fixer`
  that classifies problems (the catalog above), lists the files to copy, builds the argument
  vector and environment, and states its preconditions. Placement follows the architecture
  guardrails; no plugin reaches another.
- The diff and version-preservation logic reads the parsed lockfile representation the scan
  already builds (`LockfileData`), so the fixer and the scanner cannot disagree about what a
  lockfile says.
