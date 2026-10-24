# Untrusted Input Hardening Specification

**Created**: 2026-10-24
**Status**: Accepted (decisions recorded at the end)
**Input**: "any feedback on architectural improvements to prevent these issues?" — items 1–3 of the
answer: allowlist config tables, a declared table of the files each package manager reads, and one
function through which every security-relevant file is read.

## Context

### Problem / Why Now

Fourteen red-team rounds found about 100 bypasses. Almost all fall into three classes:

1. **Denylists of dangerous keys.** uv (`UV_UNVERIFIABLE_KEYS`), Composer `config`, Gradle
   properties, Maven `-D` options, Cargo `[env]` and `.npmrc` each list the keys known to be
   dangerous. Every round found another key (`python-install-mirror`, `cache-dir`, `mirrors`,
   `systemProp.javax.net.ssl.*`, `-Duser.home`). `poetry.toml` was written as an allowlist
   (unknown key blocks) and has had no follow-up finding.
2. **Files the package manager reads that nobody modeled.** `.python-version`, a committed `.venv`,
   `.env` beside a Pipfile, `dotnet-tools.json`, `gradle-daemon-jvm.properties`, `.mvn/jvm.config`,
   `.mvn/maven-build-cache-config.xml`, a parent `pyproject.toml`. Each was found by a red team
   running the real tool, not by the scanner knowing the tool's inputs.
3. **Parser differentials.** A lone `\r`, U+2028, a BOM or a duplicate key reads one way for the
   package manager and another way for the scanner (`go.mod`, `gradle.lockfile`, `yarn.lock`,
   `setup.py`, `tox.ini`, the Groovy lexer, `tox.toml`). `fsutil::read_line_oriented_limited` fixes
   this, but only where a developer remembered to call it. Today the tree has 66 calls to
   `read_file_limited`, 10 non-test `read_to_string` calls and 29 non-test `.lines()` calls.

The tool's own rule is "silent degradation is a bug". These three classes are all silent: the
scanner passes because it does not know what it does not know.

### Expected Outcomes

- A key or file the scanner has not classified blocks. A new package-manager setting is a reported
  false positive, never a silent pass.
- Every file whose bytes affect what gets installed is read through one gateway that refuses
  inputs the scanner cannot model, so a new parser cannot reintroduce the line-break class.
- For each ecosystem the set of repo-controlled inputs is written down as data and covered by a
  conformance test, so "which files does this tool read?" has an answer in the tree.
- The architecture tests fail when new code reads a security-relevant file around the gateway.

### Alternatives Considered

- **Keep red-teaming and append to denylists**: found real bugs every round and has not converged.
- **Fuzz/differential testing against the real tools** (item 5 of the earlier proposal): valuable,
  complementary, and a separate spec. It finds what this spec's tables miss.
- **Workspace-crate split to enforce layers** (item 6): separate spec; unrelated to input handling.
- **Per-ecosystem hand-written checks stay as they are, add only the table**: leaves the gateway
  bypassable and the key lists open-ended.

---

## Acceptance Criteria

### A. Allowlist config surfaces

- **Given** a config file a package manager reads from the repo (see the surface list below),
  **when** it contains a key not in that file's allowlist table, **then** the project is blocked
  with a message naming the file, the key path and the table.
- **Given** a key on the allowlist with a value predicate (for example `virtualenvs.in-project`
  must be a boolean), **when** the value fails the predicate, **then** the project is blocked.
- **Given** a config file with a duplicate key, **when** it is read, **then** the project is
  blocked (see C), so the table sees the same value the tool does.
- **Given** the existing denylist-based checks for uv, Composer `config`, Gradle properties, Maven
  options, `.npmrc`, `.yarnrc.yml`, `bunfig.toml`, Cargo config, `pip.conf`, `nuget.config` and
  `pnpm-workspace.yaml`, **when** the migration is complete, **then** each is a table and the
  denylist constant is removed. Every key that blocked before still blocks.
- **Given** a table, **when** a test enumerates its entries, **then** every entry has a fixture
  test (an allowed key passes, a near-miss spelling blocks).

### B. Declared ambient inputs

- **Given** an ecosystem plugin, **when** the conformance suite runs, **then** the plugin returns a
  non-empty `ambient_inputs()` table, and every entry names: a file-name pattern, a search scope
  (`ProjectDir`, `AncestorsToRepoRoot`), and a disposition (`Modeled(checker)`, `Blocked(reason)`
  or `Irrelevant(reason)`).
- **Given** a project and an entry marked `Blocked`, **when** a matching file exists in scope,
  **then** the project is blocked. An entry marked `Modeled` runs its checker, whose error blocks.
- **Given** the table, **when** the conformance suite places a file for each entry in a fixture,
  **then** the observed verdict equals the declared disposition (`Irrelevant` entries must pass
  and must have a non-empty reason).
- **Given** a case-variant, symlinked or ancestor-directory copy of a table file, **when** scanned,
  **then** the verdict is the same as for the exact name in the project directory.
- **Given** the initial population, **then** it includes at least every file the round 1–14
  findings touched (listed in Context Anchors), so each past finding has a table row.

### C. Untrusted-read gateway

- **Given** a security-relevant file, **when** it is read through the gateway, **then** the caller
  declares its format (`Line`, `Toml`, `Json`, `Yaml`, `Xml`, `Properties`, `Script`) and a size
  limit, and receives parsed content or an error.
- **Given** a file containing a BOM, a NUL byte, invalid UTF-8, or (for `Line`, `Properties`,
  `Script`, `Xml`) a line terminator other than `\n`/`\r\n` (lone `\r`, U+2028/9, U+0085, `\v`,
  `\f`), **then** the read fails closed with a message naming the file and offset.
- **Given** a JSON or YAML file with duplicate keys, or a YAML file with anchors, aliases or merge
  keys, **then** the read fails closed. TOML duplicate keys already fail in the parser.
- **Given** a symlink, a non-regular file, or a file over the limit, **then** the read fails
  closed (existing `read_bytes_limited` behavior is preserved).
- **Given** non-test code in `src/parsers/`, `src/lockfiles/`, `src/ecosystems/`, **when**
  `cargo test --test architecture` runs, **then** it contains no `std::fs::read_to_string`,
  `std::fs::read`, `File::open`, `read_file_limited` or `read_bytes_limited` call outside the
  gateway module, except sites listed in the baseline. The baseline may only shrink; new sites are
  never baselined.
- **Given** the same files, **then** `.lines()` and `.split('\n')` over file content appear only
  inside the gateway or on values the gateway returned as `Line` content.
- **Given** the migration is complete, **then** the baseline lists no `read_file_limited`,
  `read_to_string` or `.lines()` sites and the gateway is the only reader.

### Cross-cutting

- **Given** any of the above, **then** blocking behavior that existed before this change still
  blocks and CHANGELOG "Unreleased" states which messages changed.
- **Given** `--ci` and `--full`, **then** table verdicts do not depend on the mode.

---

## Constraints

- Fail closed: an unreadable, unparseable or unclassified input blocks; no warning-only path is
  introduced for a case that blocks today.
- Gateway and table helpers live in foundation modules (below `parsers`/`lockfiles`/`ecosystems` in
  the layer table). Ecosystem-specific tables live in their plugin, never in `src/engine/` or
  `src/lib.rs`. Plugins do not import each other; shared helpers go to a foundation module.
- 800 lines per file and complexity 15 per function hold. No new baseline entry, ever.
- No new runtime dependency unless a YAML parser with duplicate-key and alias detection is
  required (see Open Questions).
- TDD: for each migrated surface, write the failing "unknown key blocks" test first.

## Scope Boundaries

In scope: the three mechanisms, migrating every existing denylist and every `read_file_limited` /
`read_to_string` / `.lines()` site over repo-controlled files, the architecture rules for C, the
conformance rows for B.

Out of scope: differential testing against real tools, splitting layers into workspace crates,
replacing the complexity/line counters with `syn`, environment variables and files outside the repo
(`~/.npmrc`, `~/.gradle`; the scanner cannot see them), config of the scanner itself
(`src/config`), network responses (registry clients).

## I/O Contracts

### Gateway (`src/untrusted.rs`, foundation layer)

```
pub(crate) enum Format { Line, Properties, Script, Toml, Json, Yaml, Xml, Text }
pub(crate) fn read(path: &Path, format: Format, max_bytes: u64) -> Result<Untrusted>
pub(crate) enum Untrusted { Text(String), Toml(toml::Value), Json(serde_json::Value), Yaml(Value) }
```

Errors are `anyhow` with the path, the format and the first offending offset.

### Config surface table (`src/config_surface.rs`, foundation layer)

```
pub(crate) struct Surface { file: &'static str, format: Format, keys: &'static [KeyRule] }
pub(crate) struct KeyRule { path: &'static str /* dotted, `*` matches one segment */,
                            value: ValueRule /* Any | Bool | OneOf(&[..]) | Predicate(fn) */ }
pub(crate) fn check(surface: &Surface, parsed: &Untrusted, source: &Path) -> Result<()>
```

`check` returns the first violation; unknown paths are violations.

### Ambient inputs (`EcosystemSupport::ambient_inputs`)

```
pub(crate) struct AmbientInput { pattern: &'static str, scope: Scope,
                                 disposition: Disposition }
pub(crate) enum Scope { ProjectDir, AncestorsToRepoRoot }
pub(crate) enum Disposition { Modeled(fn(&Path) -> Result<()>), Blocked(&'static str),
                              BlockedIfTracked(&'static str),
                              Irrelevant(&'static str) }
fn ambient_inputs(&self) -> &'static [AmbientInput];   // no default implementation
```

The preflight walk is generic (one function in the engine); it does not name ecosystems.

## Context Anchors

- Files the findings touched (initial table rows): `.npmrc`, `.yarnrc.yml`, `bunfig.toml`,
  `pnpm-workspace.yaml`, `.pnpmfile.cjs`, `.cargo/config(.toml)`, `rust-toolchain(.toml)`,
  `uv.toml`, `pyproject.toml [tool.uv|tool.poetry|tool.tox|tool.pdm|tool.hatch]`, parent
  `pyproject.toml`, `poetry.toml`, `pip.conf`, `.python-version`, `.venv`, `.env` (Pipfile),
  `tox.ini`/`tox.toml`, `setup.py`, `setup.cfg`, `composer.json config/extra/scripts`,
  `composer.lock dist/source`, `auth.json`, `vendor/composer/installed.json`, `gradle.properties`,
  `gradle/gradle-wrapper.properties`, `gradle/gradle-daemon-jvm.properties`, `settings.gradle(.kts)`,
  `buildSrc`, `gradle.lockfile`, `verification-metadata.xml`, `.mvn/{maven.config,jvm.config,
  extensions.xml,settings.xml,toolchains.xml,wrapper,maven-build-cache-config.xml}`, `nuget.config`,
  `Directory.Build.*`, `Directory.Packages.props`, `global.json`, `.config/dotnet-tools.json`,
  `*.csproj` targets, `obj/*.props`, `Gemfile`, `Gemfile.lock`, `.bundle/config`, `*.gemspec`,
  `go.mod`, `go.sum`, `go.work`, `vendor/modules.txt`.
- `src/fsutil.rs` (`read_line_oriented_limited`, `reject_unmodeled_line_breaks`,
  `parse_java_properties`) — seed of the gateway.
- `src/ecosystems/python/interpreter_config.rs` — the `poetry.toml` allowlist is the model for A.
- `src/ecosystems/tests/` conformance suite — home of B's checks.
- `docs/specs/architecture-guardrails.md`, `tests/architecture/` — rules for C are added there.
- `CHANGELOG.md` "Unreleased" rounds 1–13 — the findings each table row must cover.

## Architecture

Three foundation modules, no engine knowledge of any ecosystem:

1. `src/untrusted.rs` wraps `fsutil` byte reading with format-specific rejection and structured
   parsing. `fsutil::read_line_oriented_limited` and `reject_unmodeled_line_breaks` become its
   internals; the old public helpers are removed once the baseline reaches zero.
2. `src/config_surface.rs` holds `Surface`/`KeyRule`/`check`. Each plugin declares its surfaces as
   `const` data next to the code that already reads the file.
3. `EcosystemSupport::ambient_inputs` is a required trait method. The engine's preflight walks
   each spec's scope (reusing the repo-root discovery in `cache::find_git_root`), matches patterns
   case-insensitively, and dispatches on the disposition. `Modeled` checkers are the existing
   per-file functions, which now take `Untrusted` from the gateway.

Architecture test additions: raw-read ban (C), `.lines()` ban outside the gateway, and a check
that every plugin returns a non-empty `ambient_inputs`.

### Rollout (each step lands green and is committed alone)

1. Gateway + architecture rule + baseline of the current raw-read sites. Migrate `Line`-class
   files first (go.mod, lockfiles, requirements, setup.py, tox.ini), then the rest.
2. `config_surface` helper; convert `poetry.toml` (already an allowlist) as the reference, then
   uv, Composer `config`, Gradle properties, Maven options, `.npmrc`/`.yarnrc.yml`/`bunfig.toml`,
   Cargo config, `pip.conf`, `nuget.config`, `pnpm-workspace.yaml`.
3. `ambient_inputs` per plugin, populated from the Context Anchors list; conformance suite.
4. Remove the old helpers and denylist constants; tighten baselines; CHANGELOG.

## Decisions (2026-10-24)

1. **YAML**: a small YAML dependency is acceptable where the existing crate cannot report duplicate
   keys, anchors, aliases and merge keys.
2. **Unknown keys must be flexible**: an unlisted key blocks by default, and users can allow it
   explicitly through the scanner config (a per-file, per-key allow entry). Constraints: the allow
   list is read only from the trusted config source defined in `docs/specs/config-injection.md`
   (never from a file inside the scanned repo that the repo's author controls unless that spec
   already trusts it); an allow entry names the file pattern and the exact key path, never a
   wildcard over a whole file; every applied allow is reported as a warning so it stays visible in
   output and `--json`; an allow cannot override a `Blocked` ambient input or a gateway rejection
   (BOM, NUL, line terminators, duplicate keys), only a missing-from-table key.
3. **Git-tracked helper**: add a foundation helper (`is_git_tracked(path)` reading `.git/index`,
   returning tracked / untracked / undecidable) and a `BlockedIfTracked` disposition for
   `ambient_inputs`; the Python `.venv` check and a committed Composer `vendor/` use it.
4. **Rollout**: each rollout step is its own commit (tests green, changelog entry, no push).

