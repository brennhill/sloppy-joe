# Python

This guide covers the current Python support surface in `sloppy-joe`.

## Quick Start

Trusted Python modes today are:

- Poetry projects: `pyproject.toml` + `poetry.lock`
- uv projects: `pyproject.toml` + `uv.lock`

Reduced-confidence Python mode:

- pip-tools environment locks: fully hash-locked `requirements*.txt` without an explicit file-bound primary index

Recommended commands:

```bash
sloppy-joe check
sloppy-joe check --full
sloppy-joe check --ci
sloppy-joe check --python-groups dev,test --python-version 3.12
sloppy-joe check --python-extras docs --python-platform linux --python-arch aarch64 --python-version 3.12
```

Legacy Python manifests still scan by default, but they are not the trusted path.

## What sloppy-joe checks

- Supported manifest inputs:
  - Poetry `pyproject.toml`
  - uv `pyproject.toml`
  - non-Poetry `pyproject.toml`
  - `requirements*.txt`
  - `Pipfile`
  - `setup.cfg`
  - statically readable `setup.py`
- Poetry projects require `poetry.lock` and use it for exact version resolution plus trusted transitive coverage. Every scanned group dependency must have a resolved package in `poetry.lock`; a missing one blocks.
- uv projects require `uv.lock` and use it for exact version resolution plus trusted transitive coverage. sloppy-joe reads the root package's `dependencies`, `optional-dependencies`, and `dev-dependencies` (dependency groups, including `[tool.uv] dev-dependencies` recorded as `dev`) together with `metadata.requires-dist` / `metadata.requires-dev`, and follows locked package extras (`[package.optional-dependencies]`) transitively. Every manifest dependency in scope for some environment must be recorded there, including one whose marker is false for the scan target; a missing or out-of-sync entry blocks.
- uv.lock consistency is checked in both directions: every scanned manifest dependency must be locked with the same specifier, and every root entry in uv.lock (main, extra, or group) must be declared in the matching pyproject.toml section, whether or not that group was selected for scanning.
- Supported uv version ranges are trusted only when lock metadata matches the manifest and the selected version satisfies the range; ambiguous or stale selections fail.
- An adjacent `uv.lock` identifies a uv project without requiring an otherwise empty `[tool.uv]` section. Both virtual roots and packaged `editable = "."` roots are supported; external editable paths remain unsupported.
- Fully hash-locked pip-tools requirements provide exact pinned versions only when every installable requirement is exact-pinned and fully hash-covered, including recursively included requirement files.
- pip-tools reaches exact source provenance only when the committed requirements graph binds its own primary `--index-url` and any `--extra-index-url` values with supported HTTP(S) URLs. If the primary index is not explicitly file-bound, sloppy-joe downgrades pip-tools to reduced-confidence mode.
- Trusted Poetry and uv inputs resolve versions for one concrete Python install profile at a time: environment markers pick the target environment's locked versions rather than being flattened into unconditional direct dependencies.
- Environment markers never hide a package. Source policy (untrusted indexes, undeclared or unauthorized sources, lock hash proofs) and the package checks walk the lockfile graph for every environment, so a dependency gated on `sys_platform == "win32"` is vetted on a Linux CI runner too. A manifest dependency whose marker is false for the target is still a direct dependency: it gets the canonical, similarity, existence, metadata and vulnerability checks at its locked version, in every scan mode. Other locked packages the target does not install are checked like transitive dependencies (existence, metadata, vulnerabilities; similarity with `--deep`). Lockfile-less manifests (`requirements*.txt`, non-Poetry `pyproject.toml`) scan every dependency whatever its marker. A marker the evaluator cannot decide counts as true, and so do uv's encoded `[tool.uv] conflicts` markers on lock edges (`extra == 'extra-4-proj-b'`), which name the project's extra or group rather than the requesting package's.
- By default every declared dependency group and extra is in scope, because uv and Poetry install the dev group without any flag. This covers Poetry groups (including `optional = true` groups) and `dev-dependencies`, PEP 735 `[dependency-groups]`, `[tool.uv] dev-dependencies`, `[project.optional-dependencies]`, and Poetry extras. PDM `dev-dependencies` and Hatch environments are scanned as unlocked tooling because no Poetry/uv lockfile records them.
- PEP 735 `{ include-group = "..." }` entries are resolved transitively. Unknown groups, include cycles, duplicate normalized group names, and include tables with any other keys block.
- `--python-groups` and `--python-extras` narrow the scan to the named groups/extras (matched after name normalization) and warn about the declared ones they leave out. `--python-platform`, `--python-arch`, and `--python-version` select the environment Poetry and uv versions are resolved for; without them, the current host is used and sloppy-joe warns. They never narrow what is scanned.
- Repo-visible Poetry and uv sources can use exact normalized Python index allowlists through `trusted_indexes.pypi`. The same allowlist applies to `--index-url` / `--extra-index-url` options in every scanned requirements file.
- For Poetry and uv, manifest source intent and lockfile provenance must agree before a non-PyPI source is trusted.
- For Poetry and uv, reachable non-PyPI packages must also be authorized by the in-scope root dependency graph; declaring an alternate source does not automatically authorize unrelated transitives.
- A repo-defined Poetry or uv source named `pypi` is not trusted unless it resolves to the canonical PyPI simple index. A custom index pretending to be `pypi` fails closed.
- Declared but unused non-PyPI Poetry/uv sources warn and suggest removal for clarity and maintenance.
- Legacy Python manifests are still scanned for direct dependencies and standard signals like existence, similarity, canonicals, and vulnerabilities. Without a lockfile, their transitive dependencies are projected from PyPI metadata (see [Projected transitive dependencies](#projected-transitive-dependencies-no-lockfile)).
- Included requirements files are expanded recursively.
- Legacy `setup.py` and `setup.cfg` scans include `install_requires`, `setup_requires`, `tests_require`, and extras.
- `setup.cfg` supports both `=` and `:` option delimiters case-insensitive option names, and trailing section comments. `DEFAULT` inheritance reports `Scan not supported` rather than silently omitting inherited dependencies.
- `setup.py` accepts standard setuptools imports, string metadata assignments, comments, and one `setup(...)` call with literal arguments. Executable preambles, computed metadata, custom source encodings, and trailing statements report `Scan not supported`. It requires complete literal dependency values. Concatenated lists or strings, encoded string escapes, expanded keyword arguments, multiple setup calls, triple-quoted strings, and unrecognized calls report `Scan not supported` (exit 2).
- `setup.py` keywords are checked against a fixed list. `install_requires`, `setup_requires`, `tests_require`, and `extras_require` (a dict of string keys to lists of strings) are scanned. Standard metadata (`name`, `python_requires`, `classifiers`, `entry_points`, the PEP 314 `requires`/`provides`/`obsoletes`, and similar) is ignored. Unknown or plugin keywords (for example `pbr=True`), repeated keywords, a non-empty `dependency_links`, `options` that set `easy_install`, and string-valued or non-literal dependency values report `Scan not supported`.

## Projected transitive dependencies (no lockfile)

`requirements*.txt` without hashes, `setup.py`, `setup.cfg`, a non-Poetry/uv `pyproject.toml` and a `Pipfile` without `Pipfile.lock` record only the packages they declare; pip resolves the rest at install time. In full and CI scans sloppy-joe projects that closure from PyPI's JSON API so a malicious or hallucinated transitive dependency is still checked:

- Version: an `==` pin is taken as written; otherwise the newest version PyPI lists that every collected specifier allows, skipping yanked releases (unless pinned exactly) and prereleases (unless nothing else matches). Specifiers from every dependent of a package are merged.
- Requirements: `info.requires_dist` of that release, followed breadth first. Environment markers are evaluated for every environment, so `sys_platform == "win32"` and `python_version < "3.8"` requirements are included, and a marker the evaluator cannot decide counts as true. `extra == "..."` follows the extras requested: the ones a requirements file or `pyproject.toml` names (`requests[socks]`), the ones a transitive requirement names, and, for `setup.py`, `setup.cfg` and `Pipfile` direct dependencies (whose parsers do not record extras), every extra.
- Checks: projected packages are transitive dependencies (`"source": "transitive"`) and get existence, metadata and OSV checks at the projected version; similarity runs on them with `--deep`. Every finding on them ends with `[projected transitive: ...]`, because pip may install a different version. A package PyPI does not list is still scanned by name, so `existence` reports it.
- `resolution/python-projected-transitives` (warning) says how many packages were projected and that their versions may differ from what pip installs. For exact coverage, create a lockfile with `uv lock` or `poetry lock`, or run `sloppy-joe fix-lockfile`.
- `resolution/python-projected-conflict` (warning): no version satisfies every specifier collected for a package. The newest version each specifier allows is checked instead.
- `resolution/python-unprojectable` (warning): the requirements graph names an `--index-url` or `--extra-index-url` other than PyPI (allowlisted; unlisted ones block), so nothing is projected for that manifest; an `internal` package is never looked up on PyPI and its dependencies are not projected; or PyPI has no dependency metadata for a release (no wheel and `requires_dist: null`, typical of old sdists).
- Fast scans do not project.

## What blocks

- Poetry projects without a readable `poetry.lock`.
- uv projects without a readable `uv.lock`.
- Malformed Poetry lockfiles.
- Malformed, stale, or unsupported `uv.lock` files.
- A dependency declared in a scanned group or extra that is missing from `poetry.lock` or `uv.lock`.
- A `uv.lock` root dependency, extra, or group entry (resolved or in `requires-dev`) that pyproject.toml does not declare in that section, and registry packages in `uv.lock` that claim `dev-dependencies`.
- Mixed Poetry and uv project metadata in the same `pyproject.toml`.
- Poetry or uv projects whose locked graph resolves from a non-PyPI source that is not allowlisted exactly in `trusted_indexes.pypi`.
- Poetry or uv dependencies whose declared source intent disagrees with the resolved source in the lockfile.
- Poetry or uv source declarations that reuse the reserved name `pypi` for a non-canonical index URL.
- A committed `Pipfile.lock` that is out of sync with the Pipfile: a `[packages]`, `[dev-packages]`, or custom-category package missing from its `default`, `develop`, or category section, or locked at a version its Pipfile specifier does not allow.
- `Pipfile.lock` entries without an exact `==` pin or hashes, entries installed from `git`, `path`, `file`, or `editable` sources, entries resolved from a non-PyPI `index`, and `_meta.sources` indexes that are not allowlisted in `trusted_indexes.pypi` or not declared in the Pipfile. Lock entries the Pipfile does not declare are treated as transitive dependencies and scanned.
- Hash-locked pip-tools requirements that are missing hashes, use non-exact pins, or inherit an included file that is not fully hash-locked.
- Any `requirements*.txt` file (hash-locked or not, including files reached through `-r`/`-c` includes) whose `--index-url`, `-i`, or `--extra-index-url` names an index that is neither the default PyPI index (`https://pypi.org/simple`) nor allowlisted exactly in `trusted_indexes.pypi`. The error names the `resolution/untrusted-registry-source` check, the index, and the file that declared it. Without this, sloppy-joe would vet the public PyPI package while pip installs whatever the other index serves.
- `--find-links`/`-f`, `--no-index`, and index options placed after a requirement on the same line are unsupported pip options and block.
- Unsafe legacy dependency forms, including:
  - direct URLs
  - editable installs
  - local paths
  - VCS sources
  - unsupported pip global options such as `--trusted-host`
- Dynamic `setup.py` dependency construction.
- While projecting transitive dependencies of a manifest without a lockfile: a PyPI metadata lookup that fails, a `Requires-Dist` entry that is a direct URL or local path, or a release PyPI lists but serves no metadata for (`resolution/python-projection-failed`); and exceeding a projection bound, 40 dependency levels, 500 projected packages (direct dependencies not counted) or 1500 PyPI metadata requests (`resolution/python-projection-bound`). The projection never stops short silently.
- Legacy Python manifests entirely, if `python_enforcement` is set to `poetry_only`.

## Current limitations

- Poetry and uv are first-class trusted project modes.
- pip-tools with full hashes is fully trusted only when the requirements graph itself binds the primary index with `--index-url` and any non-PyPI `--extra-index-url` values are exactly allowlisted. Without an explicit primary index, pip-tools remains reduced-confidence because source selection can still come from pip config or environment variables.
- Python profile defaults and aliases are not configurable in `config.json` yet; profile selection is currently CLI-only.
- Poetry and uv support repo-visible custom indexes by exact normalized URL allowlist only. PyPI stays implicitly trusted as `https://pypi.org/simple/`.
- `pypi` is treated as a reserved identity, not a user-chosen alias. We are not aware of a legitimate reason to rename a custom index to `pypi`, and doing so is more likely to indicate confusion, misconfiguration, or an attack than a valid use case.
- `poetry_lock_policy` controls how missing Poetry proofs are handled. `strict` is the recommended CI/production setting. `warn_missing_proofs` still blocks contradictions, but it downgrades missing proof to reduced-confidence mode instead of fully trusted lock coverage.
- Legacy manifests remain allowed in the default `prefer_poetry` mode, but they warn on every run and do not inherit trusted transitive coverage: their projected transitive dependencies are a model of what pip would pick, not a record of what it installed.
- The projection does not model pip's resolver exactly: it ignores `-c` constraint files, pip configuration and environment variables (`PIP_INDEX_URL`, `pip.conf`), backtracking to older versions, and the target interpreter (every environment's requirements are included). When a later specifier changes a package's chosen version, the requirements the earlier version pulled in are kept, so it can check more packages than pip installs. Its metadata lookups are not cached between runs.
- A release with no wheel and `requires_dist: null` has unknown dependencies; they are reported (`resolution/python-unprojectable`), not projected.
- pip-tools still fails closed on unsupported global options and does not yet model editable/local first-party provenance beyond blocking those unsafe forms outright.
- Dynamic dependency generation fails closed rather than being partially interpreted.

## Recommended workflow

- Prefer Poetry or uv with a committed lockfile.
- If the repo uses environment markers, make CI pass the real target with `--python-platform`, `--python-arch`, and `--python-version`. Only pass `--python-groups`/`--python-extras` when you intentionally scan a narrower install than the full project.
- In CI or production, prefer `poetry_lock_policy = "strict"` so missing Poetry proof blocks instead of silently downgrading trust.
- If you use non-PyPI Poetry or uv sources, allowlist the exact normalized index URL under `trusted_indexes.pypi`.
- If you use pip-tools, compile exact pins with hashes, commit the compiled requirements graph, and bind the primary index with `--index-url`. Any non-PyPI `--extra-index-url` must also be allowlisted under `trusted_indexes.pypi`.
- Treat legacy manifest warnings as migration work, not noise.
- Keep exact pins where practical in legacy manifests.
- Use `python_enforcement = "poetry_only"` once the repo is fully migrated to Poetry.
