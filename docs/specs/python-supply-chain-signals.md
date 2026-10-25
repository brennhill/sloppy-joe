# Python Supply-Chain Signals

**Created**: 2026-10-25
**Status**: Implemented

## Context

### Problem / Why Now

2026 campaigns moved execution out of install scripts: PyPI wheels shipped `*.pth` files that
run at every interpreter start (LiteLLM 1.82.8, Hades), npm packages used `binding.gyp`, and
stolen maintainer accounts republished many versions quickly. Models also guess import or
command names as package names (`pip install cv2`, `huggingface-cli`), and attackers register
those guesses. See `docs/research/2026-10-23-supply-chain-coverage.md`.

### Expected Outcomes

- A recent PyPI version that installs a startup hook blocks before install.
- A Python lockfile whose hashes PyPI never served blocks.
- A version published after long silence, or in a burst, is visible while it is recent.
- A dependency named after an import or command name points at the intended distribution.

### Alternatives Considered

- **Analyze hook code**: attackers can import a module from the same wheel; recency plus
  presence is the signal, code tokens only raise a quiet case.
- **Trust Sigstore/attestations**: AsyncAPI shipped malicious releases with valid provenance.
  Out of scope.
- **Dependency added since the git base ("agent-introduced")**: built as opt-in `--base-ref`,
  because without a ref there is no baseline and guessing one (HEAD) would run git on every scan.

## Acceptance Criteria

- `metadata/python-startup-hook`: a wheel of the resolved PyPI version installs, at the top of
  `site-packages`, a `*.pth` with a line starting `import ` or `import<TAB>` (an import hook) or
  any other non-comment line (a path hook: `sitecustomize` is searched in the directories it
  adds, which another wheel can fill), a `*.start` file with an entry point (Python 3.15), or
  `sitecustomize`/`usercustomize` in any importable form (`.py`, `.pyc`, extension module,
  package directory, `__pycache__`). Error when the version or package is under 30 days old,
  the name is similarity-flagged, the hook is a customize module, unreadable, or its code spawns
  processes or reaches the network; otherwise a warning (`--paranoid` inspecting an established
  version).
- Member names are resolved as installers resolve them: `.`, `..` and empty segments are
  dropped, `\` is both a literal character (POSIX) and a separator (Windows), Windows trailing
  dots and spaces are trimmed, and a member lands at the top of `site-packages` from the wheel
  root, `<dist>.data/purelib|platlib/`, or any `<dist>.data/<key>/.../site-packages/` (or
  `dist-packages/`), or `<dist>.data/data/` itself (Windows `site` treats `sys.prefix` as a site
  directory, so `<dist>.data/data/x.pth` runs at startup there, in venvs too). A name that is
  absolute, climbs above its directory, contains `:`, or has a segment Windows reduces to
  nothing makes the wheel unverified, never skipped.
- `<dist>.data/` files installed outside `site-packages` are `metadata/python-startup-hook`s
  too, always blocking. pip and uv install `data/<rest>` at `sys.prefix/<rest>` and
  `scripts/<rest>` in `bin` (`Scripts`), replacing existing files; `headers/` (include
  directory) and other data (`share/`, `etc/`, `include/`, `lib/*.so`, `lib/pkgconfig/`) are
  not reported, nor are ordinary scripts. Reported, after the path normalization above:
  - Standard-library overwrite (`StdlibOverwrite`): anything under `data/lib/python*/` or
    `data/lib/pypy*/` (also `lib64/`) other than its `site-packages`/`dist-packages`, including
    `lib/python3XY.zip`; `data/Lib/` files Windows imports (`.py`, `.pyc`, `.pyw`, `.pyd`);
    anything under `data/DLLs/`; `data/python3XY.zip`. On a base interpreter (system Python,
    Docker images) that is the standard library itself, and modules imported at startup
    (`encodings`) run at every start. Modules Python 3.11+ loads frozen (`site`, `os`, `codecs`)
    do not run from disk at startup, but are still reported.
  - A module or package named after a standard-library module (`sys.stdlib_module_names` of
    3.10-3.15, case-insensitive) directly in the scripts directory (`scripts/json.py`,
    `data/bin/re.py`, `data/Scripts/typing.pyd`, `scripts/json/`): a console script runs with
    its own directory first on `sys.path`, so every script in the environment imports it
    instead of the standard library (`StdlibOverwrite`).
  - Environment overwrite (`EnvironmentOverwrite`): `python`, `python3`, `python3.12`,
    `python3.13t`, `pythonw`, `pypy3` (with or without `.exe`) and the activation scripts
    (`activate`, `activate.<shell>`, `Activate.ps1`, `activate_this.py`, `deactivate.*`) in the
    scripts directory; `pyvenv.cfg`, `*._pth`, `python*.exe`/`.dll` and `vcruntime*.dll` at the
    prefix.
- `.pth`/`.start` lines are read every way a supported Python reads them: a leading UTF-8 BOM
  is dropped, lines split on every `str.splitlines` break (lone `\r`, `\x0b`, `\x0c`,
  `\x1c`-`\x1e`, NEL, U+2028, U+2029), the file is decoded as UTF-8 and as Latin-1 (the locale
  fallback), and a line counts before or after Python 3.15's `str.strip`. A test checks each
  case against the local `python3`'s `site.addsitedir` when one is installed.
- A hook marks the version as running install-time code, so `metadata/install-script-risk`
  and the dormancy escalation see it.
- `metadata/wheel-unverified` (blocking): a selected wheel could not be fetched, hashed or read,
  has no published sha256, or exceeded a limit (32 wheels per version, 60 downloads per scan).
  A wheel is also unreadable when installers could read its zip structure differently: any
  zip64 locator, record, marker or extra field; a central directory that does not end where the
  end-of-central-directory record starts or whose size disagrees with its entries; data after
  that record or a second one; multi-disk counts; a local header naming a different file or data
  running into the central directory; a NUL in a name; an encrypted entry. An Info-ZIP Unicode
  Path name (used by Python 3.12+ `zipfile`) is matched alongside the recorded name.
- `metadata/wheel-integrity-mismatch` (blocking): downloaded bytes differ from PyPI's sha256.
- `metadata/lockfile-integrity-mismatch` / `-unverified` for `poetry.lock`, `uv.lock` and
  `Pipfile.lock`: every recorded sha256 of a public-PyPI entry must be one PyPI publishes for
  that version; no sha256, no entry for a lockfile-resolved version, or no published digests is
  unverified. Entries from other indexes, git, URLs or paths are left to source policy.
- `metadata/dormant-release`: the selected version is under 30 days old and followed 365+ days
  without a release. Warning; error when the version also runs install-time code or the
  publisher changed. Applies to PyPI and npm.
- `metadata/release-burst` (warning): 5+ other releases in the 24 hours before a version under
  30 days old. Applies to PyPI and npm.
- `steering/distribution-name`: a PyPI dependency equals (PEP 503) a listed import or command
  name. Warning; error when the package is under a year old or its history is unknown. Hits are
  similarity-flagged for deeper inspection.
- `steering/new-dependency` (only with `--base-ref <REF>`, e.g. `HEAD` locally or `origin/main`
  in CI): a direct dependency the manifest did not declare at the ref (PEP 503 names on PyPI;
  version bumps are not new; a manifest absent at the ref makes all its dependencies new).
  Warning; error when the package is under 90 days old or its first-publication date is
  unreadable. Hits are similarity-flagged for wheel and tarball inspection.
- `steering/baseline-unavailable`: with `--base-ref`, an unresolvable ref, missing repository
  or unreadable git blocks; a manifest that cannot be parsed alone at the ref warns.
- The PyPI version date is the newest file upload of the release, so a file added later to an
  old release cannot pass the age gate.

## Constraints

- Wheels are downloaded into memory only, from `files.pythonhosted.org` over HTTPS with no
  redirects, hashed before parsing, never extracted. Zip64, unknown compression and oversize
  hook files are reported, not skipped.
- Wheel results are cached by sha256 through `cache.rs`; failures are never cached. The cache
  records the inspector format and is discarded when detection widens.
- The baseline manifest is read with `git cat-file` (no pager, textconv or hooks) after the ref
  is checked to be a plain ref and to resolve to a commit, then parsed by the project's own
  manifest parser from a private temporary directory. Only the manifest file is restored.
- No new dependencies and no config keys; one CLI flag, `--base-ref`.

## Scope Boundaries

- Not covered: sdist `setup.py`, hook code beyond the listed tokens, `<dist>.data/data/`
  files that other programs execute (`etc/jupyter/` server extensions, shell profiles), console
  entry points (`entry_points.txt`) named `python` or `activate`, scripts that shadow
  third-party module names, Yarn Berry/other non-PyPI lock hashes, requirements.txt `--hash`, MCP name similarity,
  attestation status. Baseline comparison covers direct manifest dependencies only, and a
  manifest that needs sibling files (`-r other.txt`) cannot be compared.

## I/O Contracts

- Input: `PackageMetadata.pypi_release` (files, sha256), `release_cadence`, lockfile hashes in
  `ResolutionResult.python_hashes`.
- Output: `Issue`s with the check names above.

## Context Anchors

- `src/registry/pypi_release.rs`, `src/registry/cadence.rs`, `src/registry/wheel.rs`,
  `src/registry/wheel/layout.rs`, `src/registry/wheel/environment.rs`
- `src/engine/baseline.rs`, `src/checks/wheel_verification.rs`, `src/checks/python_lockfile_hashes.rs`,
  `src/checks/release_cadence.rs`, `src/checks/steering.rs`
- `src/lockfiles/python_hashes.rs`

## Architecture

Registry modules parse and fetch; checks decide. `MetadataCheck` runs wheel inspection before
lockfile and signal checks so the install-time flag is set first; `SimilarityCheck` runs the
steering check so its hits feed wheel and tarball selection.
