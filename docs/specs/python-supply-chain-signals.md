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
  directory) and other data (`share/`, `etc/`, `include/`, `lib/pkgconfig/`, static archives,
  shared libraries in `lib/` under names the interpreter does not load) are not reported, nor
  are ordinary scripts. Reported, after the path normalization above:
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
    scripts directory (`python3.7m`-style ABI suffixes included); `pyvenv.cfg`, `*._pth`,
    `python*.exe`/`.dll` and `vcruntime*.dll` at the prefix; a macOS framework build's
    `data/Python` (the interpreter library `bin/python3` links) and anything under
    `data/Resources/Python.app/` (the binary `bin/python3` executes).
  - Shared-library overwrite (`EnvironmentOverwrite`): a shared library (`.so`, `.so.N`,
    `.dylib`, `.dll`) directly in `data/lib/` or `data/lib64/` (any case) whose name, before the
    first `.` or `-` and without trailing version digits, is the interpreter's own library
    (`libpython*`, `libpypy*`) or one the interpreter and its standard-library extension modules
    link: `libssl`, `libcrypto`, `libffi`, `libz`, `libbz2`, `libb2`, `liblzma`, `libzstd`,
    `libsqlite3`, `libmpdec`, `libexpat`, `libreadline`, `libedit`, `libhistory`, `libuuid`,
    `libcrypt`, `libnsl`, `libtirpc`, `libdb`, `libintl`, `libiconv`, `libc`, `libm`, `libdl`,
    `libpthread`, `librt`, `libutil`, `libgcc_s`, `libstdc++`, `libatomic`, and the
    `libtcl*`, `libtk*`, `libicu*`, `libncurses*`, `libtinfo*`, `libpanel*`, `libform*`,
    `libmenu*`, `libgdbm*` families. An `--enable-shared` interpreter (the official Docker
    images, prefix `/usr/local`) loads `lib/libpython3.X.so.1.0` through its `RUNPATH` at every
    start, and pip running as root replaces it (checked against `python:3.12-slim`: the
    interpreter then fails to start); conda environments load `lib/libssl.so.3` etc. through
    `RPATH $ORIGIN/../..` (checked against `condaforge/miniforge3`: `import ssl` loads the
    wheel's copy), as python.org macOS builds do by install name. Any shared library in a
    Debian multiarch directory (`data/lib/<x>-linux-<y>/`) is reported too: Debian and Ubuntu
    list `/usr/local/lib/<triplet>` ahead of `/lib/<triplet>`, so after the next `ldconfig` it
    replaces the system's copy for every program (checked against `python:3.12`: `import zlib`
    then loads the wheel's `libz.so.1`). Other library names in `data/lib/` are not reported:
    Intel's `mkl`, `intel-openmp`, `tbb` and `intel-cmplr-lib-rt` wheels install dozens there
    (`libmkl_core.so.3`, `libiomp5.so`, `libtbb.so.12`), and on Debian-based images
    `/usr/local/lib` comes after the multiarch directories even after `ldconfig`, so a new name
    there replaces no system library.
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
- The baseline manifest is read with git plumbing (no pager, textconv or hooks) after the ref
  is checked to be a plain ref and resolved to one commit id: `git ls-tree -z --full-tree
  --name-only <id>^{commit} -- <path>` with literal pathspecs decides whether the manifest
  exists there (no output: absent; exactly the path: present; anything else, or a failed run,
  blocks), and `git cat-file blob <id>:<path>` reads it. No decision depends on git's message
  text, which differs between versions (git 2.34 says "Not a valid object name" for a missing
  path). The manifest is then parsed by the project's own manifest parser from a private
  temporary directory. Only the manifest file is restored.
- No new dependencies and no config keys; one CLI flag, `--base-ref`.

## Scope Boundaries

- Not covered: sdist `setup.py`, hook code beyond the listed tokens, `<dist>.data/data/`
  files that other programs execute (`etc/jupyter/` server extensions, shell profiles),
  shared libraries in `data/lib/` named after a library a third-party package loads (a conda
  environment's `libopenblas`) or one a later `ldconfig` would add for a program that finds
  no other copy, console
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
