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
- **Dependency added since the git base ("agent-introduced")**: needs a VCS baseline in the
  engine; not built.

## Acceptance Criteria

- `metadata/python-startup-hook`: a wheel of the resolved PyPI version installs a `*.pth` with
  a line starting `import ` or `import<TAB>`, or `sitecustomize`/`usercustomize`, at the top of
  `site-packages` (wheel root or `<dist>.data/purelib|platlib/`). Error when the version or
  package is under 30 days old, the name is similarity-flagged, the hook is a customize module,
  unreadable, or its code spawns processes or reaches the network; otherwise a warning
  (`--paranoid` inspecting an established version).
- A hook marks the version as running install-time code, so `metadata/install-script-risk`
  and the dormancy escalation see it.
- `metadata/wheel-unverified` (blocking): a selected wheel could not be fetched, hashed or read,
  has no published sha256, or exceeded a limit (32 wheels per version, 60 downloads per scan).
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
- The PyPI version date is the newest file upload of the release, so a file added later to an
  old release cannot pass the age gate.

## Constraints

- Wheels are downloaded into memory only, from `files.pythonhosted.org` over HTTPS with no
  redirects, hashed before parsing, never extracted. Zip64, unknown compression and oversize
  hook files are reported, not skipped.
- Wheel results are cached by sha256 through `cache.rs`; failures are never cached.
- No new dependencies; no new UI or config keys.

## Scope Boundaries

- Not covered: sdist `setup.py`, hook code beyond the listed tokens, `.pth` path entries,
  Yarn Berry/other non-PyPI lock hashes, requirements.txt `--hash`, newly-added-dependency
  detection, MCP name similarity, attestation status.

## I/O Contracts

- Input: `PackageMetadata.pypi_release` (files, sha256), `release_cadence`, lockfile hashes in
  `ResolutionResult.python_hashes`.
- Output: `Issue`s with the check names above.

## Context Anchors

- `src/registry/pypi_release.rs`, `src/registry/cadence.rs`, `src/registry/wheel.rs`
- `src/checks/wheel_verification.rs`, `src/checks/python_lockfile_hashes.rs`,
  `src/checks/release_cadence.rs`, `src/checks/steering.rs`
- `src/lockfiles/python_hashes.rs`

## Architecture

Registry modules parse and fetch; checks decide. `MetadataCheck` runs wheel inspection before
lockfile and signal checks so the install-time flag is set first; `SimilarityCheck` runs the
steering check so its hits feed wheel and tarball selection.
