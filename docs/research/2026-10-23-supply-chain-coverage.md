# Supply-chain coverage research for 1.2.0

Research date: 2026-10-23. Scope: primary-source incident reports and package-manager documentation, checked against the current scanner implementation. This is a documentation inventory, not evidence that historical malicious artifacts were successfully replayed through sloppy-joe.

## Add these attack classes to the README

| Class | Primary-source evidence | Actual sloppy-joe coverage and limits |
| --- | --- | --- |
| Compromised releases of legitimate packages | The [LiteLLM maintainer incident report](https://github.com/BerriAI/litellm-docs/blob/main/blog/security_update_march_2026/index.md) identifies malicious PyPI versions 1.82.7 and 1.82.8 on March 24, 2026, including credential theft and a Python startup payload. | The configured publication-age gate can block newly published resolved versions before installation. This is a timing policy, not payload detection. Python `.pth` files, secret theft, persistence, and runtime behavior are not inspected. |
| Malicious transitive dependency injection | The [Axios maintainer postmortem](https://github.com/axios/axios/issues/10636) reports that malicious versions 1.14.1 and 0.30.4 added `plain-crypto-js@4.2.1`, delivering a cross-platform RAT on March 31, 2026. | Supported lockfiles expose transitives to metadata and OSV checks. `--deep` adds transitive name-similarity checks. The publication-age gate is relevant; the dependency-explosion check is not a general detector of a single injected dependency. |
| Install-time execution and credential-driven propagation | [GitHub's Shai-Hulud analysis](https://github.blog/security/supply-chain-security/strengthening-supply-chain-security-preparing-for-the-next-malware-campaign/) describes compromised maintainer credentials, malicious lifecycle scripts, and propagation through republished packages. | npm install-script metadata is combined with risk signals; publisher-change and publisher/script-history checks provide additional heuristics. The scanner does not execute, sandbox, or deobfuscate package contents and cannot establish that a script is malware. |
| Dependency confusion and source substitution | [pip's own warning](https://pip.pypa.io/en/stable/cli/pip_install/#examples) explains how `--extra-index-url` can select a public attacker-owned package in place of a private one. | Source/provenance checks constrain supported Cargo and Python workflows. Exact allowlists and manifest/lock consistency matter. Other source configurations may be explicitly unsupported. An `internal` name pattern alone does not prove where an installer will obtain a package. |
| Lockfile/source tampering and graph omission | [npm's lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/) distinguishes the resolved artifact location, integrity metadata, and dependency graph. | Scanner validation checks supported graph structure, declared dependency consistency, and provenance metadata. It does not download every artifact and recompute its integrity digest, authenticate every publisher, or prove that all supported installers behave identically. Describe this as validation of supported lockfile/source policy, not universal tamper-proofing. |
| Known vulnerable package versions | The [OSV query API](https://google.github.io/osv.dev/post-v1-query/) accepts a package ecosystem/name and optional version. | `malicious/known-vulnerability` reports returned OSV records; exact lockfile versions improve specificity. Advisory coverage and freshness remain external dependencies. An empty lookup is not proof that package content is safe. |

## Corrections to existing claims

- Replace the README's unconditional LiteLLM prevention statement with a conditional inference: a full/CI scan before installation, with a resolved affected version, usable publication metadata, an enabled age gate, and no relevant exemption would reject a version inside the cooldown. The maintainer report supports the incident facts, not a claim that sloppy-joe was historically deployed and stopped it.
- Remove unsupported competitor capability comparisons rather than treating unchecked competitor features as absent. Remove the unsupported zero-false-positive and fixed attack-count marketing claims. Name similarity, publisher changes, absent repository URLs, and install scripts can also occur in legitimate packages. A publisher-name comparison cannot reliably detect compromise of the same publisher account.
- Explain each metadata check separately: install-script risk, dependency explosion, maintainer changes, and publisher-plus-script history are currently missing from the numbered attack walkthrough. The implementation requires at least ten additional dependencies for `metadata/dependency-explosion`.
- Separate scanner findings from unsupported-input errors: unsupported dependency expressions, source configurations, or lockfile shapes stop verification with exit 2; they are not evidence that a package is malicious.
- State that online checks require `--full` or `--ci`; the default fast scan validates local state and recommends a full scan when freshness or state requires it.
- Preserve explicit limits: this is a pre-install dependency metadata/policy scanner, not an endpoint malware scanner, runtime monitor, general code auditor, or recovery tool after malicious code has executed.

## Implementation anchors

- `src/checks/signals.rs`: version age, script-risk combinations, ten-dependency threshold, publisher changes, publisher/script history.
- `src/registry/npm.rs`: version-specific publication dates, lifecycle-script flags, publisher identities, dependency counts, history extraction.
- `src/lib.rs`: transitive tier classification and scans; source-policy and lockfile checks; full/fast scan behavior.
- `src/checks/malicious.rs`: package/version OSV queries and bounded-expiry disk cache.

## Research-discovered gap: fixed for 1.2.0

The [OSV pagination contract](https://google.github.io/osv.dev/post-v1-query/#pagination) permits token-only responses. Research reproduced a missed-advisory case in the old client. Version 1.2.0 follows `next_page_token` using `page_token`, retains package/version filters, validates response schemas, and fails closed on repeated tokens or a 100-page safety limit. Local HTTP protocol regressions cover these cases; historical attack artifacts were not replayed.

## Live release-gate follow-up

The live check identified affected locked dependencies, including [anyhow unsoundness](https://osv.dev/vulnerability/RUSTSEC-2026-0190), [rustls handshake validation](https://osv.dev/vulnerability/RUSTSEC-2026-0285), and [distrusted root certificates](https://osv.dev/vulnerability/RUSTSEC-2026-0381). The release updates affected dependencies to compatible patched versions.

[RUSTSEC-2024-0449](https://osv.dev/vulnerability/RUSTSEC-2024-0449) explicitly describes an unmaintained package, not a demonstrated vulnerability. The client excludes records whose affected entries are all marked `informational: unmaintained` from vulnerability findings. Unsoundness records remain blocking. This does not evaluate dependency maintenance quality.

Self-check publisher exceptions are pinned to exact package, version, and publisher transitions. Official [colored 2.1.0](https://github.com/colored-rs/colored/releases/tag/v2.1.0) and [ICU4X 2.2.0](https://github.com/unicode-org/icu4x/releases/tag/icu@2.2.0) releases corroborate the reviewed publishers. Named canonical dependency exceptions skip existence/similarity only; metadata and advisory checks still run.

Cargo name comparison also respects the [crates.io collision rules](https://doc.rust-lang.org/cargo/reference/registry-index.html#name-restrictions): case and hyphen/underscore spellings cannot distinguish separately registered crates. The release excludes these equivalent spellings from name-similarity candidates.

## 2026 campaigns and slopsquatting (added 2026-10-24)

Sources below are mostly vendor write-ups and secondary reports; counts differ between them and were not independently verified. They motivate the coverage table and gap list, and none was replayed through sloppy-joe.

| Class | Evidence | Actual sloppy-joe coverage and limits |
| --- | --- | --- |
| Slopsquatting (registered hallucinated names) | Bar Lanyado registered an empty `huggingface-cli` package that LLMs kept inventing; it drew 30,000+ downloads in three months ([Wikipedia](https://en.wikipedia.org/wiki/Slopsquatting)). A USENIX study found 19.7% of generated samples contained a hallucinated package and 43% of hallucinations repeated across ten runs ([Endor Labs](https://www.endorlabs.com/learn/slopsquatting-when-ai-agents-hallucinate-malicious-packages)). No in-the-wild malicious slopsquat is named in the sources reviewed. | A name that does not exist blocks (`existence`). A name an attacker has already registered passes `existence`; only `metadata/new-package`, `metadata/low-downloads`, similarity and OSV can catch it. A registered squat older than 30 days with downloads passes. |
| Build-time execution without an install script (Phantom Gyp) | A 157-byte `binding.gyp` makes npm run `node-gyp rebuild` with no `scripts` entry ([StepSecurity](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm)). | Covered for npm: `gypfile` and a root `*.gyp` in the tarball count as install scripts (`src/registry/npm.rs`, `src/registry/npm_tarball.rs`). Content of the gyp file is not analyzed. |
| Interpreter-startup execution (`*.pth` in PyPI wheels, Hades) | Malicious wheels shipped a `*-setup.pth` that runs at Python startup ([GitGuardian](https://blog.gitguardian.com/shai-hulud-npm-pypi-supply-chain-attacks/)). | Not covered. Only npm tarballs are opened; PyPI archives are not inspected. The version-age gate is the only relevant control. |
| Compromised maintainer account, worm propagation (ChainDrop/keyv) | Hundreds of packages republished through one stolen account ([Datadog](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/), [Aikido](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack)). | Version-age gate and publisher-change checks apply. A stolen account publishes under the same identity, so publisher-change does not fire. |
| Malicious release with valid provenance | AsyncAPI releases carried valid Sigstore/SLSA provenance because CI was hijacked ([TuxCare](https://tuxcare.com/blog/supply-chain-broke-in-2026/)). | sloppy-joe does not read attestations, so it neither trusts nor reports them. Provenance would not have been a safe pass signal. |
| Typosquatted MCP server packages | Described as plausible by [Nesbitt](https://nesbitt.io/2026/04/08/package-security-problems-for-ai-agents); no in-the-wild case found. | Ordinary similarity applies only if the real MCP package is in the popular-package set. Not specifically modeled. |

## Gap review of proposed checks (updated 2026-10-25)

Spec: `docs/specs/python-supply-chain-signals.md`. Attestation/provenance reporting and MCP-name similarity are out of scope.

| Proposed check | Status | Evidence |
| --- | --- | --- |
| New or low-history package with a plausible hallucinated name | Done | `metadata/new-package`, `metadata/low-downloads`; `steering/distribution-name` adds the guessed import/command-name case for PyPI. |
| Execution on install beyond scripts (`binding.gyp`, `.pth`) | Done | npm gyp counts as an install script; PyPI wheels are read for `*.pth` import lines and `sitecustomize`/`usercustomize` (`metadata/python-startup-hook`). sdist `setup.py` and hook code beyond a token list are not analyzed. |
| Maintainer change, version burst, dormancy-then-release | Done | Publisher change and publisher/script history; `metadata/dormant-release` and `metadata/release-burst` for PyPI and npm. Other registries carry no cadence data yet. |
| Cooldown window for new versions | Done | `min_version_age_hours`, default 72. The PyPI version date is the newest file upload. |
| Dependency steering | Done | Guessed import/command names for PyPI (`steering/distribution-name`); `--base-ref <REF>` singles out dependencies added since a git ref (`steering/new-dependency`), stricter when young. |
| Lockfile integrity and non-registry sources | Done for npm-family and Python | `metadata/lockfile-integrity-*` for npm lockfiles, `poetry.lock`, `uv.lock`, `Pipfile.lock`. `requirements.txt --hash` and Yarn Berry are not compared. |
| MCP server package name similarity | Out of scope | |
| Report attestation/provenance status | Out of scope | |
