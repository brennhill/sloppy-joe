# Ecosystem Guides

`sloppy-joe` applies the same high-level scan pipeline everywhere, but the trust boundary is different for each package ecosystem. These guides describe the current user workflow, what the scanner verifies, what blocks immediately, and where each ecosystem still fails closed.

## Current guides

- [JavaScript](JAVASCRIPT.md)
- [Python](PYTHON.md)
- [Rust](RUST.md)
- [Go](GO.md)
- [Ruby](RUBY.md)
- [PHP / Composer](PHP.md)
- [JVM](JVM.md)
- [.NET / NuGet](DOTNET.md)

## Support summary

| Ecosystem | Primary workflow | Trust level today |
|---|---|---|
| JavaScript | Scan the workspace or package root with the authoritative manager lockfile | strict |
| Python | Trust Poetry + `poetry.lock`, uv + `uv.lock`, or fully hash-locked pip-tools; legacy manifests still warn by default | mixed |
| Rust | Strict `Cargo.lock` plus provenance validation for local paths, registries, git, and rewrites | strict |
| Go | `go.mod` required; `go.sum` required for external deps | partial |
| Ruby | `Gemfile` + `Gemfile.lock`, registry-only source model | strict |
| PHP | `composer.json` + `composer.lock`, default registry-only source model | strict |
| JVM | Gradle is strict with `gradle.lockfile`; Maven is reduced-confidence | mixed |
| .NET | `.csproj` + `packages.lock.json` | strict |

## How to read these pages

Each ecosystem guide follows the same structure:

- `Quick Start`: what to commit and what to run
- `What sloppy-joe checks`: the current supported trust model
- `What blocks`: the fast fail-closed conditions
- `Current limitations`: important unsupported or reduced-confidence cases
- `Recommended workflow`: how to use the tool without fighting it

If you are onboarding a new repo, start here from the main [README](../../README.md), then read the guide for the ecosystem you are scanning.
