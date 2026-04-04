# Fixture Corpus

Static fixture projects used to preserve regression cases across ecosystems.

Each fixture directory contains:

- the minimal manifest and lockfile files needed to reproduce a case
- a `fixture.json` metadata file describing the expected scanner outcome

Expected outcomes are:

- `pass`: strict trusted input should scan cleanly
- `warn`: scan should continue, but sloppy-joe should emit a warning
- `fail`: scan should block

Current coverage:

- `npm/`: adversarial JS manager and supply-chain cases
- `python/`: Poetry and uv trusted paths plus pip-tools hash-locking and legacy/fail-closed cases
- `cargo/`: trusted local/workspace provenance and blocked alternate sources
- `go/`: `go.sum` enforcement and local-replace behavior
- `ruby/`: strict RubyGems path and blocked alternate sources
- `php/`: Packagist path and blocked custom repositories
- `jvm/`: Gradle strict path plus Maven warning/custom-repo cases
- `dotnet/`: `packages.lock.json` strict path
