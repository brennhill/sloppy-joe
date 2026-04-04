# Go

This guide covers the current Go support surface in `sloppy-joe`.

## Quick Start

Required project state:

- `go.mod`
- `go.sum` when the module has external dependencies

Recommended command:

```bash
go mod tidy
```

Then run:

```bash
sloppy-joe check
```

## What sloppy-joe checks

- `go.mod` is always required.
- `go.sum` is required when the module depends on external code.
- If the module has no external dependencies, or every required dependency is replaced with a local path, missing `go.sum` does not block.
- Direct Go dependencies still get the normal dependency checks such as existence, similarity, and canonicals.

## What blocks

- Missing `go.sum` when the module depends on external packages.
- Local `replace` targets in `go.mod`; those are not trusted yet.
- Broken or unreadable `go.mod`.

## Current limitations

- `go.sum` is treated as an integrity gate, not as a full project-local lockfile model.
- Go does not currently get the same trusted lockfile-backed transitive graph coverage as ecosystems with richer project-local lockfiles.
- Local `replace` targets fail closed today.

## Recommended workflow

- Run `go mod tidy` and commit `go.sum`.
- Avoid local `replace` directives in repos you want to scan strictly.
- Treat Go support today as strong on direct dependency hygiene and checksum presence, but lighter on trusted transitive graph reconstruction than Rust, JavaScript, or Poetry.
