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
- Every module listed in `go.mod`, including requirements marked `// indirect`, gets normal dependency checks. Whitespace and comment formatting do not change coverage.

## What blocks

- Missing `go.sum` when the module depends on external packages.
- All local and remote `replace` targets in `go.mod`; replacement identities are not trusted yet.
- Ancestor `go.work` files; workspace source resolution is not modeled.
- Broken or unreadable `go.mod`.

## Current limitations

- `go.sum` is treated as an integrity gate, not as a full project-local lockfile model.
- Go does not currently get the same trusted lockfile-backed transitive graph coverage as ecosystems with richer project-local lockfiles.
- Replacement and workspace source resolution fail closed today.

## Recommended workflow

- Run `go mod tidy` and commit `go.sum`.
- Avoid `replace` directives and `go.work` files in repos you want to scan strictly.
- Treat Go support today as strong on direct dependency hygiene and checksum presence, but lighter on trusted transitive graph reconstruction than Rust, JavaScript, or Poetry.
