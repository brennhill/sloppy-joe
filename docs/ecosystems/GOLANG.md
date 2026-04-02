# Go Rules

## Required inputs

- `go.mod` is always required.
- `go.sum` is required when the module has external dependencies.

## When `go.sum` is not required

`sloppy-joe` does not block on a missing `go.sum` when either of these is true:

- the module has no external dependencies
- every required dependency is replaced with a local path via `replace`

That exception exists because `go.sum` is not a classic lockfile. It is checksum data, and the Go module reference allows it to be empty or absent in valid cases.

## Why the rule exists

When a Go module depends on external code, `go.sum` is the project-local record of the dependency checksums the Go toolchain verified. If it is missing, the scan cannot treat dependency verification as locked-down project state.

## Fix

Run:

```bash
go mod tidy
```

Then commit the updated `go.sum`.

## Notes

- `go.mod` remains the version-selection source.
- `go.sum` is still important for integrity, even though it is not a traditional lockfile.
