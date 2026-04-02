# Cargo Rules

## Required inputs

- `Cargo.toml` is required.
- `Cargo.lock` is required.

If `Cargo.lock` is missing or unreadable, `sloppy-joe` blocks the scan.

## Fix

Run:

```bash
cargo generate-lockfile
```

Then commit `Cargo.lock`.
