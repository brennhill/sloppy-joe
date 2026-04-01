# npm Rules

## Required inputs

- `package.json` is required.
- `package-lock.json` or `npm-shrinkwrap.json` is required.

If neither lockfile is present, or the lockfile is unreadable, `sloppy-joe` blocks the scan.

## Fix

Run one of:

```bash
npm install --package-lock-only
```

or:

```bash
npm shrinkwrap
```

Then commit the generated lockfile.
