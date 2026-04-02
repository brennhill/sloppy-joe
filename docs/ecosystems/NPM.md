# npm Rules

## Required inputs

- `package.json` is required.
- `npm-shrinkwrap.json` or `package-lock.json` is required.

If neither lockfile is present, or the effective lockfile is unreadable, `sloppy-joe` blocks the scan.

`npm-shrinkwrap.json` takes precedence over `package-lock.json`, matching npm itself.

By default, `lockfileVersion: 1` is blocked. That format comes from npm v5/v6 and is too weak for strict trust. If you must keep it temporarily, set `allow_legacy_npm_v1_lockfile: true` in config and plan a migration to a modern npm-generated lockfile.

If `package.json` declares a non-npm package manager such as pnpm or Yarn, or if foreign lockfiles like `pnpm-lock.yaml` or `yarn.lock` are present next to a shadow `package-lock.json`, `sloppy-joe` blocks the scan rather than trusting the npm lockfile.

The effective lockfile must also be in sync with `package.json`:

- the root lockfile dependency sections must match the manifest exactly
- direct sections include `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`
- a populated lockfile with an empty manifest blocks the scan
- npm alias entries must resolve to the same underlying package identity in both files
- npm `overrides` currently block the scan. They change the resolved graph, and sloppy-joe does not yet have strict override verification.

## Direct dependency policy

- `optionalDependencies` and `peerDependencies` are scanned as direct inputs.
- npm alias dependencies are scanned under their published package identity, and the alias indirection is reported explicitly.
- `workspace:`, `file:`, and `link:` dependencies are not treated as registry packages.
- Those local dependency references must resolve to scanned npm projects inside the scan root.
- If a local npm reference escapes the scan root, points at a missing target, or does not resolve to a discovered local project, `sloppy-joe` blocks the scan.
- npm transitive dependencies get similarity checks even without `--deep`, because npm typosquats often hide one level down in the lockfile graph.

## Discovery notes

- Repo-root discovery follows in-repo symlinked directories, but blocks symlinks that escape the scan root.
- Directories merely named `node_modules` do not hide first-party projects during repo-root discovery.
- Installed packages inside a real npm dependency `node_modules` tree are still not treated as standalone projects unless they are checked-in npm projects with their own lockfile.

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
