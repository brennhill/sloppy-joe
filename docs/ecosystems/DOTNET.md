# .NET / NuGet

This guide covers the current .NET / NuGet support surface in `sloppy-joe`.

## Quick Start

Required project state:

- one or more project-local `.csproj` files
- `packages.lock.json` next to the scanned project

If the lockfile is missing, regenerate it with:

```bash
dotnet restore --use-lock-file
```

Then run:

```bash
sloppy-joe check
```

## What sloppy-joe checks

- `.csproj` files are required and parsed for `PackageReference` dependencies.
- Both self-closing and nested `<PackageReference>` forms are supported.
- `packages.lock.json` provides trusted exact version and transitive coverage.
- XML comments are stripped before dependency extraction, so commented references are not treated as real packages.

## What blocks

- Missing or unreadable `packages.lock.json`.
- Broken or unreadable `.csproj` dependency declarations.

## Current limitations

- The current .NET trust model is centered on `PackageReference` plus `packages.lock.json`.
- Feed/source policy is not yet modeled as a separate first-class trust surface.

## Recommended workflow

- Commit `packages.lock.json`.
- Keep the repo on the standard `PackageReference` + lockfile workflow.
- Scan the project directory that owns the `.csproj` and its adjacent `packages.lock.json`.
