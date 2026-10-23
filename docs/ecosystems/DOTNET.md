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
- Publish dates for the version-age gate come from NuGet's SemVer 2.0.0 registration hive (`registration5-gz-semver2`), so SemVer 2.0.0-only packages and versions (such as `1.0.0-rc.1`) are covered. Paged registration indexes are followed (up to 128 pages). Page URLs must stay on the NuGet host under the package's own registration directory, redirects are not followed, and gzip bodies are capped (16 MiB compressed, 64 MiB decompressed); any violation, or malformed registration data, makes the package's metadata lookup fail and the scan block. Unlisted versions (NuGet's `1900-01-01` publish date) have no usable date and fail the version-age gate.

## What blocks

- Missing or unreadable `packages.lock.json`.
- Broken or unreadable `.csproj` dependency declarations.
- Explicit MSBuild imports and ancestor `Directory.Build.props`, `Directory.Build.targets`, or `Directory.Packages.props` imports.
- Namespaced package references, `PackageDownload`, and package references without `Include`.
- Empty or structurally unsupported `packages.lock.json` files.

## Current limitations

- A lockfile containing packages with no supported direct dependency declarations reports `Scan not supported` (exit 2). The scanner cannot verify that dependency graph.

- The current .NET trust model is centered on `PackageReference` plus `packages.lock.json`.
- Feed/source policy is not yet modeled as a separate first-class trust surface.

## Recommended workflow

- Commit `packages.lock.json`.
- Keep the repo on the standard `PackageReference` + lockfile workflow.
- Scan the project directory that owns the `.csproj` and its adjacent `packages.lock.json`.
