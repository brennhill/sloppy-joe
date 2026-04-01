# .NET / NuGet Rules

## Required inputs

- A project-local `.csproj` file is required.
- `packages.lock.json` is required next to that project file.

If `packages.lock.json` is missing or unreadable, `sloppy-joe` blocks the scan.

## Fix

Run:

```bash
dotnet restore --use-lock-file
```

Then commit `packages.lock.json`.
