# Ecosystem Rules

`sloppy-joe` now enforces some ecosystem-specific input rules before it scans.

- Some ecosystems are strict: missing or unreadable manifests/lockfiles block the scan.
- Some ecosystems are warning-only: the scan continues, but `sloppy-joe` tells you exact lockfile-backed verification is unavailable.
- The exact rules differ by ecosystem because package managers differ.

Current guides:

- [npm](NPM.md)
- [PyPI](PYPI.md)
- [Cargo](CARGO.md)
- [Go](GOLANG.md)
- [Ruby](RUBY.md)
- [PHP / Composer](PHP.md)
- [JVM](JVM.md)
- [.NET / NuGet](DOTNET.md)

Additional ecosystem guides can be added here as the policy surface grows.
