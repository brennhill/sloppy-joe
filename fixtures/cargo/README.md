# Cargo Fixtures

- `workspace-pass`: trusted workspace/path-local Cargo project inside the scan root
- `git-dependency-fail`: git dependency that should block by default
- `registry-not-allowlisted-fail`: manifest alias plus lockfile source that should block without config allowlisting
