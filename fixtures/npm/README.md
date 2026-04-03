# npm Fixtures

Adversarial npm fixture projects used by unit tests.

Each directory contains a static project shape that represents one failure mode
or attack path. Tests load these fixtures directly instead of synthesizing every
case in code so the corpus stays inspectable.

Current cases:

- `stale-shadow-package-lock-pnpm`: pnpm project with a stale shadow `package-lock.json`
- `stale-shadow-package-lock-yarn`: Yarn project with a stale shadow `package-lock.json`
- `stale-shadow-package-lock-bun`: Bun project with a stale shadow `package-lock.json`
- `override-only-drift`: npm project whose `overrides` changes the resolved graph
- `v1-range-drift`: legacy npm v1 lockfile with stale ranged dependency state
- `transitive-typosquat`: transitive npm package that should trigger similarity without `--deep`
- `private-scope-typo`: typo of a repo-specific trusted npm scope
- `long-tail-combo-squat`: combo-squat against a long-tail package not present in the built-in npm top list
- `workspace-lock-target-mismatch`: `workspace:` dependency whose lockfile link target points at the wrong local package
- `file-lock-target-mismatch`: `file:` dependency whose lockfile link target points at the wrong local package
- `wrong-package-identity`: lockfile entry whose installed package name disagrees with the manifest identity
- `registry-url-wrong-package`: npm registry tarball URL that points at a different package than the locked identity
- `registry-url-wrong-version`: npm registry tarball URL that points at a different version than the locked identity
- `bundled-entry`: lockfile entry marked as bundled to prove bundled payloads are not trusted
