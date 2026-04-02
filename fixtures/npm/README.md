# npm Fixtures

Adversarial npm fixture projects used by unit tests.

Each directory contains a static project shape that represents one failure mode
or attack path. Tests load these fixtures directly instead of synthesizing every
case in code so the corpus stays inspectable.

Current cases:

- `stale-shadow-package-lock-pnpm`: pnpm project with a stale shadow `package-lock.json`
- `stale-shadow-package-lock-yarn`: Yarn project with a stale shadow `package-lock.json`
- `override-only-drift`: npm project whose `overrides` changes the resolved graph
- `v1-range-drift`: legacy npm v1 lockfile with stale ranged dependency state
- `transitive-typosquat`: transitive npm package that should trigger similarity without `--deep`
- `private-scope-typo`: typo of a repo-specific trusted npm scope
- `long-tail-combo-squat`: combo-squat against a long-tail package not present in the built-in npm top list
