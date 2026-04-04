# Ruby

This guide covers the current Ruby / Bundler support surface in `sloppy-joe`.

## Quick Start

Required project state:

- `Gemfile`
- `Gemfile.lock`

If `Gemfile.lock` is missing, regenerate it with:

```bash
bundle lock
```

or:

```bash
bundle install
```

Then run:

```bash
sloppy-joe check
```

## What sloppy-joe checks

- `Gemfile` and `Gemfile.lock` are both required.
- Multi-line `gem` declarations are parsed.
- Registry-backed gem dependencies are scanned with lockfile-backed exact version and transitive coverage from `Gemfile.lock`.

## What blocks

- Missing or unreadable `Gemfile.lock`.
- Non-registry Gem sources in `Gemfile`, including:
  - `git:`
  - `github:`
  - `gist:`
  - `bitbucket:`
  - `gitlab:`
  - `path:`
  - `source:`

## Current limitations

- The current Ruby trust model is intentionally registry-only.
- Non-registry gem sources fail closed rather than being modeled as trusted local or VCS provenance.

## Recommended workflow

- Commit `Gemfile.lock`.
- Keep scanned gems on the default registry-backed Bundler path.
- If the project relies on git or path gems, expect `sloppy-joe` to block until Ruby provenance support grows beyond the registry-only model.
