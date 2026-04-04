# PHP / Composer

This guide covers the current PHP / Composer support surface in `sloppy-joe`.

## Quick Start

Required project state:

- `composer.json`
- `composer.lock`

If `composer.lock` is missing, regenerate it with:

```bash
composer update
```

or:

```bash
composer install
```

Then run:

```bash
sloppy-joe check
```

## What sloppy-joe checks

- `composer.json` and `composer.lock` are required.
- `require` and `require-dev` are scanned.
- Platform requirements such as `php` and `ext-*` are ignored as package dependencies.
- Trusted transitive coverage comes from `composer.lock`.

## What blocks

- Missing or unreadable `composer.lock`.
- Custom `repositories` declarations in `composer.json`.
- Unsupported non-string dependency version declarations.

## Current limitations

- The current Composer trust model assumes the default Packagist-style registry path.
- Custom package sources fail closed instead of being modeled as trusted private repositories.

## Recommended workflow

- Commit `composer.lock`.
- Keep scanned packages on the default Composer registry path.
- If the repo depends on custom Composer repositories, expect `sloppy-joe` to block until that provenance model is implemented explicitly.
