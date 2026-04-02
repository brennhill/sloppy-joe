# PHP / Composer Rules

## Required inputs

- `composer.json` is required.
- `composer.lock` is required.

If `composer.lock` is missing or unreadable, `sloppy-joe` blocks the scan.

## Fix

Run:

```bash
composer update
```

or:

```bash
composer install
```

Then commit `composer.lock`.
