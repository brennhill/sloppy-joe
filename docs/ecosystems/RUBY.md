# Ruby Rules

## Required inputs

- `Gemfile` is required.
- `Gemfile.lock` is required.

If `Gemfile.lock` is missing or unreadable, `sloppy-joe` blocks the scan.

## Fix

Run:

```bash
bundle lock
```

or:

```bash
bundle install
```

Then commit `Gemfile.lock`.
