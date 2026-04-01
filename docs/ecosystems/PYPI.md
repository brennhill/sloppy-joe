# PyPI Rules

## Required inputs

- `requirements.txt` is required.

## Lockfile policy

`sloppy-joe` does not currently enforce a single universal lockfile rule for `requirements.txt`-based Python projects.

That is deliberate: Python teams use different project-local resolution models (`requirements.txt`, pip-tools, Poetry, uv, PDM), and `sloppy-joe` does not pretend they are interchangeable.

## Recommendation

- Keep versions pinned where practical.
- Commit the resolver output your workflow actually uses.
- Treat resolution-sensitive findings with extra care if your Python workflow does not produce a stable, reviewed lock artifact.
