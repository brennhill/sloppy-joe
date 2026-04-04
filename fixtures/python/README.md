# Python Fixtures

- `poetry-pass`: trusted Poetry project with a readable `poetry.lock`
- `uv-pass`: trusted uv project with a readable `uv.lock`
- `uv-stale-fail`: uv project whose `uv.lock` is stale relative to `pyproject.toml`
- `uv-schema-fail`: uv project whose `uv.lock` uses an unsupported schema
- `pip-tools-pass`: trusted pip-tools requirements file with exact pins and full hash coverage
- `pip-tools-missing-hash-fail`: requirements file that stays legacy because one pinned package is missing hashes
- `pip-tools-nonexact-fail`: requirements file that stays legacy because a package is not pinned exactly
- `requirements-warn-pass`: legacy `requirements.txt` project that should scan with warnings
- `direct-url-fail`: direct URL dependency that must fail closed
