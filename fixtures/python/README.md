# Python Fixtures

- `poetry-pass`: trusted Poetry project with a readable `poetry.lock`
- `poetry-source-pass`: trusted Poetry project whose non-PyPI source is allowlisted exactly
- `poetry-source-block`: Poetry project whose locked non-PyPI source is not allowlisted
- `poetry-source-mismatch-fail`: Poetry project whose declared source intent disagrees with `poetry.lock`
- `poetry-unused-source-warn`: Poetry project that declares an unused non-PyPI source and warns only
- `uv-pass`: trusted uv project with a readable `uv.lock`
- `uv-source-pass`: trusted uv project whose non-PyPI source is allowlisted exactly
- `uv-source-block`: uv project whose locked non-PyPI source is not allowlisted
- `uv-source-mismatch-fail`: uv project whose declared source intent disagrees with `uv.lock`
- `uv-unused-source-warn`: uv project that declares an unused non-PyPI index and warns only
- `uv-stale-fail`: uv project whose `uv.lock` is stale relative to `pyproject.toml`
- `uv-schema-fail`: uv project whose `uv.lock` uses an unsupported schema
- `pip-tools-pass`: hash-locked pip-tools requirements file with exact pins and full hash coverage, but no explicit primary index, so it stays reduced-confidence
- `pip-tools-explicit-source-pass`: hash-locked pip-tools requirements file with exact pins, full hash coverage, and explicit file-bound index provenance
- `pip-tools-missing-hash-fail`: requirements file that stays legacy because one pinned package is missing hashes
- `pip-tools-nonexact-fail`: requirements file that stays legacy because a package is not pinned exactly
- `requirements-warn-pass`: legacy `requirements.txt` project that should scan with warnings
- `direct-url-fail`: direct URL dependency that must fail closed
