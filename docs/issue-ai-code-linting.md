# AI-generated code linting: detect hallucinated APIs, imports, and structural tells

## Problem

AI code assistants generate code with predictable failure patterns that existing linters don't catch. These aren't style issues — they're correctness and security issues specific to AI-generated code. sloppy-joe already catches hallucinated *dependencies*; this extends the same philosophy to hallucinated *code*.

## Proposed checks

### Tier 1: Hallucinated imports (closest to what sloppy-joe already does)

- **Importing packages not in requirements/lockfile.** AI writes `import pandas as pd` in a project that doesn't have pandas installed. Works on the AI's mental model, fails at runtime.
- **Importing nonexistent submodules.** `from cryptography.hazmat.primitives import aes` — plausible path, doesn't exist.
- **Importing deprecated re-exports.** Using old import paths that were removed in newer versions.
- **Mixed ecosystem patterns.** Using npm naming conventions in a Python package name (`my-package` vs `my_package`).
- **Plausible-but-nonexistent packages.** `pip install flask-redis-cache` — sounds real, Flask has Redis extensions, but this exact package doesn't exist.
- **Version ranges that never existed.** `"react": "^19.0.0"` when React 19 hasn't been released yet.

### Tier 2: Hallucinated APIs

- **Calling functions that don't exist on the installed version.** AI trained on multiple versions confidently uses `requests.get(url, timeout=30, retry=3)` — but `retry` isn't a `requests` parameter. It exists in `urllib3` which the AI confused.
- **Using removed/deprecated APIs.** `datetime.utcnow()` is deprecated since Python 3.12. AI still generates it because most training data uses it.
- **Inventing methods on real objects.** `array.flatMap()` in a Python context (it's JavaScript). `str.contains()` in Python (it's Pandas).
- **Wrong argument order/names.** `subprocess.run(shell=True, "ls")` — positional after keyword.

### Tier 3: Confident nonsense (context-aware dead reference detection)

- **Environment variables that don't exist.** AI writes `os.environ["DATABASE_REPLICATION_URL"]` — looks right, but the app only sets `DATABASE_URL`. No human would invent an env var name.
- **Config keys that don't exist.** `settings.CACHE_REPLICATION_BACKEND` — plausible Django setting, completely made up.
- **HTTP endpoints that don't exist.** AI generates `fetch('/api/v2/users/sync')` but the backend only has `/api/v1/users`.
- **Phantom feature flags.** AI introduces `if (ENABLE_NEW_FEATURE)` referencing a flag that doesn't exist anywhere in the codebase.

### Tier 4: Structural tells

- **Orphan functions.** AI writes a helper function that nothing calls. It was part of an approach the AI started, pivoted away from, but forgot to delete.
- **Copy-paste with wrong context.** Error messages that reference a different function: `"Failed to update user"` in a function that deletes orders.
- **Overly generic error handling.** `except Exception: pass` or `catch (error) { console.log(error) }` everywhere. Humans write specific handlers; AI plays it safe.
- **Redundant null checks.** Checking for null on a value that was already checked 3 lines up, or on a value that can never be null in that context.

### Tier 5: Security-specific tells

- **Hardcoding example credentials from training data.** AI writes `password = "admin123"` or `api_key = "sk-..."` because it saw those patterns in examples.
- **Copying insecure patterns from old code.** `eval()`, `shell=True`, `dangerouslySetInnerHTML` without sanitization — AI reproduces what it saw most often.
- **Made-up cryptographic constructions.** `hashlib.sha256(password + "salt")` instead of using proper KDF like bcrypt/argon2.

## Implementation approach

Tier 1 is the natural extension of sloppy-joe's existing registry infrastructure — cross-reference imports against installed packages. Tier 2 requires type stub / API signature databases. Tiers 3-4 require codebase-aware analysis (cross-referencing against `.env` files, route definitions, config schemas). Tier 5 overlaps with existing security linters but the AI-specific patterns (example creds from training data) are novel.

The core primitive across all tiers is the same: **cross-reference what the code claims to use against what actually exists** — in the registry, in the installed packages, in the type stubs, in the codebase.

## Open questions

- Should this be part of sloppy-joe or a separate tool? Tier 1 fits naturally. Tiers 2-5 are source code analysis, which is a different domain.
- Which languages first? Python and TypeScript/JavaScript have the most AI-generated code.
- How to get API signature databases? Python has typeshed. TypeScript has DefinitelyTyped. Rust has docs.rs. Go has go doc.
