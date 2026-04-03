# Config Bootstrap Direction

**Status:** Implemented  
**Date:** 2026-04-03

## Problem

`sloppy-joe` is strict about config placement for good reasons: the active policy file must live outside the repo. That security choice is correct, but the onboarding UX is still too manual:

- a generic template is not the same thing as a usable policy
- the starter config mixes example data with real security controls
- existing repos have no discovery-assisted path for seeding `internal`, trusted scopes, package roots, or candidate canonicals

The product needs a first-use flow that is both safe and fast.

## Direction

Bootstrap should become explicit instead of one generic `init` blob.

### 1. Greenfield mode

```bash
sloppy-joe init --greenfield --ecosystem <eco>
```

Purpose:
- create an opinionated starter policy for a new project
- keep defaults ecosystem-specific instead of shipping one mixed template
- avoid fake org-specific data like `@yourorg/*` unless the user explicitly supplies it

Rules:
- write outside the repo or combine with `--register`
- emit only policy that is defensible as a default for that ecosystem
- prefer warnings or reviewable suggestions over aggressive canonicals when there is no repo context

### 2. Existing repo discovery mode

```bash
sloppy-joe init --from-current
```

Purpose:
- inspect the current codebase
- seed config from what the repo already uses
- shorten adoption time for real projects

Should discover:
- likely `internal` patterns
- trusted scopes and package roots
- workspace/local-package provenance
- reviewable candidate canonical groups

Should not do silently:
- invent hard canonical policy and enforce it as fact
- mark third-party packages as `allowed` without review
- weaken security controls to “make it pass”

Output model:
- write config outside the repo
- register it automatically for the current git root
- surface discoveries as either:
  - accepted config entries
  - or review-required suggestions when confidence is lower

### 3. Neutral default template

If `init` is used without mode flags, the output should be a neutral manual template, not a disguised policy bundle with example canonicals and fake org data.

## Current recommendation

The supported safe paths are:

```bash
sloppy-joe init --register
sloppy-joe init --greenfield --ecosystem npm
sloppy-joe init --from-current
```

or, for manual placement:

```bash
sloppy-joe init > /secure/location/sloppy-joe.json
```

Never write the active config into the repo itself.
