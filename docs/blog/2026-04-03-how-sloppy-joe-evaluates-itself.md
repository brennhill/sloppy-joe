# How sloppy-joe evaluates its own dependencies

**April 3, 2026**

If sloppy-joe flags your dependencies, the easy answer is to add an exception and move on.

That is exactly what sloppy-joe should not do for itself.

This week we ran sloppy-joe against its own Cargo dependency graph in CI and forced it to meet the same bar it imposes on everyone else. That surfaced four different classes of findings:

- real workflow bugs
- real scanner bugs
- real policy findings
- real false positives that needed exact review

The important part was not that the scan failed. The important part was what we did next.

## The rule

When sloppy-joe flags sloppy-joe, we do **not** start by adding repo-specific exceptions.

We ask four questions in order:

1. Is this a CI or workflow bug?
2. Is this a scanner bug?
3. Is this a legitimate supply chain risk?
4. Only if the answer is "no, but the rule is still useful globally": can we justify one exact reviewed exception?

That order matters. If you skip straight to exceptions, you teach the tool to lie about its own standards.

## What failed first

The initial CI failures had nothing to do with third-party package trust.

Two separate workflow problems were causing the self-check to fail:

- CI was building with `cargo build --release --locked`, but the repo was not actually tracking a root `Cargo.lock`.
- The self-check was scanning the fixture corpus as if it were production code, so intentionally adversarial test fixtures were being treated as real dependency roots.

Both of those are workflow bugs, not package risk.

The fix was straightforward:

- track the lockfiles that CI depends on
- run self-check from an isolated temporary workspace containing only the repo's real `Cargo.toml` and `Cargo.lock`

That is the first lesson: if the tool is scanning the wrong thing, fix the scan boundary before you touch policy.

## What turned out to be a scanner bug

Once the workflow bugs were gone, sloppy-joe still blocked on one of its own direct Cargo dependencies:

```text
ERROR serde_yaml [resolution/lockfile-out-of-sync]
      'serde_yaml' is pinned to '=0.9.34' in the manifest but resolves to
      '0.9.34+deprecated' in the lockfile.
```

That looked like a real sync problem at first. It was not.

Cargo records some packages with build metadata suffixes like `+deprecated` in `Cargo.lock`. The scanner was doing raw string equality, so it treated:

- manifest: `=0.9.34`
- lockfile: `0.9.34+deprecated`

as different versions.

That was wrong. We fixed the Cargo sync and provenance logic to treat Cargo build metadata as equivalent for exact-version proof, and then added regression tests so it cannot silently come back.

This is the second lesson: when the tool is wrong, the right answer is to tighten the implementation, not to add a config exception for the symptom.

## What was not the 72-hour burn-in

The next failures were metadata findings on maintainer transfers.

This is where people often get confused.

sloppy-joe has two separate policies:

- `metadata/version-age`
- `metadata/maintainer-change`

They are not the same thing.

### Version age

This is the 72-hour burn-in:

- if a version is too new, it blocks
- after the window passes, the finding clears automatically

### Maintainer change

This is not time-based.

It fires when the publisher of a package changes between one version and the previous version. Under the current policy, that blocks indefinitely until one of three things happens:

- you move back to a pre-transfer version
- you move forward to a later release by the same new maintainer
- you add an exact reviewed exception

That means the first release after a maintainer handoff is special:

- `1.2.4` by the new maintainer blocks, because `1.2.3` was published by someone else
- `1.2.5` by the same new maintainer would no longer trigger `maintainer-change`
- but `1.2.5` would still have to pass the normal 72-hour burn-in

That policy is intentionally strict. A maintainer transfer is a real supply-chain event, not just "new version smell."

## What we learned from self-scanning

Running sloppy-joe against its own Cargo graph surfaced a set of real maintainer-transfer findings across direct and transitive dependencies:

- `colored`
- `displaydoc`
- `rustls`
- `url`
- `lazy_static`
- several ICU and crypto support crates

Those are not scanner bugs. They are the tool doing what it says it does.

But that does not automatically mean the right answer is "add exceptions."

The right question is: what standard do we want sloppy-joe to hold itself to?

Our answer is:

- prefer dependency changes over repo-specific exceptions
- if a package crossed a maintainer handoff, we should prefer either:
  - the last pre-transfer version
  - or a later post-transfer version that is no longer the first handoff release, after burn-in
- use repo-specific exceptions only as a narrow last resort

That is stricter, slower, and more honest.

## What about the similarity findings?

Self-scan also found several similarity hits on completely legitimate crates:

- `serde_yaml` vs `serde`
- `async-trait` vs `async_trait`
- `json5` vs `json`
- `tokio` vs `toio`
- `toml` vs `tml`

Some of these are obvious companion crates or benign namespace collisions. Some are valid generic heuristics that become noisy on a mature dependency set.

This is where we have to be careful.

A repo-specific exception is acceptable only if it is exact:

- exact ecosystem
- exact package
- exact candidate
- exact generator

That keeps the exception narrow enough that it does not become a hidden allowlist.

But the long-term goal is still the same: improve the algorithm so that the repo does not need special treatment if the tool can learn the distinction generically.

## The standard sloppy-joe should hold for itself

Here is the internal decision framework we ended up with:

### 1. Fix workflow bugs first

If CI is scanning the wrong files, using untracked lockfiles, or mixing fixtures into production self-checks, that is not a dependency issue. Fix the workflow.

### 2. Fix scanner bugs second

If the tool misreads valid package-manager state, fix the code and add a regression test.

### 3. Treat real supply-chain findings as real

If a dependency is genuinely too new, unresolved, or the first release after a maintainer handoff, the default answer should be to change the dependency, not to weaken the policy.

### 4. Use exact reviewed exceptions only when the remaining finding is a false positive narrow enough to justify

Not "allow this package."

Not "turn off maintainer change."

Not "suppress this ecosystem."

Only:

- one package
- one version or one similarity edge
- one exact reviewed reason

## Where this leaves us

sloppy-joe should be stricter with itself than with most repos, not looser.

If the tool cannot survive its own policy, that is a product problem. Sometimes the product problem is the scanner. Sometimes it is the workflow. Sometimes it is the dependencies. The point is to find out which one is true before muting the result.

That is what self-scanning is for.

And it is why the answer to "sloppy-joe flagged itself" should almost never be "fine, just add an exception."

It should be:

**prove the scan boundary is correct, prove the tool is correct, and then decide whether the dependency is worth the risk.**
