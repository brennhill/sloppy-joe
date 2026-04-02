# JVM Rules

## Gradle vs Maven

`sloppy-joe` treats Gradle and Maven differently because the ecosystems give you different guarantees.

## Gradle

Gradle is the preferred JVM path for strict scanning.

Required inputs:

- `build.gradle` or `build.gradle.kts`
- `gradle.lockfile`

If `gradle.lockfile` is missing or unreadable, `sloppy-joe` blocks the scan.

### Fix

Enable dependency locking in the build, then run:

```bash
./gradlew dependencies --write-locks
```

Commit `gradle.lockfile`.

## Maven

Maven currently runs in warning-only mode for lockfile policy.

- `pom.xml` is still required and must be readable.
- The scan continues without a strict lockfile requirement.
- `sloppy-joe` emits a warning that exact lockfile-backed verification is unavailable.

## Recommendation

If you need strict, lockfile-backed dependency verification in CI, prefer Gradle with dependency locking.

That is not a claim that Gradle is universally better than Maven. It is a narrow operational recommendation: today, Gradle has a clear project-local lockfile model that `sloppy-joe` can enforce, while Maven does not.
