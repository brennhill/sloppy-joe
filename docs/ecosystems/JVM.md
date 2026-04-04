# JVM

This guide covers the current JVM support surface in `sloppy-joe`: Gradle and Maven.

## Quick Start

### Gradle

Required project state:

- `build.gradle` or `build.gradle.kts`
- `gradle.lockfile`

If `gradle.lockfile` is missing, enable dependency locking and regenerate it:

```bash
./gradlew dependencies --write-locks
```

### Maven

Required project state:

- `pom.xml`

Maven scans continue in reduced-confidence mode because there is no trusted project-local lockfile path enforced today.

## What sloppy-joe checks

- Gradle and Maven manifests are both parsed for direct dependencies.
- Gradle uses `gradle.lockfile` for trusted exact version and transitive coverage.
- Maven scans the manifest and continues with warnings about reduced lockfile confidence.
- Custom Gradle repositories and local project/file dependency sources are blocked.
- Custom Maven repositories and `systemPath` dependencies are blocked.

## What blocks

### Gradle

- Missing or unreadable `gradle.lockfile`
- Custom repositories beyond `mavenCentral()`
- Local project or file dependency sources such as `project(...)`, `files(...)`, `fileTree(...)`, or `includeBuild(...)`
- Classifier-bearing dependency notation

### Maven

- Custom `<repositories>`, `<pluginRepositories>`, or equivalent namespaced repository declarations
- `systemPath` dependencies

## Current limitations

- Gradle is the only strict JVM path today.
- Maven has no trusted project-local lockfile model in `sloppy-joe` yet, so exact lockfile-backed verification is reduced-confidence there.
- Gradle custom repository and local project provenance are not modeled yet and therefore fail closed.

## Recommended workflow

- Prefer Gradle with dependency locking when you want strict JVM CI enforcement.
- If you are on Maven, expect useful manifest scanning but reduced confidence compared with Gradle.
- Keep custom repositories and local binary references out of strictly scanned JVM projects for now.
