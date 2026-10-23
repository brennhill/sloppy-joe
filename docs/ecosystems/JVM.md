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
- Gradle `plugins {}` requests (build scripts and settings scripts) are checked as plugin marker artifacts, see below.

### Gradle plugins

A plugin request `id 'x' version 'v'` makes Gradle download the marker artifact `x:x.gradle.plugin:v` from the plugin repositories. Markers never appear in `gradle.lockfile`, so sloppy-joe scans them as unlocked build tooling against the plugin repositories themselves:

- Plugins bundled with Gradle (`java`, `application`, `maven-publish`, ...) are skipped.
- Every other request must resolve to a literal plugin id and an exact release version: an explicit `version`, `kotlin("x") version "v"`, an `alias(libs.plugins.x)` entry in `gradle/libs.versions.toml` with a literal `id` and `version` or `version.ref`, a `pluginManagement { plugins {} }` default in the settings script, or a version declared by an enclosing build script (`apply false` in the root project).
- The marker is looked up in the `pluginManagement { repositories {} }` repositories in declaration order (default: the Gradle Plugin Portal). `gradlePluginPortal()` and `mavenCentral()` are supported. The pinned version's marker POM must be published there. Its publication date feeds the version age check, and the first published version feeds the new-package check. The scan reports the marker as `<id>:<id>.gradle.plugin`, which is also the name to use in `allowed` or `internal`.
- Plugin ids that closely resemble a widely used plugin id (for example `com.diffplug.spotles`) are flagged as look-alikes.
- A custom `maven { url = "..." }` plugin repository blocks unless its exact URL is allowlisted in the out-of-repo config under `trusted_registries.jvm` with the name `gradle-plugins` (see [CONFIG.md](../../CONFIG.md#trusted_registriesjvm)). With an allowlisted repository, every plugin of that build is reported as a non-blocking `resolution/private-registry-unvetted` warning and is not checked against public repositories, because Gradle may resolve it from the private repository.

## What blocks

### Gradle

- Missing or unreadable `gradle.lockfile`
- Custom repositories beyond `mavenCentral()`, including repositories in ancestor repository-local `settings.gradle` / `settings.gradle.kts`
- Applied scripts, composite builds, dependency mutation calls, version-catalog expressions, and unsupported configurations
- Only literal coordinates in `implementation`, `api`, `compileOnly`, `runtimeOnly`, and `testImplementation` are accepted
- Local project or file dependency sources such as `project(...)`, `files(...)`, `fileTree(...)`, or `includeBuild(...)`
- Classifier-bearing dependency notation
- Plugin requests without a literal id or exact version: missing versions, `+`/`latest.*`/range/SNAPSHOT versions, interpolated or computed ids and versions, aliases from catalogs other than `libs`, rich catalog versions, and settings scripts that customize `versionCatalogs`
- Plugin repositories other than `gradlePluginPortal()`, `mavenCentral()`, and allowlisted literal `maven` URLs (`google()`, `mavenLocal()`, `ivy`, content filters, `exclusiveContent`)
- `pluginManagement { resolutionStrategy {} }` and `buildscript { dependencies { classpath ... } }`

### Maven

- Custom `<repositories>`, `<pluginRepositories>`, or equivalent namespaced repository declarations
- Namespaced or attributed `<dependency>` elements that cannot be parsed safely
- `systemPath` dependencies

## Current limitations

- A lockfile containing packages with no supported direct dependency declarations reports `Scan not supported` (exit 2). The scanner cannot verify that dependency graph.

- Gradle is the only strict JVM path today.
- Maven has no trusted project-local lockfile model in `sloppy-joe` yet, so exact lockfile-backed verification is reduced-confidence there.
- Gradle custom repository and local project provenance are not modeled yet and therefore fail closed.

## Recommended workflow

- Prefer Gradle with dependency locking when you want strict JVM CI enforcement.
- If you are on Maven, expect useful manifest scanning but reduced confidence compared with Gradle.
- Keep custom repositories and local binary references out of strictly scanned JVM projects for now.
