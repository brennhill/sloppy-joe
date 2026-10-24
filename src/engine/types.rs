use crate::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectInputKind {
    Npm,
    PyProjectPoetry,
    PyProjectUv,
    PyRequirements,
    PyRequirementsTrusted,
    PyProjectLegacy,
    PyPipfile,
    PySetupPy,
    PySetupCfg,
    Cargo,
    Go,
    Ruby,
    Php,
    Gradle,
    Maven,
    Dotnet,
}

#[derive(Clone, Debug)]
pub(crate) struct ProjectInputSpec {
    pub(crate) kind: ProjectInputKind,
    pub(crate) manifest_path: std::path::PathBuf,
    pub(crate) lockfile_path_override: Option<std::path::PathBuf>,
    pub(crate) js_binding: Option<JsProjectBinding>,
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedProject {
    pub(crate) spec: ProjectInputSpec,
    pub(crate) deps: Vec<Dependency>,
    pub(crate) python_root_extras: PythonRootExtras,
    /// Build/tooling packages (e.g. `[build-system] requires`) that no lockfile records.
    /// Scanned without lockfile reconciliation; unresolved ranges are reported as warnings.
    pub(crate) unlocked_tooling: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ParsedInput {
    pub(crate) deps: Vec<Dependency>,
    pub(crate) warnings: Vec<Issue>,
    pub(crate) python_root_extras: PythonRootExtras,
    pub(crate) unlocked_tooling_deps: Vec<Dependency>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum JsPackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl JsPackageManager {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct JsProjectBinding {
    pub(crate) manager: JsPackageManager,
    pub(crate) root_manifest_path: std::path::PathBuf,
    pub(crate) lockfile_path: Option<std::path::PathBuf>,
    pub(crate) package_entry_key: String,
    pub(crate) npm_registries: npm_config::NpmRegistries,
    pub(crate) independent_from_workspace: Option<std::path::PathBuf>,
}

impl ProjectInputSpec {
    pub(crate) fn project_dir(&self) -> &std::path::Path {
        self.manifest_path
            .parent()
            .expect("manifest paths should always have a parent directory")
    }

    pub(crate) fn npm_lockfile_package_key(&self) -> &str {
        self.js_binding
            .as_ref()
            .map(|binding| binding.package_entry_key.as_str())
            .unwrap_or("")
    }
}

/// How a project kind relates to a lockfile. Every kind states one: there is no default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockfilePolicy {
    /// A lockfile must exist and be readable; scans block without it.
    Required,
    /// No trusted lockfile format exists; the scan continues with reduced confidence.
    Unsupported,
}

/// Static facts about a project kind. The one place a new kind must answer each question.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KindDescriptor {
    /// The ecosystem this project installs from, known even when the manifest
    /// declares no dependencies (its lockfile may still list packages).
    pub(crate) ecosystem: Ecosystem,
    pub(crate) manifest_label: &'static str,
    /// Package manager name; `None` for JS, where it is bound per project.
    pub(crate) manager: Option<&'static str>,
    pub(crate) lockfile: LockfilePolicy,
    /// Remedy shown when the required lockfile is missing; `Some` exactly when `lockfile` is `Required`.
    pub(crate) missing_lockfile_help: Option<&'static str>,
    /// Locked packages with no declared dependencies means declarations were missed: block.
    pub(crate) rejects_locked_packages_without_declarations: bool,
}

impl ProjectInputKind {
    #[cfg(test)]
    pub(crate) const ALL: [ProjectInputKind; 16] = [
        Self::Npm,
        Self::PyProjectPoetry,
        Self::PyProjectUv,
        Self::PyRequirements,
        Self::PyRequirementsTrusted,
        Self::PyProjectLegacy,
        Self::PyPipfile,
        Self::PySetupPy,
        Self::PySetupCfg,
        Self::Cargo,
        Self::Go,
        Self::Ruby,
        Self::Php,
        Self::Gradle,
        Self::Maven,
        Self::Dotnet,
    ];

    pub(crate) fn descriptor(self) -> KindDescriptor {
        use LockfilePolicy::{Required, Unsupported};
        let python = |manifest_label, manager, lockfile, help| KindDescriptor {
            ecosystem: Ecosystem::PyPI,
            manifest_label,
            manager: Some(manager),
            lockfile,
            missing_lockfile_help: help,
            rejects_locked_packages_without_declarations: false,
        };
        let simple = |ecosystem, manifest_label, manager, help| KindDescriptor {
            ecosystem,
            manifest_label,
            manager: Some(manager),
            lockfile: Required,
            missing_lockfile_help: Some(help),
            rejects_locked_packages_without_declarations: false,
        };
        match self {
            Self::Npm => KindDescriptor {
                ecosystem: Ecosystem::Npm,
                manifest_label: "package.json",
                manager: None,
                lockfile: Required,
                missing_lockfile_help: Some(
                    "Run `npm install --package-lock-only` or `npm shrinkwrap`, then commit the lockfile.",
                ),
                rejects_locked_packages_without_declarations: false,
            },
            Self::Cargo => simple(
                Ecosystem::Cargo,
                "Cargo.toml",
                "cargo",
                "Run `cargo generate-lockfile` and commit Cargo.lock.",
            ),
            Self::Go => simple(
                Ecosystem::Go,
                "go.mod",
                "go",
                "Run `go mod tidy` so Go records dependency checksums in go.sum.",
            ),
            Self::Ruby => simple(
                Ecosystem::Ruby,
                "Gemfile",
                "bundler",
                "Run `bundle lock` or `bundle install`, then commit Gemfile.lock.",
            ),
            Self::Php => simple(
                Ecosystem::Php,
                "composer.json",
                "composer",
                "Run `composer update` or `composer install`, then commit composer.lock.",
            ),
            Self::Gradle => KindDescriptor {
                rejects_locked_packages_without_declarations: true,
                ..simple(
                    Ecosystem::Jvm,
                    "build.gradle or build.gradle.kts",
                    "gradle",
                    "Enable Gradle dependency locking and run `./gradlew dependencies --write-locks`, then commit gradle.lockfile.",
                )
            },
            Self::Dotnet => KindDescriptor {
                rejects_locked_packages_without_declarations: true,
                ..simple(
                    Ecosystem::Dotnet,
                    "*.csproj",
                    "nuget",
                    "Run `dotnet restore --use-lock-file` and commit packages.lock.json.",
                )
            },
            Self::Maven => KindDescriptor {
                ecosystem: Ecosystem::Jvm,
                manifest_label: "pom.xml",
                manager: Some("maven"),
                lockfile: Unsupported,
                missing_lockfile_help: None,
                rejects_locked_packages_without_declarations: false,
            },
            Self::PyProjectPoetry => python(
                "pyproject.toml",
                "poetry",
                Required,
                Some("Run `poetry lock` and commit poetry.lock alongside pyproject.toml."),
            ),
            Self::PyProjectUv => python(
                "pyproject.toml",
                "uv",
                Required,
                Some("Run `uv lock` and commit uv.lock alongside pyproject.toml."),
            ),
            Self::PyProjectLegacy => python("pyproject.toml", "pip", Unsupported, None),
            Self::PyRequirements | Self::PyRequirementsTrusted => {
                python("requirements*.txt", "pip", Unsupported, None)
            }
            Self::PyPipfile => python("Pipfile", "pipenv", Unsupported, None),
            Self::PySetupPy => python("setup.py", "pip", Unsupported, None),
            Self::PySetupCfg => python("setup.cfg", "pip", Unsupported, None),
        }
    }

    pub(crate) fn is_python(self) -> bool {
        self.descriptor().ecosystem == Ecosystem::PyPI
    }

    pub(crate) fn ecosystem(self) -> Ecosystem {
        self.descriptor().ecosystem
    }

    pub(crate) fn manifest_label(self) -> &'static str {
        self.descriptor().manifest_label
    }

    pub(crate) fn missing_lockfile_help(&self) -> Option<&'static str> {
        self.descriptor().missing_lockfile_help
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
