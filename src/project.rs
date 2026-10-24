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

/// What discovery does with a manifest found inside an installed dependency tree (`node_modules`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstalledTreePolicy {
    /// The manifest is a project like any other.
    Scan,
    /// Installed packages are not projects, unless they carry a lockfile of their own.
    ScanWhenLocked,
    /// Never a project: it belongs to an installed dependency.
    Skip,
}

/// Static facts about a project kind. The one place a new kind must answer each question.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KindDescriptor {
    /// The ecosystem this project installs from, known even when the manifest
    /// declares no dependencies (its lockfile may still list packages).
    pub(crate) ecosystem: Ecosystem,
    pub(crate) manifest_label: &'static str,
    /// The `--type` value that selects this kind.
    pub(crate) project_type: &'static str,
    /// Manifest file names that identify this kind on their own; empty when detection is by
    /// pattern (`pyproject.toml` content, `requirements*.txt`, `*.csproj`).
    pub(crate) manifest_file_names: &'static [&'static str],
    /// Lockfile sitting next to the manifest; `None` when the lockfile is bound per project (JS),
    /// is the manifest itself, or does not exist for the kind.
    pub(crate) lockfile_name: Option<&'static str>,
    pub(crate) in_installed_tree: InstalledTreePolicy,
    /// Package manager name; `None` for JS, where it is bound per project.
    pub(crate) manager: Option<&'static str>,
    pub(crate) lockfile: LockfilePolicy,
    /// The lockfile format the lockfile reader parses for this kind.
    pub(crate) lockfile_kind: lockfiles::LockfileKind,
    /// Remedy shown when the required lockfile is missing; `Some` exactly when `lockfile` is `Required`.
    pub(crate) missing_lockfile_help: Option<&'static str>,
}

/// One row per project kind: the facts the rest of the scan reads instead of matching on the kind.
static DESCRIPTORS: [(ProjectInputKind, KindDescriptor); 16] = {
    use InstalledTreePolicy::{Scan, ScanWhenLocked, Skip};
    use LockfilePolicy::{Required, Unsupported};
    use ProjectInputKind as K;
    use lockfiles::LockfileKind::{Absent, Ecosystem as LockEcosystem, Pipfile, Uv};
    [
        (
            K::Npm,
            KindDescriptor {
                ecosystem: Ecosystem::Npm,
                manifest_label: "package.json",
                project_type: "npm",
                manifest_file_names: &["package.json"],
                lockfile_name: None,
                in_installed_tree: ScanWhenLocked,
                manager: None,
                lockfile: Required,
                lockfile_kind: LockEcosystem(Ecosystem::Npm),
                missing_lockfile_help: Some(
                    "Run `npm install --package-lock-only` or `npm shrinkwrap`, then commit the lockfile.",
                ),
            },
        ),
        (
            K::PyProjectPoetry,
            KindDescriptor {
                ecosystem: Ecosystem::PyPI,
                manifest_label: "pyproject.toml",
                project_type: "pypi",
                manifest_file_names: &[],
                lockfile_name: Some("poetry.lock"),
                in_installed_tree: Skip,
                manager: Some("poetry"),
                lockfile: Required,
                lockfile_kind: LockEcosystem(Ecosystem::PyPI),
                missing_lockfile_help: Some(
                    "Run `poetry lock` and commit poetry.lock alongside pyproject.toml.",
                ),
            },
        ),
        (
            K::PyProjectUv,
            KindDescriptor {
                ecosystem: Ecosystem::PyPI,
                manifest_label: "pyproject.toml",
                project_type: "pypi",
                manifest_file_names: &[],
                lockfile_name: Some("uv.lock"),
                in_installed_tree: Skip,
                manager: Some("uv"),
                lockfile: Required,
                lockfile_kind: Uv,
                missing_lockfile_help: Some(
                    "Run `uv lock` and commit uv.lock alongside pyproject.toml.",
                ),
            },
        ),
        (
            K::PyRequirements,
            KindDescriptor {
                ecosystem: Ecosystem::PyPI,
                manifest_label: "requirements*.txt",
                project_type: "pypi",
                manifest_file_names: &[],
                lockfile_name: None,
                in_installed_tree: Skip,
                manager: Some("pip"),
                lockfile: Unsupported,
                lockfile_kind: Absent,
                missing_lockfile_help: None,
            },
        ),
        (
            K::PyRequirementsTrusted,
            KindDescriptor {
                ecosystem: Ecosystem::PyPI,
                manifest_label: "requirements*.txt",
                project_type: "pypi",
                manifest_file_names: &[],
                lockfile_name: None,
                in_installed_tree: Skip,
                manager: Some("pip"),
                lockfile: Unsupported,
                lockfile_kind: Absent,
                missing_lockfile_help: None,
            },
        ),
        (
            K::PyProjectLegacy,
            KindDescriptor {
                ecosystem: Ecosystem::PyPI,
                manifest_label: "pyproject.toml",
                project_type: "pypi",
                manifest_file_names: &[],
                lockfile_name: None,
                in_installed_tree: Skip,
                manager: Some("pip"),
                lockfile: Unsupported,
                lockfile_kind: Absent,
                missing_lockfile_help: None,
            },
        ),
        (
            K::PyPipfile,
            KindDescriptor {
                ecosystem: Ecosystem::PyPI,
                manifest_label: "Pipfile",
                project_type: "pypi",
                manifest_file_names: &["Pipfile"],
                lockfile_name: None,
                in_installed_tree: Skip,
                manager: Some("pipenv"),
                lockfile: Unsupported,
                lockfile_kind: Pipfile,
                missing_lockfile_help: None,
            },
        ),
        (
            K::PySetupPy,
            KindDescriptor {
                ecosystem: Ecosystem::PyPI,
                manifest_label: "setup.py",
                project_type: "pypi",
                manifest_file_names: &["setup.py"],
                lockfile_name: None,
                in_installed_tree: Skip,
                manager: Some("pip"),
                lockfile: Unsupported,
                lockfile_kind: Absent,
                missing_lockfile_help: None,
            },
        ),
        (
            K::PySetupCfg,
            KindDescriptor {
                ecosystem: Ecosystem::PyPI,
                manifest_label: "setup.cfg",
                project_type: "pypi",
                manifest_file_names: &["setup.cfg"],
                lockfile_name: None,
                in_installed_tree: Skip,
                manager: Some("pip"),
                lockfile: Unsupported,
                lockfile_kind: Absent,
                missing_lockfile_help: None,
            },
        ),
        (
            K::Cargo,
            KindDescriptor {
                ecosystem: Ecosystem::Cargo,
                manifest_label: "Cargo.toml",
                project_type: "cargo",
                manifest_file_names: &["Cargo.toml"],
                lockfile_name: Some("Cargo.lock"),
                in_installed_tree: Scan,
                manager: Some("cargo"),
                lockfile: Required,
                lockfile_kind: LockEcosystem(Ecosystem::Cargo),
                missing_lockfile_help: Some("Run `cargo generate-lockfile` and commit Cargo.lock."),
            },
        ),
        (
            K::Go,
            KindDescriptor {
                ecosystem: Ecosystem::Go,
                manifest_label: "go.mod",
                project_type: "go",
                manifest_file_names: &["go.mod"],
                lockfile_name: Some("go.sum"),
                in_installed_tree: Scan,
                manager: Some("go"),
                lockfile: Required,
                lockfile_kind: LockEcosystem(Ecosystem::Go),
                missing_lockfile_help: Some(
                    "Run `go mod tidy` so Go records dependency checksums in go.sum.",
                ),
            },
        ),
        (
            K::Ruby,
            KindDescriptor {
                ecosystem: Ecosystem::Ruby,
                manifest_label: "Gemfile",
                project_type: "ruby",
                manifest_file_names: &["Gemfile"],
                lockfile_name: Some("Gemfile.lock"),
                in_installed_tree: Scan,
                manager: Some("bundler"),
                lockfile: Required,
                lockfile_kind: LockEcosystem(Ecosystem::Ruby),
                missing_lockfile_help: Some(
                    "Run `bundle lock` or `bundle install`, then commit Gemfile.lock.",
                ),
            },
        ),
        (
            K::Php,
            KindDescriptor {
                ecosystem: Ecosystem::Php,
                manifest_label: "composer.json",
                project_type: "php",
                manifest_file_names: &["composer.json"],
                lockfile_name: Some("composer.lock"),
                in_installed_tree: Scan,
                manager: Some("composer"),
                lockfile: Required,
                lockfile_kind: LockEcosystem(Ecosystem::Php),
                missing_lockfile_help: Some(
                    "Run `composer update` or `composer install`, then commit composer.lock.",
                ),
            },
        ),
        (
            K::Gradle,
            KindDescriptor {
                ecosystem: Ecosystem::Jvm,
                manifest_label: "build.gradle or build.gradle.kts",
                project_type: "jvm",
                manifest_file_names: &["build.gradle", "build.gradle.kts"],
                lockfile_name: Some("gradle.lockfile"),
                in_installed_tree: Scan,
                manager: Some("gradle"),
                lockfile: Required,
                lockfile_kind: LockEcosystem(Ecosystem::Jvm),
                missing_lockfile_help: Some(
                    "Enable Gradle dependency locking and run `./gradlew dependencies --write-locks`, then commit gradle.lockfile.",
                ),
            },
        ),
        (
            K::Maven,
            KindDescriptor {
                ecosystem: Ecosystem::Jvm,
                manifest_label: "pom.xml",
                project_type: "jvm",
                manifest_file_names: &["pom.xml"],
                lockfile_name: None,
                in_installed_tree: Scan,
                manager: Some("maven"),
                lockfile: Unsupported,
                lockfile_kind: Absent,
                missing_lockfile_help: None,
            },
        ),
        (
            K::Dotnet,
            KindDescriptor {
                ecosystem: Ecosystem::Dotnet,
                manifest_label: "*.csproj",
                project_type: "dotnet",
                manifest_file_names: &[],
                lockfile_name: Some("packages.lock.json"),
                in_installed_tree: Scan,
                manager: Some("nuget"),
                lockfile: Required,
                lockfile_kind: LockEcosystem(Ecosystem::Dotnet),
                missing_lockfile_help: Some(
                    "Run `dotnet restore --use-lock-file` and commit packages.lock.json.",
                ),
            },
        ),
    ]
};

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
        DESCRIPTORS
            .iter()
            .find(|(kind, _)| *kind == self)
            .map(|(_, descriptor)| *descriptor)
            .unwrap_or_else(|| panic!("no descriptor row for {self:?}"))
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

    pub(crate) fn lockfile_kind(self) -> lockfiles::LockfileKind {
        self.descriptor().lockfile_kind
    }

    pub(crate) fn missing_lockfile_help(&self) -> Option<&'static str> {
        self.descriptor().missing_lockfile_help
    }
}

#[cfg(test)]
#[path = "project_tests.rs"]
mod tests;
