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

impl ProjectInputKind {
    pub(crate) fn is_python(self) -> bool {
        matches!(
            self,
            Self::PyProjectPoetry
                | Self::PyProjectUv
                | Self::PyRequirements
                | Self::PyRequirementsTrusted
                | Self::PyProjectLegacy
                | Self::PyPipfile
                | Self::PySetupPy
                | Self::PySetupCfg
        )
    }

    /// The ecosystem this project installs from, known even when the manifest
    /// declares no dependencies (its lockfile may still list packages).
    pub(crate) fn ecosystem(self) -> Ecosystem {
        match self {
            Self::Npm => Ecosystem::Npm,
            Self::Cargo => Ecosystem::Cargo,
            Self::Go => Ecosystem::Go,
            Self::Ruby => Ecosystem::Ruby,
            Self::Php => Ecosystem::Php,
            Self::Gradle | Self::Maven => Ecosystem::Jvm,
            Self::Dotnet => Ecosystem::Dotnet,
            Self::PyProjectPoetry
            | Self::PyProjectUv
            | Self::PyRequirements
            | Self::PyRequirementsTrusted
            | Self::PyProjectLegacy
            | Self::PyPipfile
            | Self::PySetupPy
            | Self::PySetupCfg => Ecosystem::PyPI,
        }
    }

    pub(crate) fn manifest_label(self) -> &'static str {
        match self {
            Self::Npm => "package.json",
            Self::PyProjectPoetry | Self::PyProjectUv | Self::PyProjectLegacy => "pyproject.toml",
            Self::PyRequirements | Self::PyRequirementsTrusted => "requirements*.txt",
            Self::PyPipfile => "Pipfile",
            Self::PySetupPy => "setup.py",
            Self::PySetupCfg => "setup.cfg",
            Self::Cargo => "Cargo.toml",
            Self::Go => "go.mod",
            Self::Ruby => "Gemfile",
            Self::Php => "composer.json",
            Self::Gradle => "build.gradle or build.gradle.kts",
            Self::Maven => "pom.xml",
            Self::Dotnet => "*.csproj",
        }
    }

    pub(crate) fn missing_lockfile_help(&self) -> Option<&'static str> {
        match self {
            Self::Npm => Some(
                "Run `npm install --package-lock-only` or `npm shrinkwrap`, then commit the lockfile.",
            ),
            Self::Cargo => Some("Run `cargo generate-lockfile` and commit Cargo.lock."),
            Self::Go => Some("Run `go mod tidy` so Go records dependency checksums in go.sum."),
            Self::Ruby => Some("Run `bundle lock` or `bundle install`, then commit Gemfile.lock."),
            Self::Php => {
                Some("Run `composer update` or `composer install`, then commit composer.lock.")
            }
            Self::Gradle => Some(
                "Enable Gradle dependency locking and run `./gradlew dependencies --write-locks`, then commit gradle.lockfile.",
            ),
            Self::Dotnet => {
                Some("Run `dotnet restore --use-lock-file` and commit packages.lock.json.")
            }
            Self::PyProjectPoetry => {
                Some("Run `poetry lock` and commit poetry.lock alongside pyproject.toml.")
            }
            Self::PyProjectUv => Some("Run `uv lock` and commit uv.lock alongside pyproject.toml."),
            Self::PyRequirements
            | Self::PyRequirementsTrusted
            | Self::PyProjectLegacy
            | Self::PyPipfile
            | Self::PySetupPy
            | Self::PySetupCfg
            | Self::Maven => None,
        }
    }
}
