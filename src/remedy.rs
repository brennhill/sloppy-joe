//! The manual fix for each lockfile problem `check` blocks on, and the error type that carries it.
//!
//! Every blocking lockfile-format or staleness error names the exact command that fixes it and the
//! minimum tool version, and points at `sloppy-joe fix-lockfile`. The error is a
//! [`LockfileProblem`], so `fix-lockfile` reads the remedy from the error instead of matching
//! message text: an error without one is a problem it has no fix for (fail closed).
//! See docs/specs/fix-lockfile.md.

use std::fmt;

/// How `fix-lockfile` treats a problem with this remedy. The plugin may still refuse a `Tool`
/// remedy when a precondition fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Automation {
    /// `fix-lockfile` can run the command in a scratch copy and verify the result.
    Tool,
    /// `fix-lockfile` only prints the command; the text says why it does not run it.
    Manual(&'static str),
    /// No command is safe to run: a person must decide. The text says why.
    Decision(&'static str),
}

/// The manual fix for one lockfile problem.
#[derive(Debug, PartialEq, Eq)]
pub struct Remedy {
    /// Stable identifier shown in `fix-lockfile` output.
    pub id: &'static str,
    /// The exact command, as a person would type it.
    pub command: &'static str,
    /// The tool and minimum version the command needs, e.g. `pnpm 9.0`; empty when no tool runs.
    pub min_version: &'static str,
    pub automation: Automation,
}

impl Remedy {
    /// The `Fix:` sentence appended to a blocking error.
    pub fn fix_text(&self) -> String {
        format!("Fix: {}", self.instruction())
    }

    /// The instruction as a sentence of its own, for an issue's `fix` field.
    pub fn sentence(&self) -> String {
        let instruction = self.instruction();
        let mut chars = instruction.chars();
        match chars.next() {
            Some(first) => first.to_uppercase().chain(chars).collect(),
            None => instruction,
        }
    }

    fn instruction(&self) -> String {
        let needs = if self.min_version.is_empty() {
            String::new()
        } else {
            format!(" (needs {} or later)", self.min_version)
        };
        match self.automation {
            Automation::Tool => format!(
                "run `{}`{needs} and commit the result, or run `sloppy-joe fix-lockfile`, which runs it in a scratch copy when that is safe and shows the verified version diff before anything is written.",
                self.command
            ),
            Automation::Manual(why) => format!(
                "run `{}`{needs}, review the diff and commit the result. `sloppy-joe fix-lockfile` explains the plan but does not run it: {why}.",
                self.command
            ),
            Automation::Decision(why) => format!(
                "{}. `sloppy-joe fix-lockfile` will not change this automatically: {why}.",
                self.command
            ),
        }
    }
}

pub const NPM_LOCKFILE: Remedy = Remedy {
    id: "npm-lockfile",
    command: "npm install --package-lock-only --ignore-scripts",
    min_version: "npm 7.0",
    automation: Automation::Tool,
};

pub const NPM_LOCKFILE_UPGRADE: Remedy = Remedy {
    id: "npm-lockfile-upgrade",
    command: "npm install --package-lock-only --ignore-scripts --lockfile-version 3",
    min_version: "npm 8.1.2",
    automation: Automation::Tool,
};

pub const PNPM_LOCKFILE: Remedy = Remedy {
    id: "pnpm-lockfile",
    command: "pnpm install --lockfile-only --ignore-scripts --ignore-pnpmfile",
    min_version: "pnpm 9.0",
    automation: Automation::Tool,
};

pub const BUN_LOCKFILE: Remedy = Remedy {
    id: "bun-lockfile",
    command: "bun install --lockfile-only --ignore-scripts",
    min_version: "bun 1.1.43",
    automation: Automation::Tool,
};

pub const BUN_BINARY_LOCKFILE: Remedy = Remedy {
    id: "bun-binary-lockfile",
    command: "bun install --save-text-lockfile --frozen-lockfile --lockfile-only --ignore-scripts",
    min_version: "bun 1.1.43",
    automation: Automation::Tool,
};

pub const YARN_BERRY_LOCKFILE: Remedy = Remedy {
    id: "yarn-berry-lockfile",
    command: "yarn install --mode=update-lockfile",
    min_version: "Yarn 3.0",
    automation: Automation::Tool,
};

pub const YARN_CLASSIC_LOCKFILE: Remedy = Remedy {
    id: "yarn-classic-lockfile",
    command: "yarn install --ignore-scripts",
    min_version: "Yarn 1.22",
    automation: Automation::Manual(
        "Yarn Classic has no lockfile-only mode, so it downloads and links every package, and migrating to Yarn Berry changes the package manager, which is your decision",
    ),
};

pub const JS_SHADOW_LOCKFILE: Remedy = Remedy {
    id: "js-shadow-lockfile",
    command: "delete the lockfile under the workspace member and keep the workspace root lockfile",
    min_version: "",
    automation: Automation::Tool,
};

pub const JS_DEPENDENCY_REWRITE: Remedy = Remedy {
    id: "js-dependency-rewrite",
    command: "remove the overrides, resolutions, pnpm settings or patchedDependencies, or review this project with another control",
    min_version: "",
    automation: Automation::Decision(
        "they rewrite the dependency graph in ways the scanner cannot verify, so regenerating the lockfile would bake in an unverified rewrite",
    ),
};

pub const LOCK_PIN_MISMATCH: Remedy = Remedy {
    id: "lock-pin-mismatch",
    command: "decide whether the manifest or the lockfile holds the right version, then change the other to match",
    min_version: "",
    automation: Automation::Decision(
        "which side is right is a decision, not a format fix, and regenerating would silently pick one",
    ),
};

pub const CARGO_GENERATE_LOCKFILE: Remedy = Remedy {
    id: "cargo-generate-lockfile",
    command: "cargo generate-lockfile",
    min_version: "cargo 1.50",
    automation: Automation::Tool,
};

pub const CARGO_UPDATE_WORKSPACE: Remedy = Remedy {
    id: "cargo-update-workspace",
    command: "cargo update --workspace",
    min_version: "cargo 1.50",
    automation: Automation::Tool,
};

pub const COMPOSER_LOCK: Remedy = Remedy {
    id: "composer-lock",
    command: "composer update --lock --no-install --no-scripts --no-plugins",
    min_version: "Composer 2.0",
    automation: Automation::Tool,
};

pub const COMPOSER_LOCK_MISSING: Remedy = Remedy {
    id: "composer-lock-missing",
    command: "composer update --no-install --no-scripts --no-plugins",
    min_version: "Composer 2.0",
    automation: Automation::Tool,
};

pub const POETRY_LOCK: Remedy = Remedy {
    id: "poetry-lock",
    command: "poetry lock --no-plugins",
    min_version: "Poetry 2.0",
    automation: Automation::Tool,
};

pub const UV_LOCK: Remedy = Remedy {
    id: "uv-lock",
    command: "uv lock --no-build",
    min_version: "uv 0.3",
    automation: Automation::Tool,
};

pub const GO_SUM: Remedy = Remedy {
    id: "go-sum",
    command: "go mod download all",
    min_version: "Go 1.21",
    automation: Automation::Tool,
};

pub const PIPENV_LOCK: Remedy = Remedy {
    id: "pipenv-lock",
    command: "pipenv lock",
    min_version: "pipenv 2022.1",
    automation: Automation::Manual(
        "pipenv lock re-resolves every package, so it does not keep the locked versions",
    ),
};

pub const PIP_COMPILE_HASHES: Remedy = Remedy {
    id: "pip-compile-hashes",
    command: "pip-compile --generate-hashes",
    min_version: "pip-tools 6.0",
    automation: Automation::Manual(
        "pip-compile runs a resolution that may build source distributions, which executes their code",
    ),
};

pub const BUNDLE_LOCK: Remedy = Remedy {
    id: "bundle-lock",
    command: "bundle lock",
    min_version: "Bundler 2.0",
    automation: Automation::Manual(
        "Bundler evaluates the Gemfile as Ruby, which executes repository code",
    ),
};

pub const GRADLE_WRITE_LOCKS: Remedy = Remedy {
    id: "gradle-write-locks",
    command: "gradle dependencies --write-locks",
    min_version: "Gradle 6.0",
    automation: Automation::Manual("Gradle executes the build scripts, which are repository code"),
};

pub const DOTNET_RESTORE_LOCK: Remedy = Remedy {
    id: "dotnet-restore-lock",
    command: "dotnet restore --use-lock-file",
    min_version: ".NET SDK 5.0",
    automation: Automation::Manual(
        "restore evaluates MSBuild targets from the repository, which executes repository code",
    ),
};

/// Every remedy, for the tests that hold each one to the message contract.
#[cfg(test)]
pub const ALL: &[&Remedy] = &[
    &NPM_LOCKFILE,
    &NPM_LOCKFILE_UPGRADE,
    &PNPM_LOCKFILE,
    &BUN_LOCKFILE,
    &BUN_BINARY_LOCKFILE,
    &YARN_BERRY_LOCKFILE,
    &YARN_CLASSIC_LOCKFILE,
    &JS_SHADOW_LOCKFILE,
    &JS_DEPENDENCY_REWRITE,
    &LOCK_PIN_MISMATCH,
    &CARGO_GENERATE_LOCKFILE,
    &CARGO_UPDATE_WORKSPACE,
    &COMPOSER_LOCK,
    &COMPOSER_LOCK_MISSING,
    &POETRY_LOCK,
    &UV_LOCK,
    &GO_SUM,
    &PIPENV_LOCK,
    &PIP_COMPILE_HASHES,
    &BUNDLE_LOCK,
    &GRADLE_WRITE_LOCKS,
    &DOTNET_RESTORE_LOCK,
];

/// The remedy for a direct dependency missing from the lockfile named `lockfile` (a file name or
/// path). `None` for lockfiles whose regeneration depends on more than the file name.
pub fn for_missing_entry(lockfile: &str) -> Option<&'static Remedy> {
    let name = lockfile.rsplit(['/', '\\']).next().unwrap_or(lockfile);
    Some(match name {
        "package-lock.json" | "npm-shrinkwrap.json" => &NPM_LOCKFILE,
        "pnpm-lock.yaml" => &PNPM_LOCKFILE,
        "bun.lock" => &BUN_LOCKFILE,
        "Cargo.lock" => &CARGO_UPDATE_WORKSPACE,
        "composer.lock" => &COMPOSER_LOCK,
        "poetry.lock" => &POETRY_LOCK,
        "uv.lock" => &UV_LOCK,
        "Pipfile.lock" => &PIPENV_LOCK,
        "Gemfile.lock" => &BUNDLE_LOCK,
        "gradle.lockfile" => &GRADLE_WRITE_LOCKS,
        "packages.lock.json" => &DOTNET_RESTORE_LOCK,
        _ => return None,
    })
}

/// A blocking lockfile error that carries its remedy. Displays as the full message.
#[derive(Debug)]
pub struct LockfileProblem {
    pub remedy: &'static Remedy,
    message: String,
}

impl fmt::Display for LockfileProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LockfileProblem {}

/// The error for a lockfile problem: `message` followed by the remedy's `Fix:` sentence.
pub fn problem(remedy: &'static Remedy, message: impl fmt::Display) -> anyhow::Error {
    anyhow::Error::new(LockfileProblem {
        remedy,
        message: format!("{message} {}", remedy.fix_text()),
    })
}

/// The remedy an error carries, searching its whole cause chain.
pub fn find(error: &anyhow::Error) -> Option<&'static Remedy> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<LockfileProblem>())
        .map(|problem| problem.remedy)
}

/// Rewrap `error` with a new message built from it, keeping its remedy when it has one.
pub fn rewrap(error: anyhow::Error, message: impl FnOnce(&anyhow::Error) -> String) -> anyhow::Error {
    let text = message(&error);
    match find(&error) {
        Some(remedy) => anyhow::Error::new(LockfileProblem {
            remedy,
            message: text,
        }),
        None => anyhow::anyhow!(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fix_text_names_the_command_the_version_and_fix_lockfile() {
        for remedy in ALL {
            let text = remedy.fix_text();
            assert!(text.contains(remedy.command), "{text}");
            assert!(text.contains("sloppy-joe fix-lockfile"), "{text}");
            if !remedy.min_version.is_empty() {
                assert!(text.contains(remedy.min_version), "{text}");
            }
        }
    }

    #[test]
    fn remedy_ids_are_unique() {
        let mut ids: Vec<_> = ALL.iter().map(|remedy| remedy.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ALL.len());
    }

    #[test]
    fn the_remedy_survives_context_and_rewrap() {
        let error = problem(&PNPM_LOCKFILE, "pnpm-lock.yaml is old.");
        assert_eq!(find(&error), Some(&PNPM_LOCKFILE));
        let wrapped = error.context("while reading");
        assert_eq!(find(&wrapped), Some(&PNPM_LOCKFILE));
        let rewrapped = rewrap(wrapped, |inner| format!("Broken manifest: {inner:#}"));
        assert_eq!(find(&rewrapped), Some(&PNPM_LOCKFILE));
        assert!(rewrapped.to_string().starts_with("Broken manifest: while reading"));
        let plain = rewrap(anyhow::anyhow!("other"), |inner| format!("x: {inner}"));
        assert_eq!(find(&plain), None);
    }

    #[test]
    fn missing_entry_remedies_follow_the_lockfile_name() {
        assert_eq!(for_missing_entry("a/b/pnpm-lock.yaml"), Some(&PNPM_LOCKFILE));
        assert_eq!(for_missing_entry("Cargo.lock"), Some(&CARGO_UPDATE_WORKSPACE));
        assert_eq!(for_missing_entry("yarn.lock"), None);
    }
}
