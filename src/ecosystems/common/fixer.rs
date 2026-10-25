//! What `fix-lockfile` asks an ecosystem plugin, and the classification every plugin shares
//! (docs/specs/fix-lockfile.md). A plugin answers [`EcosystemSupport::lockfile_fixer`]: which of
//! a project's problems it can fix, the exact command, and the files and environment the command
//! needs. The engine owns everything generic: the scratch copy, running the tool, the version
//! diff, the rescan and the write.

use super::super::*;
use crate::remedy::{Automation, Remedy};
use std::collections::HashSet;

pub(crate) use crate::lockfiles::LockedPackage;

/// One problem `check` reports for a project, as the fixer plans it.
#[derive(Debug, Clone)]
pub(crate) struct Problem {
    /// The `check` name of an issue, or the remedy id of a blocking error, or `preflight`.
    pub(crate) name: String,
    pub(crate) message: String,
    /// The fix the error carries (see `crate::remedy`), or the plugin's fix for the issue.
    pub(crate) remedy: Option<&'static Remedy>,
    /// The check name when the problem is an issue rather than a blocking error.
    pub(crate) check: Option<String>,
}

impl Problem {
    /// A blocking error; its remedy (if any) comes from the error itself.
    pub(crate) fn from_error(error: &anyhow::Error) -> Self {
        let remedy = crate::remedy::find(error);
        Self {
            name: remedy.map_or("preflight", |remedy| remedy.id).to_string(),
            message: format!("{error:#}"),
            remedy,
            check: None,
        }
    }

    pub(crate) fn from_issue(issue: &Issue) -> Self {
        Self {
            name: issue.check.clone(),
            message: issue.message.clone(),
            remedy: None,
            check: Some(issue.check.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixClass {
    /// `fix-lockfile` runs the command in a scratch copy and verifies the result.
    Fixable,
    /// The manual command is shown; automation is refused with the reason.
    Guided,
    /// No safe fix: a person must decide.
    Human,
}

impl FixClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Fixable => "fixable",
            Self::Guided => "guided",
            Self::Human => "human",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Verdict {
    pub(crate) class: FixClass,
    pub(crate) command: Option<String>,
    pub(crate) reason: Option<String>,
}

impl Verdict {
    pub(crate) fn human(reason: impl Into<String>) -> Self {
        Self {
            class: FixClass::Human,
            command: None,
            reason: Some(reason.into()),
        }
    }

    pub(crate) fn guided(command: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            class: FixClass::Guided,
            command: Some(command.into()),
            reason: Some(reason.into()),
        }
    }
}

/// The tool a recipe runs and the oldest version that supports its flags.
#[derive(Debug, Clone)]
pub(crate) struct ToolRequirement {
    /// Program name looked up on the trusted part of `PATH`.
    pub(crate) program: &'static str,
    pub(crate) min_version: (u64, u64, u64),
    /// Human form of the minimum, e.g. `pnpm 9.0`.
    pub(crate) label: &'static str,
    /// Arguments that print the version (`--version`; Go has `version`).
    pub(crate) version_args: &'static [&'static str],
}

/// An environment value for the tool. Paths are created inside the scratch directory, never in
/// the user's home or the working tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnvValue {
    Literal(String),
    /// A directory under the scratch home, created before the tool runs.
    ScratchDir(&'static str),
    /// An empty file under the scratch home, created before the tool runs.
    ScratchFile(&'static str),
    /// The absolute path of a program on the trusted part of `PATH`; the run is refused when
    /// it cannot be found.
    TrustedProgram(&'static str),
    /// A directory under the user's real home that holds installed toolchains (rustup's), passed
    /// only when it exists. Never a config or credential directory.
    UserPath(&'static str),
}

/// What a lockfile records, for the version-preservation comparison.
#[derive(Debug, Clone, Default)]
pub(crate) struct Snapshot {
    /// `false` when there is no lockfile at all.
    pub(crate) exists: bool,
    pub(crate) packages: Vec<LockedPackage>,
    /// `(name, version)` the project reaches; `None` when every package counts as reachable.
    pub(crate) reachable: Option<HashSet<(String, String)>>,
    /// Direct dependencies `(name, exact version)` the manifest declares.
    pub(crate) direct: Vec<(String, Option<String>)>,
}

/// Reads one project's lockfile into a [`Snapshot`].
pub(crate) type SnapshotFn = fn(&ProjectInputSpec) -> Result<Snapshot>;

/// How to read the lockfile the fix replaces when the scan's own parser cannot.
#[derive(Clone)]
pub(crate) enum OldSnapshot {
    /// The same reader as the candidate.
    SameAsCandidate,
    /// A reader of its own (an older format the scan does not model).
    Reader(SnapshotFn),
    /// The tool prints the old lockfile as text (`bun bun.lockb`); `parse` reads that output.
    ToolPrint {
        args: Vec<String>,
        parse: fn(&str, &ProjectInputSpec) -> Result<Snapshot>,
    },
}

/// Everything the engine needs to run one fix. Paths are in the real tree; the engine maps them
/// into the scratch copy.
#[derive(Clone)]
pub(crate) struct Recipe {
    /// The command as shown to the user.
    pub(crate) display: String,
    /// `None` for a fix that only deletes files.
    pub(crate) tool: Option<ToolRequirement>,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<(&'static str, EnvValue)>,
    /// Directory the tool runs in.
    pub(crate) workdir: PathBuf,
    /// Files copied into the scratch copy: manifests, workspace manifests, accepted tool
    /// configuration and the old lockfile.
    pub(crate) inputs: Vec<PathBuf>,
    /// Empty files created in the scratch copy so the tool accepts the manifest (Cargo needs a
    /// target); never copied from the repository.
    pub(crate) placeholders: Vec<PathBuf>,
    /// Lockfiles the tool writes; verified, then written back with `--write`.
    pub(crate) outputs: Vec<PathBuf>,
    /// Files the fix removes (a shadow lockfile under a workspace member).
    pub(crate) deletions: Vec<PathBuf>,
    pub(crate) snapshot: SnapshotFn,
    pub(crate) old_snapshot: OldSnapshot,
    /// Output text that means the tool failed even when it exits 0.
    pub(crate) failure_markers: &'static [&'static str],
    /// Whether a manifest pin the old lockfile records at another version stops the fix (the
    /// lockfile is a resolution). Off for go.sum, which is a checksum list, not a resolution.
    pub(crate) pins_must_match: bool,
}

impl Recipe {
    /// A recipe that runs nothing yet: no tool, no files, the scan's own lockfile reader.
    pub(crate) fn new(display: impl Into<String>, workdir: PathBuf) -> Self {
        Self {
            display: display.into(),
            tool: None,
            args: Vec::new(),
            env: Vec::new(),
            workdir,
            inputs: Vec::new(),
            placeholders: Vec::new(),
            outputs: Vec::new(),
            deletions: Vec::new(),
            snapshot: lockfile_data_snapshot,
            old_snapshot: OldSnapshot::SameAsCandidate,
            failure_markers: &[],
            pins_must_match: true,
        }
    }

    /// Run `program` (at least `label`, parsed as `min_version`) with `args`.
    pub(crate) fn tool(
        mut self,
        program: &'static str,
        min_version: (u64, u64, u64),
        label: &'static str,
        args: &[&str],
    ) -> Self {
        self.tool = Some(ToolRequirement {
            program,
            min_version,
            label,
            version_args: &["--version"],
        });
        self.args = args.iter().map(|arg| arg.to_string()).collect();
        self
    }

    /// Copy every file of `paths` that exists.
    pub(crate) fn inputs_if_present(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        for path in paths {
            if parsers::path_detected(&path).unwrap_or(false) && !self.inputs.contains(&path) {
                self.inputs.push(path);
            }
        }
        self
    }
}

/// Literal environment values.
pub(crate) fn literal_env(pairs: &[(&'static str, &'static str)]) -> Vec<(&'static str, EnvValue)> {
    pairs
        .iter()
        .map(|(name, value)| (*name, EnvValue::Literal(value.to_string())))
        .collect()
}

/// A plugin's answer: one verdict per problem, and the recipe when every problem is fixable.
pub(crate) struct FixPlan {
    /// The problems the verdicts belong to: the engine's, plus any the plugin found while
    /// checking its preconditions.
    pub(crate) problems: Vec<Problem>,
    pub(crate) verdicts: Vec<Verdict>,
    pub(crate) recipe: Option<Recipe>,
}

/// What a plugin needs to plan a fix.
pub(crate) struct FixCtx<'a> {
    pub(crate) scan_root: &'a Path,
    pub(crate) config: &'a config::SloppyJoeConfig,
    /// Every bound project of the scan, for workspace members that share a lockfile.
    pub(crate) specs: &'a [ProjectInputSpec],
}

const ATTACK_HIDING: &str = "regenerating the lockfile would hide a possible attack: review the finding and fix its cause by hand";

/// Checks whose findings no regeneration may touch.
pub(crate) const HUMAN_CHECKS: &[(&str, &str)] = &[
    (
        checks::names::RESOLUTION_LOCKFILE_OUT_OF_SYNC,
        "which side is right is a decision, not a format fix",
    ),
    (
        checks::names::METADATA_LOCKFILE_INTEGRITY_MISMATCH,
        ATTACK_HIDING,
    ),
    (checks::names::METADATA_TARBALL_INTEGRITY, ATTACK_HIDING),
    (checks::names::METADATA_WHEEL_INTEGRITY, ATTACK_HIDING),
    (checks::names::RESOLUTION_SOURCE_MISMATCH, ATTACK_HIDING),
    (
        checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
        ATTACK_HIDING,
    ),
    (
        checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
        ATTACK_HIDING,
    ),
    (
        checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
        ATTACK_HIDING,
    ),
    (
        checks::names::RESOLUTION_PRIVATE_REGISTRY_UNVETTED,
        ATTACK_HIDING,
    ),
];

/// Issue checks that are lockfile problems even as warnings (the fixer plans them).
pub(crate) const LOCKFILE_WARNING_CHECKS: &[&str] =
    &[crate::lockfiles::yarn::LOCKFILE_ORPHAN_ENTRIES];

/// Whether an issue belongs in the plan: everything blocking, the lockfile warnings the catalog
/// fixes, and any finding a regeneration must never touch.
pub(crate) fn planned_issue(issue: &Issue) -> bool {
    issue.severity == Severity::Error
        || LOCKFILE_WARNING_CHECKS.contains(&issue.check.as_str())
        || HUMAN_CHECKS.iter().any(|(check, _)| *check == issue.check)
}

/// Give the issue problems that a lockfile regeneration fixes (missing entries, orphans) the
/// plugin's lockfile remedy.
pub(crate) fn attach_issue_remedies(problems: &[Problem], remedy: &'static Remedy) -> Vec<Problem> {
    problems
        .iter()
        .cloned()
        .map(|mut problem| {
            let regenerates = problem.check.as_deref().is_some_and(|check| {
                check == checks::names::RESOLUTION_MISSING_LOCKFILE_ENTRY
                    || LOCKFILE_WARNING_CHECKS.contains(&check)
            });
            if problem.remedy.is_none() && regenerates {
                problem.remedy = Some(remedy);
            }
            problem
        })
        .collect()
}

/// The verdict that needs no plugin: human findings, decisions and manual-only remedies.
/// `None` means the problem has a tool remedy the plugin must decide on.
fn generic_verdict(problem: &Problem) -> Option<Verdict> {
    if let Some((_, reason)) = problem
        .check
        .as_deref()
        .and_then(|check| HUMAN_CHECKS.iter().find(|(name, _)| *name == check))
    {
        return Some(Verdict::human(*reason));
    }
    let Some(remedy) = problem.remedy else {
        return Some(Verdict::human(
            "sloppy-joe has no automatic fix for this problem; fix it by hand",
        ));
    };
    match remedy.automation {
        Automation::Decision(reason) => Some(Verdict::human(reason)),
        Automation::Manual(reason) => Some(Verdict::guided(remedy.command, reason)),
        Automation::Tool => None,
    }
}

/// Why a plugin will not run a tool remedy for this project.
pub(crate) type Refusal = String;

/// Classify `problems` and build the recipe. `recipe` is asked only for the single tool remedy of
/// a project whose every problem it fixes; it returns `Ok(None)` for a remedy this plugin does not
/// own and `Err` for a precondition refusal (the verdicts become `guided` with the reason).
pub(crate) fn plan(
    problems: &[Problem],
    recipe: impl FnOnce(&'static Remedy) -> Result<std::result::Result<Option<Recipe>, Refusal>>,
) -> Result<FixPlan> {
    let mut verdicts: Vec<Option<Verdict>> = problems.iter().map(generic_verdict).collect();
    let mut tool_remedies: Vec<&'static Remedy> = problems
        .iter()
        .zip(&verdicts)
        .filter(|(_, verdict)| verdict.is_none())
        .filter_map(|(problem, _)| problem.remedy)
        .collect();
    tool_remedies.dedup_by_key(|remedy| remedy.id);
    let blocked_elsewhere = verdicts
        .iter()
        .flatten()
        .any(|v| v.class != FixClass::Fixable);
    let outcome = match (tool_remedies.as_slice(), blocked_elsewhere) {
        ([], _) => None,
        ([_, _, ..], _) => Some(Err(
            "several different fixes are needed; apply them one at a time".to_string(),
        )),
        ([_], true) => Some(Err(
            "another problem in this project has no automatic fix, so the regenerated lockfile could never pass the rescan".to_string(),
        )),
        ([remedy], false) => Some(match recipe(remedy)? {
            Ok(Some(recipe)) => Ok(recipe),
            Ok(None) => Err("sloppy-joe has no automatic fix for this problem in this project".to_string()),
            Err(refusal) => Err(refusal),
        }),
    };
    let mut built = None;
    for (problem, verdict) in problems.iter().zip(verdicts.iter_mut()) {
        if verdict.is_some() {
            continue;
        }
        let remedy = problem.remedy.expect("tool verdicts have a remedy");
        *verdict = Some(match &outcome {
            Some(Ok(recipe)) => Verdict {
                class: FixClass::Fixable,
                command: Some(recipe.display.clone()),
                reason: None,
            },
            Some(Err(refusal)) => Verdict::guided(remedy.command, refusal.clone()),
            None => unreachable!("a tool remedy always produces an outcome"),
        });
    }
    if let Some(Ok(recipe)) = outcome {
        built = Some(recipe);
    }
    Ok(FixPlan {
        problems: problems.to_vec(),
        verdicts: verdicts
            .into_iter()
            .map(|v| v.expect("every problem has a verdict"))
            .collect(),
        recipe: built,
    })
}

/// The snapshot the scan's own parser produces for `spec`'s lockfile.
pub(crate) fn lockfile_data_snapshot(spec: &ProjectInputSpec) -> Result<Snapshot> {
    let deps = for_kind(spec.kind).parse_manifest(spec.project_dir(), spec)?;
    let direct = direct_dependencies(&deps);
    let Some(lockfile) = selected_lockfile_path(spec) else {
        return Ok(Snapshot {
            direct,
            ..Snapshot::default()
        });
    };
    if !parsers::path_detected(&lockfile)? {
        return Ok(Snapshot {
            direct,
            ..Snapshot::default()
        });
    }
    let data = lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
        spec.project_dir(),
        spec.kind.lockfile_kind(),
        &deps,
        spec.lockfile_path_override.as_deref(),
        None,
    )?;
    Ok(Snapshot {
        exists: true,
        packages: data.locked_packages()?,
        reachable: data.reachable_packages(),
        direct,
    })
}

fn direct_dependencies(deps: &[Dependency]) -> Vec<(String, Option<String>)> {
    deps.iter()
        .map(|dep| {
            let name = if dep.ecosystem == Ecosystem::PyPI {
                lockfiles::python_hashes::normalize_name(dep.package_name())
            } else {
                dep.package_name().to_string()
            };
            (name, dep.exact_version())
        })
        .collect()
}

/// Direct dependencies the manifest pins to a version the lockfile does not lock, although it
/// locks the package: which side is right is a decision, never a regeneration.
pub(crate) fn pin_mismatches(snapshot: &Snapshot) -> Vec<String> {
    snapshot
        .direct
        .iter()
        .filter_map(|(name, version)| {
            let version = version.as_ref()?;
            let locked: Vec<&str> = snapshot
                .packages
                .iter()
                .filter(|package| package.name == *name)
                .map(|package| package.version.as_str())
                .collect();
            (!locked.is_empty() && !locked.contains(&version.as_str())).then(|| {
                format!(
                    "the manifest pins {name}@{version}, the lockfile locks {}",
                    locked.join(", ")
                )
            })
        })
        .collect()
}

/// A snapshot with the manifest's direct dependencies and no lockfile, for a plugin that reads
/// the lockfile its own way.
pub(crate) fn lockfile_data_snapshot_without_lockfile(spec: &ProjectInputSpec) -> Result<Snapshot> {
    let deps = for_kind(spec.kind).parse_manifest(spec.project_dir(), spec)?;
    Ok(Snapshot {
        direct: direct_dependencies(&deps),
        ..Snapshot::default()
    })
}

/// Paths of every scanned project bound to the same lockfile as `spec` (workspace members).
pub(crate) fn projects_sharing_lockfile<'a>(
    specs: &'a [ProjectInputSpec],
    spec: &ProjectInputSpec,
) -> Vec<&'a ProjectInputSpec> {
    let lockfile = selected_lockfile_path(spec);
    specs
        .iter()
        .filter(|other| {
            other.manifest_path == spec.manifest_path
                || (lockfile.is_some() && selected_lockfile_path(other) == lockfile)
        })
        .collect()
}

#[cfg(test)]
#[path = "fixer_tests.rs"]
mod tests;
