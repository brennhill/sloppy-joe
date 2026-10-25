//! `sloppy-joe fix-lockfile` (docs/specs/fix-lockfile.md): plan every lockfile problem `check`
//! blocks on, run the safe automatic fixes in a scratch copy, prove the candidate keeps every
//! locked version and passes `check --full`, and write it only with `--write`. The flow names no
//! ecosystem: plugins answer `EcosystemSupport::lockfile_fixer`.

mod apply;
mod cli;
mod execute;
mod problems;
mod report;
mod runner;
mod scratch;
mod verify;
mod write;

pub use cli::{FixLockfileArgs, run_fix_lockfile};

use crate::ecosystems::fixer::FixCtx;
use crate::*;
use problems::discover;
use report::{FixReport, Outcome, PlannedProblem, ProjectFix};
use runner::ProcessRunner;
use std::path::PathBuf;
use std::time::Duration;
use verify::CandidateScanner;

/// Why a step refused, as shown to the user.
type Refusal = String;

/// One `fix-lockfile` run.
struct FixRequest {
    pub(super) dir: PathBuf,
    pub(super) project_type: Option<String>,
    pub(super) config: config::SloppyJoeConfig,
    pub(super) write: bool,
    /// Where scratch directories are created (the system temp directory).
    pub(super) scratch_parent: PathBuf,
    /// How long one tool run may take.
    pub(super) timeout: Duration,
}

/// Plan and, where safe, fix every project under `request.dir`.
async fn fix_lockfiles(
    request: &FixRequest,
    runner: &dyn ProcessRunner,
    rescan: &dyn CandidateScanner,
) -> Result<FixReport> {
    let discovered = discover(&request.dir, request.project_type.as_deref(), &request.config)?;
    let ctx = FixCtx {
        scan_root: &request.dir,
        config: &request.config,
        specs: &discovered.specs,
    };
    let mut report = FixReport {
        write: request.write,
        projects: Vec::new(),
    };
    // Projects that share a lockfile (workspace members) get one fix.
    let mut handled: Vec<(Vec<PathBuf>, String, Outcome)> = Vec::new();
    for spec in &discovered.specs {
        let problems = discovered.problems(spec, &request.config);
        let mut project = ProjectFix::new(&spec.manifest_path, Vec::new());
        if problems.is_empty() {
            report.projects.push(project);
            continue;
        }
        let plan = match ecosystems::lockfile_fixer(&ctx, spec, &problems) {
            Ok(plan) => plan,
            Err(err) => {
                project.problems = problems
                    .iter()
                    .map(|problem| PlannedProblem::new(problem, &ecosystems::fixer::Verdict::human("the fix could not be planned")))
                    .collect();
                project.refuse(Outcome::Failed, format!("could not plan a fix: {err:#}"));
                report.projects.push(project);
                continue;
            }
        };
        project.problems = plan
            .problems
            .iter()
            .zip(&plan.verdicts)
            .map(|(problem, verdict)| PlannedProblem::new(problem, verdict))
            .collect();
        let Some(recipe) = plan.recipe else {
            project.settle_without_recipe();
            report.projects.push(project);
            continue;
        };
        let key: Vec<PathBuf> = recipe.outputs.iter().chain(&recipe.deletions).cloned().collect();
        if let Some((_, manifest, outcome)) = handled.iter().find(|(done, _, _)| *done == key) {
            project.command = Some(recipe.display.clone());
            if outcome.is_success() {
                project.result = Outcome::Covered;
                project.reason = Some(format!("fixed with {manifest}"));
            } else {
                project.refuse(*outcome, format!("the shared lockfile fix for {manifest} did not succeed"));
            }
            report.projects.push(project);
            continue;
        }
        if let Err(err) = discovered.policy_check(spec, &request.config) {
            project.command = Some(recipe.display.clone());
            project.refuse(
                Outcome::Refused,
                format!("the project does not pass the scanner's policy, so its tool is not run: {err:#}"),
            );
        } else {
            execute::Execution {
                request,
                discovered: &discovered,
                spec,
                recipe: &recipe,
                runner,
                rescan,
            }
            .run(&mut project)
            .await;
        }
        handled.push((key, project.manifest.clone(), project.result));
        report.projects.push(project);
    }
    Ok(report)
}

#[cfg(test)]
#[path = "fix_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "catalog_js_tests.rs"]
mod catalog_js_tests;

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod catalog_tests;
