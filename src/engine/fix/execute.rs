//! Running one recipe: scratch copy, tool, version diff, rescan, write. Every failure is a
//! refusal with its reason; nothing is written unless every check passed.

use super::problems::{Discovered, discover};
use super::report::{Outcome, ProjectFix};
use super::runner::{ProcessRunner, ToolCommand, ToolOutput, parse_version};
use super::scratch::{Scratch, copy_file};
use super::verify::{CandidateScanner, compare, preview};
use super::{FixRequest, Refusal};
use crate::ecosystems::fixer::{EnvValue, OldSnapshot, Recipe, Snapshot, ToolRequirement};
use crate::*;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Output kept from a tool, per stream; enough to explain a failure.
const OUTPUT_CAP: usize = 1024 * 1024;

/// Paths of one recipe in the real tree and in the two scratch trees.
pub(super) struct Layout {
    base: PathBuf,
    work: PathBuf,
    verify: PathBuf,
}

impl Layout {
    fn new(base: PathBuf, scratch: &Scratch) -> Self {
        Self {
            base,
            work: scratch.work(),
            verify: scratch.verify(),
        }
    }

    fn rel<'p>(&self, path: &'p Path) -> std::result::Result<&'p Path, Refusal> {
        path.strip_prefix(&self.base).map_err(|_| {
            format!(
                "{} is outside {}; fix-lockfile only copies files under the project",
                path.display(),
                self.base.display()
            )
        })
    }

    pub(super) fn in_work(&self, path: &Path) -> std::result::Result<PathBuf, Refusal> {
        Ok(self.work.join(self.rel(path)?))
    }

    pub(super) fn in_verify(&self, path: &Path) -> std::result::Result<PathBuf, Refusal> {
        Ok(self.verify.join(self.rel(path)?))
    }
}

/// The deepest directory containing the scan root and every path of the recipe.
fn common_base(scan_root: &Path, recipe: &Recipe) -> PathBuf {
    let mut base = scan_root.to_path_buf();
    let paths = recipe
        .inputs
        .iter()
        .chain(&recipe.outputs)
        .chain(&recipe.deletions)
        .chain(&recipe.placeholders)
        .chain(std::iter::once(&recipe.workdir));
    for path in paths {
        while !path.starts_with(&base) {
            if !base.pop() {
                break;
            }
        }
    }
    base
}

/// What a tool needs to run.
pub(super) struct ToolRun<'a> {
    pub(super) runner: &'a dyn ProcessRunner,
    pub(super) scratch: &'a Scratch,
    pub(super) request: &'a FixRequest,
}

impl ToolRun<'_> {
    fn env(&self, recipe_env: &[(&'static str, EnvValue)]) -> std::result::Result<Vec<(String, String)>, Refusal> {
        let home = self.scratch.home();
        let path = |rel: &str| home.join(rel).display().to_string();
        let mut env = vec![
            ("PATH".to_string(), self.runner.search_path()),
            ("HOME".to_string(), home.display().to_string()),
            ("TMPDIR".to_string(), self.scratch.tmp().display().to_string()),
            ("XDG_CONFIG_HOME".to_string(), path(".config")),
            ("XDG_CACHE_HOME".to_string(), path(".cache")),
            ("XDG_DATA_HOME".to_string(), path(".local/share")),
            ("XDG_STATE_HOME".to_string(), path(".local/state")),
            ("XDG_CONFIG_DIRS".to_string(), path(".xdg")),
            ("LANG".to_string(), "C.UTF-8".to_string()),
            ("NO_COLOR".to_string(), "1".to_string()),
            ("TERM".to_string(), "dumb".to_string()),
        ];
        for dir in [".config", ".cache", ".local/share", ".local/state", ".xdg"] {
            std::fs::create_dir_all(home.join(dir)).map_err(|e| e.to_string())?;
        }
        for (name, value) in recipe_env {
            let value = match value {
                EnvValue::Literal(text) => text.clone(),
                EnvValue::ScratchDir(rel) => {
                    std::fs::create_dir_all(home.join(rel)).map_err(|e| e.to_string())?;
                    path(rel)
                }
                EnvValue::ScratchFile(rel) => {
                    let file = home.join(rel);
                    if let Some(parent) = file.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                    std::fs::write(&file, "").map_err(|e| e.to_string())?;
                    path(rel)
                }
                EnvValue::TrustedProgram(program) => self
                    .runner
                    .locate(program)
                    .ok_or_else(|| format!("{program} is not installed on the trusted PATH"))?
                    .display()
                    .to_string(),
                EnvValue::UserPath(rel) => {
                    let Some(dir) = std::env::var_os("HOME")
                        .map(|home| PathBuf::from(home).join(rel))
                        .filter(|dir| dir.is_dir())
                    else {
                        continue;
                    };
                    dir.display().to_string()
                }
            };
            env.retain(|(existing, _)| existing != name);
            env.push((name.to_string(), value));
        }
        Ok(env)
    }

    fn run(
        &self,
        program: &Path,
        args: &[String],
        cwd: &Path,
        env: &[(String, String)],
        cap: usize,
    ) -> std::result::Result<ToolOutput, Refusal> {
        self.runner
            .run(&ToolCommand {
                program: program.to_path_buf(),
                args: args.to_vec(),
                cwd: cwd.to_path_buf(),
                env: env.to_vec(),
                timeout: self.request.timeout,
                output_cap: cap,
            })
            .map_err(|err| format!("{err:#}"))
    }

    /// The program's path after proving it is installed and new enough.
    fn checked_program(
        &self,
        tool: &ToolRequirement,
        env: &[(String, String)],
    ) -> std::result::Result<PathBuf, Refusal> {
        let program = self.runner.locate(tool.program).ok_or_else(|| {
            format!(
                "{} is not installed on the trusted PATH; {} or later is required",
                tool.program, tool.label
            )
        })?;
        let output = self.run(&program, &["--version".to_string()], &self.scratch.home(), env, 64 * 1024)?;
        let version = parse_version(&format!("{}\n{}", output.stdout, output.stderr))
            .filter(|_| output.succeeded())
            .ok_or_else(|| {
                format!(
                    "could not read the version of {}; {} or later is required",
                    tool.program, tool.label
                )
            })?;
        if version < tool.min_version {
            return Err(format!(
                "{} {}.{}.{} is too old; {} or later is required",
                tool.program, version.0, version.1, version.2, tool.label
            ));
        }
        Ok(program)
    }
}

/// Copy the recipe's inputs into the work tree and make its placeholders.
fn prepare_work(layout: &Layout, recipe: &Recipe) -> std::result::Result<(), Refusal> {
    for input in &recipe.inputs {
        copy_file(input, &layout.in_work(input)?).map_err(|e| format!("{e:#}"))?;
    }
    for placeholder in &recipe.placeholders {
        let target = layout.in_work(placeholder)?;
        if target.exists() {
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&target, "").map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The tool must not change anything but its outputs: a rewritten manifest is never written back,
/// so the candidate would describe a project that does not exist.
fn ensure_inputs_untouched(layout: &Layout, recipe: &Recipe) -> std::result::Result<(), Refusal> {
    for input in recipe
        .inputs
        .iter()
        .filter(|input| !recipe.outputs.contains(input) && !recipe.deletions.contains(input))
    {
        let original = std::fs::read(input).map_err(|e| e.to_string())?;
        let after = std::fs::read(layout.in_work(input)?).map_err(|e| e.to_string())?;
        if original != after {
            return Err(format!(
                "the tool changed {}, which fix-lockfile never writes; regenerate the lockfile by hand",
                input.display()
            ));
        }
    }
    Ok(())
}

/// The verify tree: the original inputs, the tool's outputs in place of the old lockfiles, and
/// the deletions applied.
fn build_verify_tree(layout: &Layout, recipe: &Recipe) -> std::result::Result<(), Refusal> {
    for input in &recipe.inputs {
        if recipe.deletions.contains(input) || recipe.outputs.contains(input) {
            continue;
        }
        copy_file(input, &layout.in_verify(input)?).map_err(|e| format!("{e:#}"))?;
    }
    for output in &recipe.outputs {
        let produced = layout.in_work(output)?;
        if !produced.is_file() {
            return Err(format!("the tool did not write {}", output.display()));
        }
        copy_file(&produced, &layout.in_verify(output)?).map_err(|e| format!("{e:#}"))?;
    }
    Ok(())
}

pub(super) struct Execution<'a> {
    pub(super) request: &'a FixRequest,
    pub(super) discovered: &'a Discovered,
    pub(super) spec: &'a ProjectInputSpec,
    pub(super) recipe: &'a Recipe,
    pub(super) runner: &'a dyn ProcessRunner,
    pub(super) rescan: &'a dyn CandidateScanner,
}

impl Execution<'_> {
    /// Run the recipe and record the result in `project`.
    pub(super) async fn run(&self, project: &mut ProjectFix) {
        project.command = Some(self.recipe.display.clone());
        let scratch = match Scratch::create(&self.request.scratch_parent) {
            Ok(scratch) => scratch,
            Err(err) => return project.refuse(Outcome::Failed, format!("{err:#}")),
        };
        let layout = Layout::new(common_base(&self.request.dir, self.recipe), &scratch);
        let tool = ToolRun {
            runner: self.runner,
            scratch: &scratch,
            request: self.request,
        };
        if let Err((outcome, reason)) = self.attempt(&layout, &tool, project).await {
            project.refuse(outcome, reason);
        }
        // `scratch` is dropped here, on every path, removing the copy.
    }

    async fn attempt(
        &self,
        layout: &Layout,
        tool: &ToolRun<'_>,
        project: &mut ProjectFix,
    ) -> std::result::Result<(), (Outcome, Refusal)> {
        let refuse = |reason: Refusal| (Outcome::Refused, reason);
        let fail = |reason: Refusal| (Outcome::Failed, reason);
        prepare_work(layout, self.recipe).map_err(fail)?;
        let originals = super::apply::Originals::capture(layout, self.recipe).map_err(refuse)?;
        let env = tool.env(&self.recipe.env).map_err(refuse)?;
        let program = match &self.recipe.tool {
            Some(requirement) => Some(tool.checked_program(requirement, &env).map_err(refuse)?),
            None => None,
        };
        let old = if self.recipe.outputs.is_empty() {
            None
        } else {
            Some(self.old_snapshot(layout, tool, program.as_deref(), &env).map_err(refuse)?)
        };
        if let Some(program) = &program {
            let cwd = layout.in_work(&self.recipe.workdir).map_err(fail)?;
            let output = tool.run(program, &self.recipe.args, &cwd, &env, OUTPUT_CAP).map_err(fail)?;
            self.check_output(&output).map_err(fail)?;
        }
        ensure_inputs_untouched(layout, self.recipe).map_err(refuse)?;
        build_verify_tree(layout, self.recipe).map_err(fail)?;
        let verify_root = layout.in_verify(&self.request.dir).map_err(fail)?;
        let candidate_tree = discover(&verify_root, self.request.project_type.as_deref(), &self.request.config)
            .map_err(|err| refuse(format!("the candidate could not be scanned: {err:#}")))?;
        self.ensure_no_problems_left(&candidate_tree, layout).map_err(refuse)?;
        if let Some((old, reachable)) = old {
            let candidate = self.candidate_snapshot(&candidate_tree, layout).map_err(refuse)?;
            let diff = compare(&old, reachable.as_ref(), &candidate);
            let violations = diff.violations.clone();
            project.diff = Some(diff);
            if !violations.is_empty() {
                return Err(refuse(format!(
                    "the candidate does not keep the locked versions: {}",
                    preview(&violations)
                )));
            }
        }
        self.rescan_candidate(&verify_root, tool.scratch).await.map_err(refuse)?;
        project.result = Outcome::Verified;
        if self.request.write {
            super::apply::write_candidate(layout, self.recipe, &originals, project).map_err(fail)?;
            project.result = Outcome::Written;
        }
        Ok(())
    }

    fn check_output(&self, output: &ToolOutput) -> std::result::Result<(), Refusal> {
        if output.timed_out {
            return Err(format!(
                "{} did not finish within {} seconds",
                self.recipe.display,
                self.request.timeout.as_secs()
            ));
        }
        if !output.succeeded() {
            return Err(format!(
                "{} failed (exit status {}):\n{}",
                self.recipe.display,
                output.status.map_or("none".to_string(), |code| code.to_string()),
                output.tail()
            ));
        }
        let text = format!("{}\n{}", output.stdout, output.stderr);
        if let Some(marker) = self.recipe.failure_markers.iter().find(|m| text.contains(**m)) {
            return Err(format!(
                "{} reported '{marker}', so its lockfile cannot be trusted:\n{}",
                self.recipe.display,
                output.tail()
            ));
        }
        Ok(())
    }

    /// The old lockfile's packages, and what its projects reach (`None`: everything).
    fn old_snapshot(
        &self,
        layout: &Layout,
        tool: &ToolRun<'_>,
        program: Option<&Path>,
        env: &[(String, String)],
    ) -> std::result::Result<(Snapshot, Option<HashSet<(String, String)>>), Refusal> {
        let unreadable = |err: anyhow::Error| {
            format!("the current lockfile could not be read, so version preservation cannot be proven: {err:#}")
        };
        match &self.recipe.old_snapshot {
            OldSnapshot::SameAsCandidate => {
                // Workspace members share the lockfile: a package any of them reaches is reachable.
                let sharing = crate::ecosystems::fixer::projects_sharing_lockfile(
                    &self.discovered.specs,
                    self.spec,
                );
                let snapshots = sharing
                    .into_iter()
                    .map(|spec| (self.recipe.snapshot)(spec).map_err(unreadable))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let reachable = snapshots
                    .iter()
                    .map(|snapshot| snapshot.reachable.clone())
                    .collect::<Option<Vec<_>>>()
                    .map(|sets| sets.into_iter().flatten().collect::<HashSet<_>>());
                let mut snapshots = snapshots.into_iter();
                let mut merged = snapshots.next().ok_or("no project uses this lockfile")?;
                for other in snapshots {
                    merged.direct.extend(other.direct);
                }
                Ok((merged, reachable))
            }
            OldSnapshot::Reader(read) => {
                let snapshot = read(self.spec).map_err(unreadable)?;
                let reachable = snapshot.reachable.clone();
                Ok((snapshot, reachable))
            }
            OldSnapshot::ToolPrint { args, parse } => {
                let program = program.ok_or("printing the old lockfile needs the tool")?;
                let cwd = layout.in_work(&self.recipe.workdir)?;
                let output = tool.run(program, args, &cwd, env, crate::fsutil::MAX_MANIFEST_BYTES as usize)?;
                if !output.succeeded() || output.truncated {
                    return Err(format!(
                        "the current lockfile could not be printed, so version preservation cannot be proven:\n{}",
                        output.tail()
                    ));
                }
                let snapshot = parse(&output.stdout, self.spec).map_err(unreadable)?;
                Ok((snapshot, None))
            }
        }
    }

    fn candidate_snapshot(
        &self,
        tree: &Discovered,
        layout: &Layout,
    ) -> std::result::Result<Snapshot, Refusal> {
        let manifest = layout.in_verify(&self.spec.manifest_path)?;
        let spec = tree
            .spec_for(&manifest)
            .ok_or_else(|| format!("the candidate tree has no project at {}", manifest.display()))?;
        (self.recipe.snapshot)(spec).map_err(|err| format!("the candidate lockfile could not be read: {err:#}"))
    }

    /// The scanner's preflight and lockfile stages report nothing for any project of the candidate.
    fn ensure_no_problems_left(&self, tree: &Discovered, layout: &Layout) -> std::result::Result<(), Refusal> {
        let mut left = Vec::new();
        for spec in &tree.specs {
            for problem in tree.problems(spec, &self.request.config) {
                let shown = spec
                    .manifest_path
                    .strip_prefix(&layout.verify)
                    .unwrap_or(&spec.manifest_path)
                    .display()
                    .to_string();
                left.push(format!("{shown}: {}", problem.message));
            }
        }
        if left.is_empty() {
            return Ok(());
        }
        Err(format!("the candidate still has lockfile problems: {}", preview(&left)))
    }

    async fn rescan_candidate(&self, root: &Path, scratch: &Scratch) -> std::result::Result<(), Refusal> {
        let report = self
            .rescan
            .scan(root, self.request.project_type.as_deref(), &self.request.config, &scratch.cache())
            .await
            .map_err(|err| format!("the full rescan of the candidate failed: {err:#}"))?;
        let blocking: Vec<String> = report
            .issues
            .iter()
            .filter(|issue| issue.severity == Severity::Error)
            .map(|issue| format!("{} ({}): {}", issue.package, issue.check, issue.message))
            .collect();
        if blocking.is_empty() && !report.has_incomplete_projects() {
            return Ok(());
        }
        Err(format!(
            "the full rescan (check --full) of the candidate blocks: {}",
            if blocking.is_empty() {
                "a project could not be scanned".to_string()
            } else {
                preview(&blocking)
            }
        ))
    }
}
