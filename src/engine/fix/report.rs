//! What `fix-lockfile` found and did, per project, for people and as JSON.

use super::verify::{VersionDiff, preview};
use crate::ecosystems::fixer::{FixClass, Problem, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Outcome {
    /// `check` reports no lockfile problem.
    NothingToFix,
    /// The candidate passed every verification; nothing written (no `--write`).
    Verified,
    /// The candidate passed and was written.
    Written,
    /// The same lockfile was handled for another project of the workspace.
    Covered,
    /// Only manual commands apply.
    Guided,
    /// A problem has no safe fix, a precondition failed, or verification refused the candidate.
    Refused,
    /// The tool failed or could not run.
    Failed,
}

impl Outcome {
    pub(super) fn is_success(self) -> bool {
        matches!(
            self,
            Self::NothingToFix | Self::Verified | Self::Written | Self::Covered
        )
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct PlannedProblem {
    pub(super) name: String,
    pub(super) message: String,
    pub(super) class: &'static str,
    pub(super) command: Option<String>,
    pub(super) reason: Option<String>,
}

impl PlannedProblem {
    pub(super) fn new(problem: &Problem, verdict: &Verdict) -> Self {
        Self {
            name: problem.name.clone(),
            message: problem.message.clone(),
            class: verdict.class.as_str(),
            command: verdict.command.clone(),
            reason: verdict.reason.clone(),
        }
    }

    fn is(&self, class: FixClass) -> bool {
        self.class == class.as_str()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct ProjectFix {
    pub(super) manifest: String,
    pub(super) problems: Vec<PlannedProblem>,
    pub(super) result: Outcome,
    pub(super) reason: Option<String>,
    pub(super) command: Option<String>,
    pub(super) diff: Option<VersionDiff>,
    pub(super) written: Vec<String>,
    pub(super) removed: Vec<String>,
    pub(super) backups: Vec<String>,
}

impl ProjectFix {
    pub(super) fn new(manifest: &std::path::Path, problems: Vec<PlannedProblem>) -> Self {
        Self {
            manifest: manifest.display().to_string(),
            problems,
            result: Outcome::NothingToFix,
            reason: None,
            command: None,
            diff: None,
            written: Vec::new(),
            removed: Vec::new(),
            backups: Vec::new(),
        }
    }

    pub(super) fn refuse(&mut self, outcome: Outcome, reason: impl Into<String>) {
        self.result = outcome;
        self.reason = Some(reason.into());
    }

    /// Guided when every remaining problem has a manual command, refused otherwise.
    pub(super) fn settle_without_recipe(&mut self) {
        self.result = if self.problems.iter().any(|p| p.is(FixClass::Human)) {
            Outcome::Refused
        } else {
            Outcome::Guided
        };
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub(super) struct FixReport {
    pub(super) write: bool,
    pub(super) projects: Vec<ProjectFix>,
}

impl FixReport {
    pub(super) fn success(&self) -> bool {
        self.projects
            .iter()
            .all(|project| project.result.is_success())
    }

    pub(super) fn to_json(&self) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "write": self.write,
            "ok": self.success(),
            "projects": self.projects,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    }

    pub(super) fn to_human(&self) -> String {
        let mut out = String::new();
        if self.projects.is_empty() {
            out.push_str("No projects found.\n");
        }
        for project in &self.projects {
            render_project(&mut out, project, self.write);
        }
        out
    }
}

/// Tool output and repository names reach the terminal: control characters and the invisible
/// or reordering format characters are escaped, line breaks become indented lines.
pub(super) fn terminal_safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let invisible = matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}');
        match ch {
            '\n' => out.push_str("\n      "),
            ch if ch.is_control() || invisible => out.extend(ch.escape_default()),
            ch => out.push(ch),
        }
    }
    out
}

fn line(out: &mut String, text: impl AsRef<str>) {
    out.push_str(&terminal_safe(text.as_ref()));
    out.push('\n');
}

fn render_project(out: &mut String, project: &ProjectFix, write: bool) {
    line(out, &project.manifest);
    for problem in &project.problems {
        line(
            out,
            format!(
                "  problem [{}] {}: {}",
                problem.class, problem.name, problem.message
            ),
        );
        if let Some(command) = &problem.command {
            line(out, format!("    command: {command}"));
        }
        if let Some(reason) = &problem.reason {
            line(out, format!("    why: {reason}"));
        }
    }
    render_result(out, project, write);
}

fn summary(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::NothingToFix => "nothing to fix",
        Outcome::Verified => "verified (not written)",
        Outcome::Written => "fixed and written",
        Outcome::Covered => "handled with another project that shares its lockfile",
        Outcome::Guided => "not fixed automatically: run the commands above",
        Outcome::Refused => "refused",
        Outcome::Failed => "failed",
    }
}

fn render_result(out: &mut String, project: &ProjectFix, write: bool) {
    line(out, format!("  result: {}", summary(project.result)));
    if let Some(reason) = &project.reason {
        line(out, format!("    {reason}"));
    }
    if let Some(diff) = &project.diff {
        render_diff(out, diff);
    }
    for path in project.written.iter().chain(&project.removed) {
        line(out, format!("    changed {path}"));
    }
    for path in &project.backups {
        line(out, format!("    previous file kept as {path}"));
    }
    if project.result == Outcome::Verified && !write {
        line(out, "    Run again with --write to apply it.");
    }
}

fn render_diff(out: &mut String, diff: &VersionDiff) {
    line(
        out,
        format!(
            "  versions: {} added, {} removed, {} unchanged",
            diff.added.len(),
            diff.removed.len(),
            diff.unchanged
        ),
    );
    for package in &diff.added {
        line(out, format!("    + {package}"));
    }
    for package in &diff.removed {
        line(out, format!("    - {package}"));
    }
    if !diff.violations.is_empty() {
        line(
            out,
            format!("    not version-preserving: {}", preview(&diff.violations)),
        );
    }
}
