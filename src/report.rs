use colored::Colorize;
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataException {
    pub package: String,
    pub check: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReviewExceptionCandidate {
    pub ecosystem: String,
    pub package: String,
    pub check: String,
    pub version: String,
    pub previous_publisher: String,
    pub current_publisher: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_url: Option<String>,
    pub metadata_exception: MetadataException,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FullScanRecommendationReason {
    NoSuccessfulFullScan,
    LastFullScanStale,
    DependencyStateChanged,
    PolicyChanged,
    ManagerBindingChanged,
}

/// A single issue found during scanning. Each issue identifies a specific
/// problem with a dependency and provides actionable remediation guidance.
#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    /// The dependency name this issue applies to (e.g., "react", "@types/node").
    /// Set to "<registry>" or "<lockfile>" for infrastructure-level issues.
    pub package: String,
    /// The check that produced this issue. Use constants from `checks::names`.
    /// Format: "category" or "category/subcategory" (e.g., "existence", "metadata/version-age").
    pub check: String,
    /// Error = blocks the build, Warning = informational but does not block.
    pub severity: Severity,
    /// Human-readable description of the problem.
    pub message: String,
    /// Human-readable remediation advice.
    pub fix: String,
    /// Suggested replacement package (for canonical and similarity checks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    /// Link to the package's registry page for manual verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_url: Option<String>,
    /// "direct" or "transitive" — set by mark_source() after checks run.
    /// None defaults to direct for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Manifest identifying the independent project run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

impl Issue {
    /// Create an Issue with required fields. Optional fields default to None.
    /// Chain `.message()`, `.fix()`, `.suggestion()`, `.registry_url()` to set values.
    pub fn new(package: impl Into<String>, check: impl Into<String>, severity: Severity) -> Self {
        Issue {
            package: package.into(),
            check: check.into(),
            severity,
            message: String::new(),
            fix: String::new(),
            suggestion: None,
            registry_url: None,
            source: None,
            project: None,
        }
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = fix.into();
        self
    }

    pub fn suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    pub fn registry_url(mut self, url: impl Into<String>) -> Self {
        self.registry_url = Some(url.into());
        self
    }
}

pub(crate) fn sanitize_for_terminal(text: &str) -> String {
    text.chars().flat_map(|ch| ch.escape_default()).collect()
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectScanStatus {
    Passed,
    Blocked,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectScan {
    pub manifest_path: String,
    pub lockfile_path: Option<String>,
    pub manager: Option<String>,
    pub packages_checked: usize,
    pub status: ProjectScanStatus,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub packages_checked: usize,
    pub issues: Vec<Issue>,
    pub review_candidates: Vec<ReviewExceptionCandidate>,
    pub full_scan_reasons: Vec<FullScanRecommendationReason>,
    pub projects: Vec<ProjectScan>,
}

impl Serialize for ScanReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(
            "ScanReport",
            3 + usize::from(!self.projects.is_empty())
                + usize::from(!self.review_candidates.is_empty())
                + usize::from(!self.full_scan_reasons.is_empty()),
        )?;
        state.serialize_field("packages_checked", &self.packages_checked)?;
        state.serialize_field("issues", &self.issues)?;
        if !self.projects.is_empty() {
            state.serialize_field("projects", &self.projects)?;
        }
        if !self.review_candidates.is_empty() {
            state.serialize_field("review_candidates", &self.review_candidates)?;
        }
        state.serialize_field("full_scan_recommended", &self.full_scan_recommended())?;
        if !self.full_scan_reasons.is_empty() {
            state.serialize_field("full_scan_reasons", &self.full_scan_reasons)?;
        }
        state.end()
    }
}

impl ScanReport {
    pub fn empty() -> Self {
        ScanReport {
            packages_checked: 0,
            issues: vec![],
            review_candidates: vec![],
            full_scan_reasons: vec![],
            projects: vec![],
        }
    }

    pub fn from_issues(packages_checked: usize, issues: Vec<Issue>) -> Self {
        ScanReport {
            packages_checked,
            issues,
            review_candidates: vec![],
            full_scan_reasons: vec![],
            projects: vec![],
        }
    }

    pub fn from_issues_with_review_candidates(
        packages_checked: usize,
        issues: Vec<Issue>,
        review_candidates: Vec<ReviewExceptionCandidate>,
    ) -> Self {
        ScanReport {
            packages_checked,
            issues,
            review_candidates,
            full_scan_reasons: vec![],
            projects: vec![],
        }
    }

    pub fn full_scan_recommended(&self) -> bool {
        !self.full_scan_reasons.is_empty()
    }

    pub fn has_issues(&self) -> bool {
        !self.issues.is_empty()
    }

    pub fn has_incomplete_projects(&self) -> bool {
        self.projects
            .iter()
            .any(|project| project.status == ProjectScanStatus::Unsupported)
    }

    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| matches!(issue.severity, Severity::Error))
    }

    pub fn print_json(&self) {
        println!("{}", serde_json::to_string_pretty(self).unwrap());
    }

    pub fn print_human(&self) {
        print!("{}", self.render_human());
    }

    pub fn render_human(&self) -> String {
        let mut out = String::new();
        for project in &self.projects {
            let _ = writeln!(
                out,
                "Project: {} [{}], {} packages, {:?}",
                sanitize_for_terminal(&project.manifest_path),
                project.manager.as_deref().unwrap_or("auto"),
                project.packages_checked,
                project.status
            );
            if let Some(lockfile) = &project.lockfile_path {
                let _ = writeln!(out, "  Lockfile: {}", sanitize_for_terminal(lockfile));
            }
        }
        if self.issues.is_empty() {
            let _ = writeln!(
                out,
                "\n{}  {} packages checked, no issues found.",
                "OK".green().bold(),
                self.packages_checked
            );
        } else {
            let errors: Vec<&Issue> = self
                .issues
                .iter()
                .filter(|issue| matches!(issue.severity, Severity::Error))
                .collect();
            let warnings: Vec<&Issue> = self
                .issues
                .iter()
                .filter(|issue| matches!(issue.severity, Severity::Warning))
                .collect();

            let _ = writeln!(out);
            if !errors.is_empty() {
                let _ = writeln!(out, "{}", "ERRORS (build blocked):".red().bold());
                let _ = writeln!(out);
                for issue in &errors {
                    render_issue(&mut out, issue);
                }
            }

            if !warnings.is_empty() {
                let _ = writeln!(out, "{}", "WARNINGS (build allowed):".yellow().bold());
                let _ = writeln!(out);
                for issue in &warnings {
                    render_issue(&mut out, issue);
                }
            }

            let _ = writeln!(out, "{}", "─".repeat(60));
            let _ = writeln!(
                out,
                "{}: {} packages checked, {} {}, {} {}",
                "Summary".bold(),
                self.packages_checked,
                errors.len(),
                if errors.len() == 1 { "error" } else { "errors" },
                warnings.len(),
                if warnings.len() == 1 {
                    "warning"
                } else {
                    "warnings"
                },
            );
            if self.has_errors() {
                let _ = writeln!(
                    out,
                    "\n{}  Remove or replace the packages above before merging.",
                    "BLOCKED".red().bold()
                );
            } else {
                let _ = writeln!(
                    out,
                    "\n{}  Warnings did not block this scan, but accuracy is reduced.",
                    "WARN".yellow().bold()
                );
            }
        }

        if self.full_scan_recommended() {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", "FULL SCAN RECOMMENDED:".cyan().bold());
            let _ = writeln!(out);
            for reason in &self.full_scan_reasons {
                let _ = writeln!(out, "  - {}", full_scan_reason_message(*reason));
            }
            let _ = writeln!(out, "  Run: sloppy-joe check --full");
        }

        if !self.review_candidates.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", "REVIEW EXCEPTIONS:".cyan().bold());
            let _ = writeln!(out);
            for candidate in &self.review_candidates {
                render_review_candidate(&mut out, candidate);
            }
        }

        out
    }
}

fn render_issue(out: &mut String, issue: &Issue) {
    if let Some(project) = &issue.project {
        let _ = writeln!(out, "  Project: {}", sanitize_for_terminal(project));
    }

    let safe_package = sanitize_for_terminal(&issue.package);
    let (label, colorized_package) = match issue.severity {
        Severity::Error => ("ERROR".red().bold(), safe_package.red().bold()),
        Severity::Warning => ("WARN".yellow().bold(), safe_package.yellow().bold()),
    };

    let source_label = match issue.source.as_deref() {
        Some("transitive") => " [transitive]".dimmed().to_string(),
        _ => String::new(),
    };
    let _ = writeln!(
        out,
        "  {} {} {}{}",
        label,
        colorized_package,
        format!("[{}]", sanitize_for_terminal(&issue.check)).dimmed(),
        source_label
    );
    let _ = writeln!(out, "        {}", sanitize_for_terminal(&issue.message));
    let _ = writeln!(
        out,
        "   {}  {}",
        "Fix:".yellow().bold(),
        sanitize_for_terminal(&issue.fix)
    );
    if let Some(ref s) = issue.suggestion {
        let _ = writeln!(
            out,
            "        Replace with: {}",
            sanitize_for_terminal(s).green().bold()
        );
    }
    if let Some(ref url) = issue.registry_url {
        let _ = writeln!(
            out,
            "        Verify: {}",
            sanitize_for_terminal(url).dimmed()
        );
    }
    let _ = writeln!(out);
}

fn metadata_exception_snippet(candidate: &ReviewExceptionCandidate) -> String {
    let snippet = serde_json::json!({
        "metadata_exceptions": {
            candidate.ecosystem.clone(): [candidate.metadata_exception.clone()]
        }
    });
    serde_json::to_string_pretty(&snippet).expect("review exception snippets should serialize")
}

fn render_review_candidate(out: &mut String, candidate: &ReviewExceptionCandidate) {
    let _ = writeln!(
        out,
        "  {} {} {}",
        "CANDIDATE".cyan().bold(),
        sanitize_for_terminal(&candidate.package).cyan().bold(),
        format!("[{}]", sanitize_for_terminal(&candidate.check)).dimmed(),
    );
    let _ = writeln!(
        out,
        "        Version: {}",
        sanitize_for_terminal(&candidate.version)
    );
    let _ = writeln!(
        out,
        "        Publisher change: {} -> {}",
        sanitize_for_terminal(&candidate.previous_publisher),
        sanitize_for_terminal(&candidate.current_publisher)
    );
    if !candidate.owners.is_empty() {
        let _ = writeln!(
            out,
            "        Owners: {}",
            sanitize_for_terminal(&candidate.owners.join(", "))
        );
    }
    if let Some(url) = &candidate.repository_url {
        let _ = writeln!(
            out,
            "        Repository: {}",
            sanitize_for_terminal(url).dimmed()
        );
    }
    let _ = writeln!(out, "        Config snippet:");
    for line in metadata_exception_snippet(candidate).lines() {
        let _ = writeln!(out, "          {}", line);
    }
    let _ = writeln!(out);
}

fn full_scan_reason_message(reason: FullScanRecommendationReason) -> &'static str {
    match reason {
        FullScanRecommendationReason::NoSuccessfulFullScan => {
            "No successful full scan has been recorded yet."
        }
        FullScanRecommendationReason::LastFullScanStale => "Last full scan is older than 24 hours.",
        FullScanRecommendationReason::DependencyStateChanged => {
            "Dependency state changed since the last successful full scan."
        }
        FullScanRecommendationReason::PolicyChanged => {
            "Effective policy changed since the last successful full scan."
        }
        FullScanRecommendationReason::ManagerBindingChanged => {
            "Manager or ecosystem binding changed since the last successful full scan."
        }
    }
}

#[cfg(test)]
mod tests;
