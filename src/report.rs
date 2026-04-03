use colored::Colorize;
use serde::Serialize;
use serde::ser::{SerializeStruct, Serializer};
use std::fmt::Write as _;

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
    pub metadata_exception: crate::config::MetadataException,
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

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub packages_checked: usize,
    pub issues: Vec<Issue>,
    pub review_candidates: Vec<ReviewExceptionCandidate>,
    pub full_scan_reasons: Vec<FullScanRecommendationReason>,
}

impl Serialize for ScanReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(
            "ScanReport",
            if self.review_candidates.is_empty() {
                4
            } else {
                5
            },
        )?;
        state.serialize_field("packages_checked", &self.packages_checked)?;
        state.serialize_field("issues", &self.issues)?;
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
        }
    }

    pub fn from_issues(packages_checked: usize, issues: Vec<Issue>) -> Self {
        ScanReport {
            packages_checked,
            issues,
            review_candidates: vec![],
            full_scan_reasons: vec![],
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
        }
    }

    pub fn full_scan_recommended(&self) -> bool {
        !self.full_scan_reasons.is_empty()
    }

    pub fn has_issues(&self) -> bool {
        !self.issues.is_empty()
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
mod tests {
    use super::*;

    #[test]
    fn issue_new_sets_required_fields() {
        let issue = Issue::new("react", "existence", Severity::Error)
            .message("not found")
            .fix("remove it");
        assert_eq!(issue.package, "react");
        assert_eq!(issue.check, "existence");
        assert_eq!(issue.severity, Severity::Error);
        assert_eq!(issue.message, "not found");
        assert_eq!(issue.fix, "remove it");
        assert!(issue.suggestion.is_none());
        assert!(issue.registry_url.is_none());
        assert!(issue.source.is_none());
    }

    #[test]
    fn issue_builder_optional_fields() {
        let issue = Issue::new("lodash", "canonical", Severity::Error)
            .message("wrong package")
            .fix("use dayjs")
            .suggestion("dayjs")
            .registry_url("https://npmjs.com/package/lodash");
        assert_eq!(issue.suggestion, Some("dayjs".to_string()));
        assert_eq!(
            issue.registry_url,
            Some("https://npmjs.com/package/lodash".to_string())
        );
    }

    #[test]
    fn issue_builder_produces_identical_struct() {
        let manual = Issue {
            package: "foo".to_string(),
            check: "test".to_string(),
            severity: Severity::Warning,
            message: "msg".to_string(),
            fix: "fix".to_string(),
            suggestion: Some("bar".to_string()),
            registry_url: None,
            source: None,
        };
        let built = Issue::new("foo", "test", Severity::Warning)
            .message("msg")
            .fix("fix")
            .suggestion("bar");
        assert_eq!(built.package, manual.package);
        assert_eq!(built.check, manual.check);
        assert_eq!(built.severity, manual.severity);
        assert_eq!(built.message, manual.message);
        assert_eq!(built.fix, manual.fix);
        assert_eq!(built.suggestion, manual.suggestion);
        assert_eq!(built.registry_url, manual.registry_url);
        assert_eq!(built.source, manual.source);
    }

    fn review_candidate() -> ReviewExceptionCandidate {
        ReviewExceptionCandidate {
            ecosystem: "cargo".to_string(),
            package: "colored".to_string(),
            check: "metadata/maintainer-change".to_string(),
            version: "2.2.0".to_string(),
            previous_publisher: "kurtlawrence".to_string(),
            current_publisher: "hwittenborn".to_string(),
            owners: vec!["mackwic".to_string(), "kurtlawrence".to_string()],
            repository_url: Some("https://github.com/mackwic/colored".to_string()),
            metadata_exception: crate::config::MetadataException {
                package: "colored".to_string(),
                check: "metadata/maintainer-change".to_string(),
                version: "2.2.0".to_string(),
                previous_publisher: Some("kurtlawrence".to_string()),
                current_publisher: Some("hwittenborn".to_string()),
                reason: Some("reviewed transfer".to_string()),
            },
        }
    }

    fn recommendation_report() -> ScanReport {
        ScanReport {
            packages_checked: 3,
            issues: vec![],
            review_candidates: vec![],
            full_scan_reasons: vec![
                FullScanRecommendationReason::NoSuccessfulFullScan,
                FullScanRecommendationReason::LastFullScanStale,
            ],
        }
    }

    #[test]
    fn has_issues_returns_false_when_empty() {
        let report = ScanReport::empty();
        assert!(!report.has_issues());
    }

    #[test]
    fn has_issues_returns_true_when_issues_exist() {
        let report = ScanReport::from_issues(
            1,
            vec![
                Issue::new("foo", "existence", Severity::Error)
                    .message("not found")
                    .fix("remove it"),
            ],
        );
        assert!(report.has_issues());
    }

    #[test]
    fn empty_creates_report_with_zero_packages() {
        let report = ScanReport::empty();
        assert_eq!(report.packages_checked, 0);
        assert!(report.issues.is_empty());
    }

    fn issue(name: &str, check: &str, severity: Severity) -> Issue {
        Issue::new(name, check, severity)
            .message("msg")
            .fix("fix it")
            .suggestion("replacement")
            .registry_url("https://example.com")
    }

    #[test]
    fn from_issues_collects_all_issue_types() {
        let mut issues = vec![issue("a", "existence", Severity::Error)];
        issues.push(issue("b", "similarity", Severity::Error));
        issues.push(issue("c", "canonical", Severity::Error));
        let report = ScanReport::from_issues(5, issues);
        assert_eq!(report.packages_checked, 5);
        assert_eq!(report.issues.len(), 3);
    }

    #[test]
    fn print_human_no_issues() {
        let report = ScanReport::empty();
        // Should not panic
        report.print_human();
    }

    #[test]
    fn print_human_with_all_issue_types() {
        let report = ScanReport::from_issues(
            3,
            vec![
                issue("a", "existence", Severity::Error),
                issue("b", "similarity", Severity::Error),
                issue("c", "canonical", Severity::Error),
            ],
        );
        // Should not panic
        report.print_human();
    }

    #[test]
    fn print_json_does_not_panic() {
        let report = ScanReport::from_issues(1, vec![issue("foo", "existence", Severity::Error)]);
        report.print_json();
    }

    #[test]
    fn report_json_includes_review_candidates() {
        let report = ScanReport::from_issues_with_review_candidates(
            1,
            vec![issue("foo", "existence", Severity::Error)],
            vec![review_candidate()],
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"review_candidates\""));
        assert!(json.contains("\"metadata_exception\""));
        assert!(json.contains("\"current_publisher\":\"hwittenborn\""));
    }

    #[test]
    fn report_json_includes_full_scan_recommendation_fields() {
        let json = serde_json::to_string(&recommendation_report()).unwrap();
        assert!(json.contains("\"full_scan_recommended\":true"));
        assert!(json.contains("\"full_scan_reasons\""));
        assert!(json.contains("\"no-successful-full-scan\""));
        assert!(json.contains("\"last-full-scan-stale\""));
    }

    #[test]
    fn report_with_full_scan_reasons_is_marked_recommended() {
        assert!(recommendation_report().full_scan_recommended());
    }

    #[test]
    fn human_output_includes_full_scan_recommended_section() {
        let output = recommendation_report().render_human();
        assert!(output.contains("FULL SCAN RECOMMENDED"));
        assert!(output.contains("sloppy-joe check --full"));
        assert!(output.contains("No successful full scan"));
        assert!(output.contains("Last full scan is older than 24 hours"));
    }

    #[test]
    fn metadata_exception_snippet_wraps_candidate_in_config_shape() {
        let snippet = metadata_exception_snippet(&review_candidate());
        assert!(snippet.contains("\"metadata_exceptions\""));
        assert!(snippet.contains("\"cargo\""));
        assert!(snippet.contains("\"colored\""));
        assert!(snippet.contains("\"metadata/maintainer-change\""));
    }

    #[test]
    fn print_human_errors_only() {
        let report =
            ScanReport::from_issues(2, vec![issue("bad-pkg", "existence", Severity::Error)]);
        report.print_human();
        assert!(report.has_issues());
    }

    #[test]
    fn print_human_similarity_errors() {
        let report =
            ScanReport::from_issues(2, vec![issue("typo-pkg", "similarity", Severity::Error)]);
        report.print_human();
        assert!(report.has_issues());
    }

    #[test]
    fn print_human_canonical_errors() {
        let mut i = issue("old-pkg", "canonical", Severity::Error);
        i.registry_url = None;
        let report = ScanReport::from_issues(2, vec![i]);
        report.print_human();
        assert!(report.has_issues());
    }

    #[test]
    fn severity_serializes_correctly() {
        let json = serde_json::to_string(&Severity::Error).unwrap();
        assert_eq!(json, "\"Error\"");
        let json = serde_json::to_string(&Severity::Warning).unwrap();
        assert_eq!(json, "\"Warning\"");
    }

    #[test]
    fn warnings_do_not_count_as_errors() {
        let report = ScanReport::from_issues(
            1,
            vec![issue(
                "pkg",
                "resolution/no-exact-version",
                Severity::Warning,
            )],
        );
        assert!(report.has_issues());
        assert!(!report.has_errors());
    }

    #[test]
    fn issue_json_includes_all_fields() {
        let i = issue("pkg", "existence", Severity::Error);
        let json = serde_json::to_string(&i).unwrap();
        assert!(json.contains("\"severity\":\"Error\""));
        assert!(json.contains("\"fix\""));
        assert!(json.contains("\"registry_url\""));
    }

    #[test]
    fn issue_json_skips_none_fields() {
        let i = Issue::new("pkg", "existence", Severity::Error)
            .message("msg")
            .fix("fix");
        let json = serde_json::to_string(&i).unwrap();
        assert!(!json.contains("suggestion"));
        assert!(!json.contains("registry_url"));
        assert!(!json.contains("source"));
    }

    #[test]
    fn print_human_warnings_only_no_errors() {
        // Exercises lines 140-144 (warnings section) and 167-170 (WARN footer)
        let report = ScanReport::from_issues(
            5,
            vec![
                Issue::new("slow-pkg", "metadata/version-age", Severity::Warning)
                    .message("Version published recently")
                    .fix("Wait 72 hours"),
                Issue::new("old-pkg", "metadata/version-age", Severity::Warning)
                    .message("Another warning")
                    .fix("Check it"),
            ],
        );
        assert!(report.has_issues());
        assert!(!report.has_errors());
        // Should not panic; exercises the warnings-only path
        report.print_human();
    }

    #[test]
    fn print_human_mixed_errors_and_warnings() {
        // Exercises both error and warning sections, plus the summary pluralization
        let report = ScanReport::from_issues(
            10,
            vec![
                Issue::new("bad-pkg", "existence", Severity::Error)
                    .message("not found")
                    .fix("remove it"),
                Issue::new("warn-pkg", "metadata/version-age", Severity::Warning)
                    .message("recently published")
                    .fix("wait"),
            ],
        );
        assert!(report.has_errors());
        report.print_human();
    }

    #[test]
    fn print_human_with_review_candidates_does_not_panic() {
        let report = ScanReport::from_issues_with_review_candidates(
            1,
            vec![issue("foo", "existence", Severity::Error)],
            vec![review_candidate()],
        );
        report.print_human();
    }

    #[test]
    fn print_human_single_error_singular_grammar() {
        // 1 error, 0 warnings — exercises "error" singular at line 154/156
        let report = ScanReport::from_issues(
            3,
            vec![
                Issue::new("only-err", "existence", Severity::Error)
                    .message("msg")
                    .fix("fix"),
            ],
        );
        report.print_human();
    }

    #[test]
    fn print_human_single_warning_singular_grammar() {
        // 0 errors, 1 warning — exercises "warning" singular at line 156-159
        let report = ScanReport::from_issues(
            3,
            vec![
                Issue::new("only-warn", "metadata/version-age", Severity::Warning)
                    .message("msg")
                    .fix("fix"),
            ],
        );
        report.print_human();
    }

    #[test]
    fn print_issue_with_transitive_source() {
        // Exercises line 183 (source_label for transitive)
        let mut i = Issue::new("transitive-pkg", "existence", Severity::Error)
            .message("not found on registry")
            .fix("remove it")
            .suggestion("real-pkg")
            .registry_url("https://example.com");
        i.source = Some("transitive".to_string());
        let report = ScanReport::from_issues(5, vec![i]);
        report.print_human();
    }

    #[test]
    fn print_issue_warning_with_transitive_source() {
        // Exercises line 179 (Warning label/color) combined with transitive source
        let mut i = Issue::new("transitive-warn", "metadata/version-age", Severity::Warning)
            .message("recently published")
            .fix("wait for it");
        i.source = Some("transitive".to_string());
        let report = ScanReport::from_issues(5, vec![i]);
        report.print_human();
    }

    #[test]
    fn print_issue_direct_source_no_label() {
        // source = "direct" should not show [transitive] label
        let mut i = Issue::new("direct-pkg", "existence", Severity::Error)
            .message("msg")
            .fix("fix");
        i.source = Some("direct".to_string());
        let report = ScanReport::from_issues(1, vec![i]);
        report.print_human();
    }

    #[test]
    fn print_issue_no_suggestion_no_url() {
        // Exercises the paths where suggestion and registry_url are None
        let i = Issue::new("bare-pkg", "existence", Severity::Error)
            .message("msg")
            .fix("fix");
        assert!(i.suggestion.is_none());
        assert!(i.registry_url.is_none());
        let report = ScanReport::from_issues(1, vec![i]);
        report.print_human();
    }

    #[test]
    fn sanitize_for_terminal_escapes_control_sequences() {
        assert_eq!(
            sanitize_for_terminal("pkg\u{1b}[31m\nnext"),
            "pkg\\u{1b}[31m\\nnext"
        );
    }
}
