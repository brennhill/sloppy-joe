use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum Severity {
    Error,
    Warning,
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

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub packages_checked: usize,
    pub issues: Vec<Issue>,
}

impl ScanReport {
    pub fn empty() -> Self {
        ScanReport {
            packages_checked: 0,
            issues: vec![],
        }
    }

    pub fn from_issues(packages_checked: usize, issues: Vec<Issue>) -> Self {
        ScanReport {
            packages_checked,
            issues,
        }
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
        if self.issues.is_empty() {
            println!(
                "\n{}  {} packages checked, no issues found.",
                "OK".green().bold(),
                self.packages_checked
            );
            return;
        }

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

        println!();
        if !errors.is_empty() {
            println!("{}", "ERRORS (build blocked):".red().bold());
            println!();
            for issue in &errors {
                print_issue(issue);
            }
        }

        if !warnings.is_empty() {
            println!("{}", "WARNINGS (build allowed):".yellow().bold());
            println!();
            for issue in &warnings {
                print_issue(issue);
            }
        }

        println!("{}", "─".repeat(60));
        println!(
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
            println!(
                "\n{}  Remove or replace the packages above before merging.",
                "BLOCKED".red().bold()
            );
        } else {
            println!(
                "\n{}  Warnings did not block this scan, but accuracy is reduced.",
                "WARN".yellow().bold()
            );
        }
    }
}

fn print_issue(issue: &Issue) {
    let safe_package = sanitize_for_terminal(&issue.package);
    let (label, colorized_package) = match issue.severity {
        Severity::Error => ("ERROR".red().bold(), safe_package.red().bold()),
        Severity::Warning => ("WARN".yellow().bold(), safe_package.yellow().bold()),
    };

    let source_label = match issue.source.as_deref() {
        Some("transitive") => " [transitive]".dimmed().to_string(),
        _ => String::new(),
    };
    println!(
        "  {} {} {}{}",
        label,
        colorized_package,
        format!("[{}]", sanitize_for_terminal(&issue.check)).dimmed(),
        source_label
    );
    println!("        {}", sanitize_for_terminal(&issue.message));
    println!(
        "   {}  {}",
        "Fix:".yellow().bold(),
        sanitize_for_terminal(&issue.fix)
    );
    if let Some(ref s) = issue.suggestion {
        println!(
            "        Replace with: {}",
            sanitize_for_terminal(s).green().bold()
        );
    }
    if let Some(ref url) = issue.registry_url {
        println!("        Verify: {}", sanitize_for_terminal(url).dimmed());
    }
    println!();
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
