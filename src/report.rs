use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Severity {
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    pub package: String,
    pub check: String,
    pub severity: Severity,
    pub message: String,
    pub fix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_url: Option<String>,
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

    pub fn new(
        packages_checked: usize,
        existence: Vec<Issue>,
        similarity: Vec<Issue>,
        canonical: Vec<Issue>,
        metadata: Vec<Issue>,
        malicious: Vec<Issue>,
    ) -> Self {
        let mut issues = Vec::new();
        issues.extend(existence);
        issues.extend(similarity);
        issues.extend(canonical);
        issues.extend(metadata);
        issues.extend(malicious);
        ScanReport {
            packages_checked,
            issues,
        }
    }

    pub fn has_issues(&self) -> bool {
        !self.issues.is_empty()
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

        println!();
        println!("{}", "ERRORS (build blocked):".red().bold());
        println!();

        for issue in &self.issues {
            println!(
                "  {} {} {}",
                "ERROR".red().bold(),
                issue.package.red().bold(),
                format!("[{}]", issue.check).dimmed()
            );
            println!("        {}", issue.message);
            println!("   {}  {}", "Fix:".yellow().bold(), issue.fix);
            if let Some(ref s) = issue.suggestion {
                println!("        Replace with: {}", s.green().bold());
            }
            if let Some(ref url) = issue.registry_url {
                println!("        Verify: {}", url.dimmed());
            }
            println!();
        }

        println!("{}", "─".repeat(60));
        println!(
            "{}: {} packages checked, {} {}",
            "Summary".bold(),
            self.packages_checked,
            self.issues.len(),
            if self.issues.len() == 1 {
                "error"
            } else {
                "errors"
            },
        );
        println!(
            "\n{}  Remove or replace the packages above before merging.",
            "BLOCKED".red().bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_issues_returns_false_when_empty() {
        let report = ScanReport::empty();
        assert!(!report.has_issues());
    }

    #[test]
    fn has_issues_returns_true_when_issues_exist() {
        let report = ScanReport::new(
            1,
            vec![Issue {
                package: "foo".to_string(),
                check: "existence".to_string(),
                severity: Severity::Error,
                message: "not found".to_string(),
                fix: "remove it".to_string(),
                suggestion: None,
                registry_url: None,
            }],
            vec![],
            vec![],
            vec![],
            vec![],
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
        Issue {
            package: name.to_string(),
            check: check.to_string(),
            severity,
            message: "msg".to_string(),
            fix: "fix it".to_string(),
            suggestion: Some("replacement".to_string()),
            registry_url: Some("https://example.com".to_string()),
        }
    }

    #[test]
    fn new_merges_all_issue_types() {
        let existence = vec![issue("a", "existence", Severity::Error)];
        let similarity = vec![issue("b", "similarity", Severity::Error)];
        let canonical = vec![issue("c", "canonical", Severity::Error)];
        let report = ScanReport::new(5, existence, similarity, canonical, vec![], vec![]);
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
        let report = ScanReport::new(
            3,
            vec![issue("a", "existence", Severity::Error)],
            vec![issue("b", "similarity", Severity::Error)],
            vec![issue("c", "canonical", Severity::Error)],
            vec![],
            vec![],
        );
        // Should not panic
        report.print_human();
    }

    #[test]
    fn print_json_does_not_panic() {
        let report = ScanReport::new(
            1,
            vec![issue("foo", "existence", Severity::Error)],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        report.print_json();
    }

    #[test]
    fn print_human_errors_only() {
        let report = ScanReport::new(
            2,
            vec![issue("bad-pkg", "existence", Severity::Error)],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        report.print_human();
        assert!(report.has_issues());
    }

    #[test]
    fn print_human_similarity_errors() {
        let report = ScanReport::new(
            2,
            vec![],
            vec![issue("typo-pkg", "similarity", Severity::Error)],
            vec![],
            vec![],
            vec![],
        );
        report.print_human();
        assert!(report.has_issues());
    }

    #[test]
    fn print_human_canonical_errors() {
        let mut i = issue("old-pkg", "canonical", Severity::Error);
        i.registry_url = None;
        let report = ScanReport::new(2, vec![], vec![], vec![i], vec![], vec![]);
        report.print_human();
        assert!(report.has_issues());
    }

    #[test]
    fn severity_serializes_correctly() {
        let json = serde_json::to_string(&Severity::Error).unwrap();
        assert_eq!(json, "\"Error\"");
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
        let i = Issue {
            package: "pkg".to_string(),
            check: "existence".to_string(),
            severity: Severity::Error,
            message: "msg".to_string(),
            fix: "fix".to_string(),
            suggestion: None,
            registry_url: None,
        };
        let json = serde_json::to_string(&i).unwrap();
        assert!(!json.contains("suggestion"));
        assert!(!json.contains("registry_url"));
    }
}
