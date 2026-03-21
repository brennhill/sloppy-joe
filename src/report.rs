use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    pub package: String,
    pub check: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
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
    ) -> Self {
        let mut issues = Vec::new();
        issues.extend(existence);
        issues.extend(similarity);
        issues.extend(canonical);
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

        let existence_issues: Vec<_> =
            self.issues.iter().filter(|i| i.check == "existence").collect();
        let similarity_issues: Vec<_> =
            self.issues.iter().filter(|i| i.check == "similarity").collect();
        let canonical_issues: Vec<_> =
            self.issues.iter().filter(|i| i.check == "canonical").collect();

        if !existence_issues.is_empty() {
            println!("{}", "Packages not found on registry:".red().bold());
            for issue in &existence_issues {
                println!("  {} {}", "x".red(), issue.package.red());
                println!("    {}", issue.message);
            }
            println!();
        }

        if !similarity_issues.is_empty() {
            println!(
                "{}",
                "Packages with suspiciously similar names:".yellow().bold()
            );
            for issue in &similarity_issues {
                println!("  {} {}", "~".yellow(), issue.package.yellow());
                println!("    {}", issue.message);
                if let Some(ref s) = issue.suggestion {
                    println!("    Did you mean: {}", s.bold());
                }
            }
            println!();
        }

        if !canonical_issues.is_empty() {
            println!(
                "{}",
                "Non-canonical packages (preferred alternatives exist):"
                    .blue()
                    .bold()
            );
            for issue in &canonical_issues {
                println!("  {} {}", "i".blue(), issue.package.blue());
                println!("    {}", issue.message);
                if let Some(ref s) = issue.suggestion {
                    println!("    Suggested replacement: {}", s.bold());
                }
            }
            println!();
        }

        println!(
            "{}: {} packages checked, {} issues found",
            "Summary".bold(),
            self.packages_checked,
            self.issues.len()
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
                message: "not found".to_string(),
                suggestion: None,
            }],
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

    #[test]
    fn new_merges_all_issue_types() {
        let existence = vec![Issue {
            package: "a".to_string(),
            check: "existence".to_string(),
            message: "msg".to_string(),
            suggestion: None,
        }];
        let similarity = vec![Issue {
            package: "b".to_string(),
            check: "similarity".to_string(),
            message: "msg".to_string(),
            suggestion: Some("c".to_string()),
        }];
        let canonical = vec![Issue {
            package: "d".to_string(),
            check: "canonical".to_string(),
            message: "msg".to_string(),
            suggestion: Some("e".to_string()),
        }];
        let report = ScanReport::new(5, existence, similarity, canonical);
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
            vec![Issue {
                package: "a".to_string(),
                check: "existence".to_string(),
                message: "not found".to_string(),
                suggestion: None,
            }],
            vec![Issue {
                package: "b".to_string(),
                check: "similarity".to_string(),
                message: "similar".to_string(),
                suggestion: Some("bb".to_string()),
            }],
            vec![Issue {
                package: "c".to_string(),
                check: "canonical".to_string(),
                message: "not canonical".to_string(),
                suggestion: Some("cc".to_string()),
            }],
        );
        // Should not panic
        report.print_human();
    }

    #[test]
    fn print_json_does_not_panic() {
        let report = ScanReport::new(
            1,
            vec![Issue {
                package: "foo".to_string(),
                check: "existence".to_string(),
                message: "msg".to_string(),
                suggestion: None,
            }],
            vec![],
            vec![],
        );
        report.print_json();
    }
}
