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
        project: None,
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
        metadata_exception: MetadataException {
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
        projects: vec![],
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
    let report = ScanReport::from_issues(2, vec![issue("bad-pkg", "existence", Severity::Error)]);
    report.print_human();
    assert!(report.has_issues());
}

#[test]
fn print_human_similarity_errors() {
    let report = ScanReport::from_issues(2, vec![issue("typo-pkg", "similarity", Severity::Error)]);
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
