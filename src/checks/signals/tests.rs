use super::*;
use crate::Ecosystem;
use crate::registry::VersionRecord;

fn make_lookup(
    package: &str,
    unresolved: bool,
    meta: PackageMetadata,
) -> (MetadataLookup, PackageMetadata) {
    let lookup = MetadataLookup {
        package: package.to_string(),
        ecosystem: Ecosystem::Npm,
        version: Some("2.0.0".to_string()),
        resolved_version: Some("2.0.0".to_string()),
        unresolved_version: unresolved,
        exists: true,
        metadata: Some(meta.clone()),
    };
    (lookup, meta)
}

fn base_meta() -> PackageMetadata {
    PackageMetadata {
        created: Some("2020-01-01T00:00:00Z".to_string()),
        latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
        downloads: Some(50000),
        repository_url: Some("https://github.com/example/pkg".to_string()),
        ..Default::default()
    }
}

/// Helper: returns an ISO date string N months ago (approximate).
fn months_ago(months: u64) -> String {
    let secs = crate::cache::now_epoch() as i64 - (months as i64 * 30 * 24 * 3600);
    // Convert back to rough ISO string
    let (y, m, d, h, mi, s) = epoch_to_date(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
}

fn epoch_to_date(epoch: i64) -> (i64, i64, i64, i64, i64, i64) {
    let s = epoch % 60;
    let mi = (epoch / 60) % 60;
    let h = (epoch / 3600) % 24;
    let mut days = epoch / 86400;
    let mut y = 1970i64;
    loop {
        let dy = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0i64;
    for (i, &md) in mdays.iter().enumerate() {
        if days < md as i64 {
            m = i as i64 + 1;
            break;
        }
        days -= md as i64;
    }
    (y, m, days + 1, h, mi, s)
}

// Test 1: Combo fires when publisher changed 6 months ago + scripts added after
#[test]
fn combo_fires_publisher_change_6_months_scripts_after() {
    let change_date = months_ago(6);
    let meta = PackageMetadata {
        has_install_scripts: true,
        version_history: vec![
            VersionRecord {
                version: "1.0.0".to_string(),
                publisher: Some("alice".to_string()),
                has_install_scripts: false,
                date: Some(months_ago(8)),
            },
            VersionRecord {
                version: "1.1.0".to_string(),
                publisher: Some("bob".to_string()),
                has_install_scripts: false,
                date: Some(change_date.clone()),
            },
            VersionRecord {
                version: "2.0.0".to_string(),
                publisher: Some("bob".to_string()),
                has_install_scripts: true,
                date: Some(months_ago(1)),
            },
        ],
        ..base_meta()
    };
    let (lookup, meta) = make_lookup("evil-pkg", false, meta);
    let issue = check_publisher_script_combo(&lookup, &meta);
    assert!(
        issue.is_some(),
        "Should fire when publisher changed 6 months ago + scripts added after"
    );
    let issue = issue.unwrap();
    assert_eq!(
        issue.check,
        super::super::names::METADATA_PUBLISHER_SCRIPT_COMBO
    );
    assert_eq!(issue.severity, Severity::Error);
    assert!(
        issue.message.contains("alice"),
        "Message should mention old publisher"
    );
    assert!(
        issue.message.contains("bob"),
        "Message should mention new publisher"
    );
}

// Test 2: Does NOT fire when no publisher change in history
#[test]
fn no_fire_no_publisher_change() {
    let meta = PackageMetadata {
        has_install_scripts: true,
        version_history: vec![
            VersionRecord {
                version: "1.0.0".to_string(),
                publisher: Some("alice".to_string()),
                has_install_scripts: false,
                date: Some(months_ago(6)),
            },
            VersionRecord {
                version: "2.0.0".to_string(),
                publisher: Some("alice".to_string()),
                has_install_scripts: true,
                date: Some(months_ago(1)),
            },
        ],
        ..base_meta()
    };
    let (lookup, meta) = make_lookup("safe-pkg", false, meta);
    let issue = check_publisher_script_combo(&lookup, &meta);
    assert!(issue.is_none(), "Should not fire when no publisher change");
}

#[test]
fn metadata_fix_text_does_not_claim_allowed_suppresses_metadata_findings() {
    let low_download_meta = PackageMetadata {
        downloads: Some(5),
        ..base_meta()
    };
    let (lookup, low_download_meta) = make_lookup("tiny-pkg", false, low_download_meta);
    let low_download_issue = check_low_downloads(&lookup, &low_download_meta).unwrap();
    assert!(
        !low_download_issue.fix.contains("allowed"),
        "low-download remediation must not suggest a config that does not suppress metadata checks"
    );

    let new_package_meta = PackageMetadata {
        created: Some(months_ago(0)),
        ..base_meta()
    };
    let (lookup, new_package_meta) = make_lookup("fresh-pkg", false, new_package_meta);
    let new_package_issue = check_new_package(&lookup, &new_package_meta).unwrap();
    assert!(
        !new_package_issue.fix.contains("allowed"),
        "new-package remediation must not suggest a config that does not suppress metadata checks"
    );

    let combo_meta = PackageMetadata {
        has_install_scripts: true,
        version_history: vec![
            VersionRecord {
                version: "1.0.0".to_string(),
                publisher: Some("alice".to_string()),
                has_install_scripts: false,
                date: Some(months_ago(8)),
            },
            VersionRecord {
                version: "1.1.0".to_string(),
                publisher: Some("bob".to_string()),
                has_install_scripts: false,
                date: Some(months_ago(6)),
            },
            VersionRecord {
                version: "2.0.0".to_string(),
                publisher: Some("bob".to_string()),
                has_install_scripts: true,
                date: Some(months_ago(1)),
            },
        ],
        ..base_meta()
    };
    let (lookup, combo_meta) = make_lookup("combo-pkg", false, combo_meta);
    let combo_issue = check_publisher_script_combo(&lookup, &combo_meta).unwrap();
    assert!(
        !combo_issue.fix.contains("allowed"),
        "publisher-script-combo remediation must not suggest a config that does not suppress metadata checks"
    );
    assert!(
        !combo_issue.fix.contains("metadata_exceptions"),
        "publisher-script-combo remediation must not suggest a config path that sloppy-joe does not honor for this check"
    );
}

// Test 3: Does NOT fire when publisher change is >12 months old
#[test]
fn no_fire_publisher_change_old() {
    let meta = PackageMetadata {
        has_install_scripts: true,
        version_history: vec![
            VersionRecord {
                version: "1.0.0".to_string(),
                publisher: Some("alice".to_string()),
                has_install_scripts: false,
                date: Some(months_ago(18)),
            },
            VersionRecord {
                version: "2.0.0".to_string(),
                publisher: Some("bob".to_string()),
                has_install_scripts: true,
                date: Some(months_ago(14)),
            },
        ],
        ..base_meta()
    };
    let (lookup, meta) = make_lookup("old-change-pkg", false, meta);
    let issue = check_publisher_script_combo(&lookup, &meta);
    assert!(
        issue.is_none(),
        "Should not fire when publisher change is >12 months old"
    );
}

// Test 4: Does NOT fire when no install scripts in current version
#[test]
fn no_fire_no_install_scripts() {
    let meta = PackageMetadata {
        has_install_scripts: false,
        version_history: vec![
            VersionRecord {
                version: "1.0.0".to_string(),
                publisher: Some("alice".to_string()),
                has_install_scripts: false,
                date: Some(months_ago(6)),
            },
            VersionRecord {
                version: "2.0.0".to_string(),
                publisher: Some("bob".to_string()),
                has_install_scripts: false,
                date: Some(months_ago(1)),
            },
        ],
        ..base_meta()
    };
    let (lookup, meta) = make_lookup("no-scripts-pkg", false, meta);
    let issue = check_publisher_script_combo(&lookup, &meta);
    assert!(issue.is_none(), "Should not fire when no install scripts");
}

// Test 5: Fires with different message when scripts pre-date the publisher change
#[test]
fn fires_different_message_scripts_predate_change() {
    let meta = PackageMetadata {
        has_install_scripts: true,
        version_history: vec![
            VersionRecord {
                version: "1.0.0".to_string(),
                publisher: Some("alice".to_string()),
                has_install_scripts: true, // scripts already present
                date: Some(months_ago(8)),
            },
            VersionRecord {
                version: "1.1.0".to_string(),
                publisher: Some("bob".to_string()),
                has_install_scripts: true,
                date: Some(months_ago(3)),
            },
        ],
        ..base_meta()
    };
    let (lookup, meta) = make_lookup("inherited-pkg", false, meta);
    let issue = check_publisher_script_combo(&lookup, &meta);
    assert!(
        issue.is_some(),
        "Should fire when scripts pre-date publisher change"
    );
    let issue = issue.unwrap();
    assert!(
        issue.message.contains("already present")
            || issue.message.contains("pre-date")
            || issue.message.contains("inherited"),
        "Message should note scripts pre-date the change, got: {}",
        issue.message
    );
}

// Test 6: Skips when unresolved_version is true
#[test]
fn skips_unresolved_version() {
    let meta = PackageMetadata {
        has_install_scripts: true,
        version_history: vec![
            VersionRecord {
                version: "1.0.0".to_string(),
                publisher: Some("alice".to_string()),
                has_install_scripts: false,
                date: Some(months_ago(6)),
            },
            VersionRecord {
                version: "2.0.0".to_string(),
                publisher: Some("bob".to_string()),
                has_install_scripts: true,
                date: Some(months_ago(1)),
            },
        ],
        ..base_meta()
    };
    let (lookup, meta) = make_lookup("unresolved-pkg", true, meta);
    let issue = check_publisher_script_combo(&lookup, &meta);
    assert!(
        issue.is_none(),
        "Should skip when unresolved_version is true"
    );
}

// Test 7: Skips when version_history is empty
#[test]
fn skips_empty_version_history() {
    let meta = PackageMetadata {
        has_install_scripts: true,
        version_history: Vec::new(),
        ..base_meta()
    };
    let (lookup, meta) = make_lookup("empty-history-pkg", false, meta);
    let issue = check_publisher_script_combo(&lookup, &meta);
    assert!(issue.is_none(), "Should skip when version_history is empty");
}

#[test]
fn plausible_repo_url_requires_exact_known_host() {
    assert!(is_plausible_repo_url("https://github.com/example/pkg"));
    assert!(is_plausible_repo_url("git@github.com:example/pkg.git"));
    assert!(!is_plausible_repo_url(
        "https://github.com.evil.example/pkg"
    ));
    assert!(!is_plausible_repo_url(
        "https://evil.example/github.com/pkg"
    ));
}
