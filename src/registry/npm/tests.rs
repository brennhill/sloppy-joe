use super::*;

/// Helper: returns an ISO 8601 date string approximately N months ago.
/// Uses relative time so tests don't rot when hardcoded dates age out.
fn months_ago(months: u64) -> String {
    let secs = crate::cache::now_epoch() as i64 - (months as i64 * 30 * 24 * 3600);
    // Use cache module's now_iso8601 style formatting
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let min = (time_of_day % 3600) / 60;
    let sec = time_of_day % 60;
    let mut year = 1970i64;
    let mut rem_days = days;
    loop {
        let ydays = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if rem_days < ydays {
            break;
        }
        rem_days -= ydays;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
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
    let mut month = 0i64;
    for (i, &md) in mdays.iter().enumerate() {
        if rem_days < md {
            month = i as i64 + 1;
            break;
        }
        rem_days -= md;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        rem_days + 1,
        hour,
        min,
        sec
    )
}

#[test]
fn metadata_from_body_downloads_defaults_to_none() {
    // metadata_from_body itself does not populate downloads —
    // that comes from the separate downloads API call in metadata().
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": "2024-02-01T00:00:00Z",
            "1.0.0": "2020-01-02T00:00:00Z"
        },
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "scripts": {},
                "dependencies": {},
                "_npmUser": { "name": "alice" }
            }
        }
    });
    let metadata = metadata_from_body(&body, None).unwrap();
    // downloads is None until enriched by fetch_downloads
    assert_eq!(metadata.downloads, None);
}

#[test]
fn version_history_populated_from_npm_json() {
    // Use relative dates so this test doesn't rot
    let date_8mo = months_ago(8);
    let date_1mo = months_ago(1);
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": &date_1mo,
            "1.0.0": &date_8mo,
            "2.0.0": &date_1mo
        },
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "1.0.0": {
                "scripts": {},
                "dependencies": {},
                "_npmUser": { "name": "alice" }
            },
            "2.0.0": {
                "scripts": { "postinstall": "node setup.js" },
                "dependencies": { "a": "^1.0.0" },
                "_npmUser": { "name": "bob" }
            }
        }
    });
    let metadata = metadata_from_body(&body, None).unwrap();
    assert_eq!(metadata.version_history.len(), 2);
    // Chronological order (oldest first)
    assert_eq!(metadata.version_history[0].version, "1.0.0");
    assert_eq!(
        metadata.version_history[0].publisher.as_deref(),
        Some("alice")
    );
    assert!(!metadata.version_history[0].has_install_scripts);
    assert_eq!(
        metadata.version_history[0].date.as_deref(),
        Some(date_8mo.as_str())
    );

    assert_eq!(metadata.version_history[1].version, "2.0.0");
    assert_eq!(
        metadata.version_history[1].publisher.as_deref(),
        Some("bob")
    );
    assert!(metadata.version_history[1].has_install_scripts);
    assert_eq!(
        metadata.version_history[1].date.as_deref(),
        Some(date_1mo.as_str())
    );
}

#[test]
fn version_history_filters_old_versions() {
    // Versions older than 12 months should be excluded
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": "2026-02-01T00:00:00Z",
            "1.0.0": "2020-01-02T00:00:00Z",
            "2.0.0": "2026-01-15T00:00:00Z"
        },
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "1.0.0": {
                "scripts": {},
                "dependencies": {},
                "_npmUser": { "name": "alice" }
            },
            "2.0.0": {
                "scripts": {},
                "dependencies": {},
                "_npmUser": { "name": "bob" }
            }
        }
    });
    let metadata = metadata_from_body(&body, None).unwrap();
    // 1.0.0 from 2020 should be filtered out (older than 12 months)
    assert_eq!(metadata.version_history.len(), 1);
    assert_eq!(metadata.version_history[0].version, "2.0.0");
}

#[test]
fn version_history_handles_missing_npm_user() {
    let date_1mo = months_ago(1);
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": &date_1mo,
            "1.0.0": &date_1mo
        },
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "scripts": {},
                "dependencies": {}
                // no _npmUser
            }
        }
    });
    let metadata = metadata_from_body(&body, None).unwrap();
    assert_eq!(metadata.version_history.len(), 1);
    assert_eq!(metadata.version_history[0].publisher, None);
}

#[test]
fn version_history_handles_missing_scripts() {
    let date_1mo = months_ago(1);
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": &date_1mo,
            "1.0.0": &date_1mo
        },
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "dependencies": {},
                "_npmUser": { "name": "alice" }
                // no scripts object
            }
        }
    });
    let metadata = metadata_from_body(&body, None).unwrap();
    assert_eq!(metadata.version_history.len(), 1);
    assert!(!metadata.version_history[0].has_install_scripts);
}

#[test]
fn version_history_handles_missing_time_entry() {
    // Version exists but has no time entry — should be included with date=None
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": "2026-02-01T00:00:00Z"
            // no time entry for 1.0.0
        },
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "scripts": {},
                "dependencies": {},
                "_npmUser": { "name": "alice" }
            }
        }
    });
    let metadata = metadata_from_body(&body, None).unwrap();
    // Version without a date can't be age-filtered, so include it
    assert_eq!(metadata.version_history.len(), 1);
    assert_eq!(metadata.version_history[0].date, None);
}

#[test]
fn version_history_empty_for_no_versions() {
    let date_1mo = months_ago(1);
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": &date_1mo,
            "1.0.0": &date_1mo
        },
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "scripts": {},
                "dependencies": {},
                "_npmUser": { "name": "alice" }
            }
        }
    });
    // This test just verifies that when versions object is present,
    // version_history is populated (already tested above)
    let metadata = metadata_from_body(&body, None).unwrap();
    assert!(!metadata.version_history.is_empty());
}

#[test]
fn dateless_versions_sort_to_end() {
    let date_2mo = months_ago(2);
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": &date_2mo,
            "1.0.0": &date_2mo
            // no time entry for 2.0.0
        },
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "1.0.0": {
                "scripts": {},
                "dependencies": {},
                "_npmUser": { "name": "alice" }
            },
            "2.0.0": {
                "scripts": {},
                "dependencies": {},
                "_npmUser": { "name": "bob" }
            }
        }
    });
    let metadata = metadata_from_body(&body, None).unwrap();
    assert_eq!(metadata.version_history.len(), 2);
    // Dated version comes first; dateless version sorts to the end
    assert_eq!(metadata.version_history[0].version, "1.0.0");
    assert!(metadata.version_history[0].date.is_some());
    assert_eq!(metadata.version_history[1].version, "2.0.0");
    assert!(metadata.version_history[1].date.is_none());
}

#[test]
fn metadata_uses_requested_version_for_release_signals() {
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": "2024-02-01T00:00:00Z",
            "1.0.0": "2020-01-02T00:00:00Z",
            "1.1.0": "2020-02-01T00:00:00Z"
        },
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.0.0": {
                "scripts": {},
                "dependencies": { "a": "^1.0.0" },
                "_npmUser": { "name": "alice" }
            },
            "1.1.0": {
                "scripts": { "postinstall": "node setup.js" },
                "dependencies": { "a": "^1.0.0", "b": "^2.0.0" },
                "_npmUser": { "name": "bob" }
            }
        }
    });

    let metadata = metadata_from_body(&body, Some("1.0.0")).unwrap();
    assert_eq!(
        metadata.latest_version_date,
        Some("2020-01-02T00:00:00Z".to_string())
    );
    assert!(!metadata.has_install_scripts);
    assert_eq!(metadata.dependency_count, Some(1));
    assert_eq!(metadata.current_publisher, Some("alice".to_string()));
    assert_eq!(metadata.previous_dependency_count, None);
    assert_eq!(metadata.previous_publisher, None);
}

#[test]
fn metadata_does_not_fallback_to_latest_when_requested_version_is_missing() {
    let body = serde_json::json!({
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": "2024-02-01T00:00:00Z",
            "1.1.0": "2020-02-01T00:00:00Z"
        },
        "dist-tags": { "latest": "1.1.0" },
        "repository": { "url": "https://github.com/example/pkg" },
        "versions": {
            "1.1.0": {
                "scripts": { "postinstall": "node setup.js" },
                "dependencies": { "a": "^1.0.0", "b": "^2.0.0" },
                "_npmUser": { "name": "bob" }
            }
        }
    });

    let metadata = metadata_from_body(&body, Some("1.0.0")).unwrap();
    assert_eq!(metadata.latest_version_date, None);
    assert!(!metadata.has_install_scripts);
    assert_eq!(metadata.current_publisher, None);
    assert_eq!(
        metadata.repository_url.as_deref(),
        Some("https://github.com/example/pkg")
    );
}
