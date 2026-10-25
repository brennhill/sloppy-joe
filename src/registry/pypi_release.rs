//! Release facts read from the PyPI JSON API (`/pypi/<name>/json`): the files
//! of the selected version with their registry-published sha256 digests, and
//! the cadence of releases around it.
//!
//! Dates: `upload_time_iso_8601` (UTC, `Z`) when present, otherwise the legacy
//! `upload_time` (UTC, no suffix). A version's date is the earliest upload
//! among its files.

use super::cadence::{ReleaseCadence, cadence_from_epochs};
use crate::cache::iso_to_epoch;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PypiFileKind {
    Wheel,
    Sdist,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PypiFile {
    pub filename: String,
    pub url: String,
    /// Lowercase hex sha256 the registry publishes for this file.
    pub sha256: Option<String>,
    pub kind: PypiFileKind,
    pub size: Option<u64>,
    pub yanked: bool,
}

/// The files PyPI lists for one version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PypiRelease {
    pub version: String,
    pub files: Vec<PypiFile>,
}

fn file_time(file: &Value) -> Option<&str> {
    file["upload_time_iso_8601"]
        .as_str()
        .or_else(|| file["upload_time"].as_str())
}

fn file_kind(file: &Value) -> PypiFileKind {
    match file["packagetype"].as_str() {
        Some("bdist_wheel") => PypiFileKind::Wheel,
        Some("sdist") => PypiFileKind::Sdist,
        _ => PypiFileKind::Other,
    }
}

/// Files of `version`, or `None` when the registry lists none.
pub(crate) fn release_from_body(body: &Value, version: &str) -> Option<PypiRelease> {
    let entries = body["releases"][version].as_array()?;
    if entries.is_empty() {
        return None;
    }
    let files = entries
        .iter()
        .filter_map(|entry| {
            Some(PypiFile {
                filename: entry["filename"].as_str()?.to_string(),
                url: entry["url"].as_str()?.to_string(),
                sha256: entry["digests"]["sha256"]
                    .as_str()
                    .map(|digest| digest.to_ascii_lowercase()),
                kind: file_kind(entry),
                size: entry["size"].as_u64(),
                yanked: entry["yanked"].as_bool().unwrap_or(false),
            })
        })
        .collect();
    Some(PypiRelease {
        version: version.to_string(),
        files,
    })
}

/// One version PyPI lists for a project. pip skips a yanked version unless a requirement pins it
/// exactly (PEP 592); a version is yanked when every one of its files is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PypiVersionListing {
    pub version: String,
    pub yanked: bool,
}

/// Every version of a project body (`/pypi/<name>/json`) that has files to install, in the
/// order PyPI lists them. A body without a `releases` table is malformed: it would otherwise
/// read as a project with nothing to install.
pub(crate) fn versions_from_body(body: &Value) -> anyhow::Result<Vec<PypiVersionListing>> {
    let releases = body["releases"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("PyPI project metadata has no releases table"))?;
    Ok(releases
        .iter()
        .filter_map(|(version, files)| {
            let files = files.as_array().filter(|files| !files.is_empty())?;
            Some(PypiVersionListing {
                version: version.clone(),
                yanked: files
                    .iter()
                    .all(|file| file["yanked"].as_bool().unwrap_or(false)),
            })
        })
        .collect())
}

/// The `Requires-Dist` PyPI publishes for one release.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PypiRequiresDist {
    pub requirements: Vec<String>,
    /// PyPI has no dependency metadata for the release: `requires_dist` is `null` and the
    /// release has no wheel, whose `METADATA` would be authoritative. Old sdists leave it empty
    /// even when `setup.py` installs dependencies, so the requirements are unknown, not none.
    pub metadata_missing: bool,
}

/// `info.requires_dist` of a version body (`/pypi/<name>/<version>/json`). Any other shape
/// than a list of strings or `null`, or a body for another version, is malformed.
pub(crate) fn requires_dist_from_body(
    body: &Value,
    version: &str,
) -> anyhow::Result<PypiRequiresDist> {
    let info = body["info"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("PyPI release metadata has no info table"))?;
    if info.get("version").and_then(Value::as_str) != Some(version) {
        anyhow::bail!("PyPI release metadata describes another version than {version}");
    }
    let requirements = match info.get("requires_dist") {
        None | Some(Value::Null) => {
            let has_wheel = body["urls"].as_array().is_some_and(|files| {
                files
                    .iter()
                    .any(|file| file_kind(file) == PypiFileKind::Wheel)
            });
            return Ok(PypiRequiresDist {
                requirements: Vec::new(),
                metadata_missing: !has_wheel,
            });
        }
        Some(Value::Array(entries)) => entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("PyPI requires_dist entry is not a string"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        Some(_) => anyhow::bail!("PyPI requires_dist is not a list"),
    };
    Ok(PypiRequiresDist {
        requirements,
        metadata_missing: false,
    })
}

/// Whether `version` is safe as one URL path segment: PEP 440 characters only.
pub(crate) fn valid_version_segment(version: &str) -> bool {
    !version.is_empty()
        && !version.contains("..")
        && version
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '+' | '!' | '-' | '_'))
}

fn version_epoch(files: &Value) -> Option<i64> {
    files
        .as_array()?
        .iter()
        .filter_map(|file| iso_to_epoch(file_time(file)?))
        .min()
}

/// Cadence of releases around `version`. `None` when its date is unknown.
pub(crate) fn cadence_from_body(body: &Value, version: &str) -> Option<ReleaseCadence> {
    let releases = body["releases"].as_object()?;
    let published = version_epoch(releases.get(version)?)?;
    let others = releases
        .iter()
        .filter(|(other, _)| other.as_str() != version)
        .filter_map(|(_, files)| version_epoch(files));
    Some(cadence_from_epochs(published, others))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file(name: &str, kind: &str, time: &str, sha: &str) -> Value {
        json!({
            "filename": name,
            "url": format!("https://files.pythonhosted.org/packages/x/{name}"),
            "packagetype": kind,
            "size": 10,
            "upload_time_iso_8601": time,
            "digests": {"sha256": sha},
        })
    }

    #[test]
    fn versions_list_every_release_with_files_and_mark_fully_yanked_ones() {
        let yanked = |name: &str| {
            let mut entry = file(name, "sdist", "2024-01-01T00:00:00Z", "aa");
            entry["yanked"] = json!(true);
            entry
        };
        let body = json!({"releases": {
            "1.0": [file("a", "sdist", "2024-01-01T00:00:00Z", "a")],
            "1.1": [yanked("b"), file("c", "bdist_wheel", "2024-01-01T00:00:00Z", "c")],
            "1.2": [yanked("d")],
            "2.0": [],
        }});
        let versions = versions_from_body(&body).unwrap();
        assert_eq!(
            versions,
            vec![
                PypiVersionListing {
                    version: "1.0".into(),
                    yanked: false
                },
                PypiVersionListing {
                    version: "1.1".into(),
                    yanked: false
                },
                PypiVersionListing {
                    version: "1.2".into(),
                    yanked: true
                },
            ]
        );
    }

    #[test]
    fn a_project_body_without_releases_is_malformed() {
        assert!(versions_from_body(&json!({"info": {}})).is_err());
    }

    #[test]
    fn requires_dist_reads_the_version_body_and_null_means_none_declared() {
        let body = json!({"info": {"version": "2.0", "requires_dist": [
            "urllib3<3,>=1.21.1",
            "PySocks!=1.5.7,>=1.5.6; extra == \"socks\"",
        ]}, "urls": [{"packagetype": "sdist"}]});
        let declared = requires_dist_from_body(&body, "2.0").unwrap();
        assert_eq!(
            declared.requirements,
            vec![
                "urllib3<3,>=1.21.1".to_string(),
                "PySocks!=1.5.7,>=1.5.6; extra == \"socks\"".to_string()
            ]
        );
        assert!(!declared.metadata_missing);
        let wheel = json!({"info": {"version": "2.0", "requires_dist": null},
                           "urls": [{"packagetype": "sdist"}, {"packagetype": "bdist_wheel"}]});
        let none = requires_dist_from_body(&wheel, "2.0").unwrap();
        assert!(none.requirements.is_empty());
        assert!(
            !none.metadata_missing,
            "a wheel's METADATA is authoritative"
        );
    }

    #[test]
    fn null_requires_dist_on_an_sdist_only_release_means_the_dependencies_are_unknown() {
        for body in [
            json!({"info": {"version": "0.3", "requires_dist": null},
                   "urls": [{"packagetype": "sdist"}]}),
            json!({"info": {"version": "0.3"}}),
        ] {
            let unknown = requires_dist_from_body(&body, "0.3").unwrap();
            assert!(unknown.requirements.is_empty());
            assert!(unknown.metadata_missing, "{body}");
        }
    }

    #[test]
    fn requires_dist_refuses_malformed_or_mismatched_bodies() {
        let wrong_type = json!({"info": {"version": "2.0", "requires_dist": "urllib3"}});
        assert!(requires_dist_from_body(&wrong_type, "2.0").is_err());
        let wrong_entry = json!({"info": {"version": "2.0", "requires_dist": [1]}});
        assert!(requires_dist_from_body(&wrong_entry, "2.0").is_err());
        let other_version = json!({"info": {"version": "3.0", "requires_dist": []}});
        assert!(requires_dist_from_body(&other_version, "2.0").is_err());
        assert!(requires_dist_from_body(&json!({}), "2.0").is_err());
    }

    #[test]
    fn version_path_segments_are_validated_before_use_in_a_url() {
        assert!(valid_version_segment("2.31.0"));
        assert!(valid_version_segment("1!2.0rc1.post3.dev4+local.7"));
        for bad in ["", "..", "1/../2", "1?x", "1#x", "1%2f", "1 2", "1\n"] {
            assert!(!valid_version_segment(bad), "{bad:?}");
        }
    }

    #[test]
    fn release_lists_files_with_lowercased_digests_and_kinds() {
        let body = json!({"releases": {"1.0": [
            file("p-1.0-py3-none-any.whl", "bdist_wheel", "2024-01-01T00:00:00Z", "ABCDEF"),
            file("p-1.0.tar.gz", "sdist", "2024-01-01T00:00:00Z", "0123"),
        ]}});
        let release = release_from_body(&body, "1.0").unwrap();
        assert_eq!(release.files.len(), 2);
        assert_eq!(release.files[0].kind, PypiFileKind::Wheel);
        assert_eq!(release.files[0].sha256.as_deref(), Some("abcdef"));
        assert_eq!(release.files[1].kind, PypiFileKind::Sdist);
    }

    #[test]
    fn release_is_none_for_unknown_or_empty_version() {
        let body = json!({"releases": {"1.0": []}});
        assert!(release_from_body(&body, "1.0").is_none());
        assert!(release_from_body(&body, "2.0").is_none());
    }

    #[test]
    fn release_skips_files_without_filename_or_url() {
        let body = json!({"releases": {"1.0": [{"packagetype": "bdist_wheel"}]}});
        let release = release_from_body(&body, "1.0").unwrap();
        assert!(release.files.is_empty());
    }

    #[test]
    fn cadence_finds_previous_release_and_counts_prior_day() {
        let body = json!({"releases": {
            "1.0": [file("a", "sdist", "2023-01-01T00:00:00Z", "a")],
            "1.1": [file("b", "sdist", "2024-06-01T00:00:00Z", "b")],
            "1.2": [file("c", "sdist", "2024-06-01T10:00:00Z", "c")],
            "1.3": [file("d", "sdist", "2024-06-01T20:00:00Z", "d")],
            "9.9": [file("e", "sdist", "2025-01-01T00:00:00Z", "e")],
        }});
        let cadence = cadence_from_body(&body, "1.3").unwrap();
        assert_eq!(cadence.releases_prior_24h, 2);
        let previous = iso_to_epoch("2024-06-01T10:00:00Z").unwrap();
        assert_eq!(cadence.previous_release_epoch, Some(previous));
    }

    #[test]
    fn cadence_uses_earliest_file_of_a_version() {
        let body = json!({"releases": {
            "1.0": [
                file("a", "sdist", "2024-01-05T00:00:00Z", "a"),
                file("b", "bdist_wheel", "2024-01-01T00:00:00Z", "b"),
            ],
            "1.1": [file("c", "sdist", "2024-03-01T00:00:00Z", "c")],
        }});
        let cadence = cadence_from_body(&body, "1.1").unwrap();
        assert_eq!(
            cadence.previous_release_epoch,
            iso_to_epoch("2024-01-01T00:00:00Z")
        );
    }

    #[test]
    fn cadence_first_release_has_no_previous() {
        let body = json!({"releases": {"1.0": [file("a", "sdist", "2024-01-01T00:00:00Z", "a")]}});
        let cadence = cadence_from_body(&body, "1.0").unwrap();
        assert_eq!(cadence.previous_release_epoch, None);
        assert_eq!(cadence.releases_prior_24h, 0);
    }

    #[test]
    fn cadence_is_none_when_selected_date_is_unparseable() {
        let body = json!({"releases": {"1.0": [{"filename": "a", "upload_time": "garbage"}]}});
        assert!(cadence_from_body(&body, "1.0").is_none());
    }

    #[test]
    fn legacy_upload_time_without_suffix_is_read_as_utc() {
        let body = json!({"releases": {
            "1.0": [{"filename": "a", "upload_time": "2024-01-01T00:00:00"}],
            "1.1": [{"filename": "b", "upload_time": "2024-02-01T00:00:00"}],
        }});
        let cadence = cadence_from_body(&body, "1.1").unwrap();
        assert!(cadence.previous_release_epoch.is_some());
    }
}
