//! Dependency steering: a PyPI dependency named after an import or command
//! name instead of the distribution that provides it.
//!
//! Models guess `pip install cv2` or `pip install huggingface-cli` because
//! that is the name the code imports or the shell runs. Those names are the
//! ones attackers register (the `huggingface-cli` experiment drew 30,000
//! downloads to an empty package), and `sklearn` was blocked on PyPI for the
//! same reason. The table lists only well-known mismatches.
//!
//! A hit is a warning (`jwt`, `dotenv` and others are real, different
//! distributions) and blocks when the package is young or its history is
//! unknown. Hits are also marked similarity-flagged by the caller, so wheel
//! inspection and tarball verification look at them.

use super::metadata::{MetadataLookup, age_in_hours};
use crate::Dependency;
use crate::Ecosystem;
use crate::lockfiles::python_hashes::normalize_name;
use crate::names;
use crate::report::{Issue, Severity, sanitize_for_terminal};
use std::collections::HashSet;

/// (name people use, distribution that provides it)
const WRONG_NAMES: &[(&str, &str)] = &[
    // Import names.
    ("cv2", "opencv-python"),
    ("PIL", "Pillow"),
    ("yaml", "PyYAML"),
    ("sklearn", "scikit-learn"),
    ("skimage", "scikit-image"),
    ("bs4", "beautifulsoup4"),
    ("dateutil", "python-dateutil"),
    ("Crypto", "pycryptodome"),
    ("OpenSSL", "pyOpenSSL"),
    ("serial", "pyserial"),
    ("attr", "attrs"),
    ("git", "GitPython"),
    ("magic", "python-magic"),
    ("docx", "python-docx"),
    ("fitz", "PyMuPDF"),
    ("telegram", "python-telegram-bot"),
    ("discord", "discord.py"),
    ("MySQLdb", "mysqlclient"),
    ("zmq", "pyzmq"),
    ("usb", "pyusb"),
    ("jwt", "PyJWT"),
    ("dotenv", "python-dotenv"),
    ("slugify", "python-slugify"),
    ("ldap", "python-ldap"),
    ("jose", "python-jose"),
    ("nacl", "PyNaCl"),
    ("gi", "PyGObject"),
    ("wx", "wxPython"),
    ("win32api", "pywin32"),
    ("pkg_resources", "setuptools"),
    // Command names.
    ("huggingface-cli", "huggingface-hub"),
    ("pip-compile", "pip-tools"),
    ("pip-sync", "pip-tools"),
    ("django-admin", "Django"),
    ("sphinx-build", "Sphinx"),
    ("jupyter-lab", "jupyterlab"),
    ("jupyter-notebook", "notebook"),
    ("ansible-playbook", "ansible"),
    ("aws", "awscli"),
];

/// A package created within this many hours counts as young.
const YOUNG_HOURS: u64 = 365 * 24;

fn intended_distribution(dependency: &str) -> Option<&'static str> {
    let wanted = normalize_name(dependency);
    WRONG_NAMES
        .iter()
        .find(|(wrong, _)| normalize_name(wrong) == wanted)
        .map(|(_, right)| *right)
}

/// Is the package young, or is its history unknown?
fn history_is_thin(lookup: Option<&MetadataLookup>) -> bool {
    let created = lookup
        .and_then(|l| l.metadata.as_ref())
        .and_then(|meta| meta.created.as_deref());
    created
        .and_then(age_in_hours)
        .is_none_or(|age| age < YOUNG_HOURS)
}

/// Issues for PyPI dependencies named after an import or command name.
pub(crate) fn check_wrong_distribution_names(
    deps: &[Dependency],
    lookups: &[MetadataLookup],
) -> Vec<Issue> {
    let mut seen = HashSet::new();
    let mut issues = Vec::new();
    for dep in deps.iter().filter(|dep| dep.ecosystem == Ecosystem::PyPI) {
        let package = dep.package_name();
        let Some(intended) = intended_distribution(package) else {
            continue;
        };
        if !seen.insert(normalize_name(package)) {
            continue;
        }
        let lookup = lookups
            .iter()
            .find(|l| l.ecosystem == Ecosystem::PyPI && normalize_name(&l.package) == normalize_name(package));
        let thin = history_is_thin(lookup);
        let severity = if thin { Severity::Error } else { Severity::Warning };
        let why = if thin {
            "The package is new or its history could not be read, which is how a registered guess looks."
        } else {
            "The package is established, so it may be a different library that shares the name."
        };
        issues.push(
            Issue::new(package, names::STEERING_DISTRIBUTION_NAME, severity)
                .message(format!(
                    "'{}' is the name that code imports or a shell runs for '{}', not the name of the distribution that provides it. AI assistants guess this name, and attackers register guessed names. {why}",
                    sanitize_for_terminal(package),
                    intended
                ))
                .fix(format!(
                    "If you meant '{intended}', replace '{}' with it. If '{}' really is the library you want, confirm its publisher and repository on PyPI.",
                    sanitize_for_terminal(package),
                    sanitize_for_terminal(package)
                )),
        );
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PackageMetadata;

    fn dep(name: &str, ecosystem: Ecosystem) -> Dependency {
        Dependency {
            name: name.into(),
            version: Some("==1.0".into()),
            ecosystem,
            actual_name: None,
        }
    }

    fn lookup(name: &str, created: Option<&str>) -> MetadataLookup {
        MetadataLookup {
            package: name.into(),
            ecosystem: Ecosystem::PyPI,
            version: Some("==1.0".into()),
            resolved_version: Some("1.0".into()),
            unresolved_version: false,
            exists: true,
            metadata: Some(PackageMetadata {
                created: created.map(str::to_string),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn established_package_with_a_wrong_name_warns_and_names_the_intended_one() {
        let issues = check_wrong_distribution_names(
            &[dep("jwt", Ecosystem::PyPI)],
            &[lookup("jwt", Some("2015-01-01T00:00:00Z"))],
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].check, "steering/distribution-name");
        assert_eq!(issues[0].severity, Severity::Warning);
        assert!(issues[0].message.contains("PyJWT"));
    }

    #[test]
    fn young_package_with_a_wrong_name_blocks() {
        let issues = check_wrong_distribution_names(
            &[dep("huggingface-cli", Ecosystem::PyPI)],
            &[lookup("huggingface-cli", Some("2999-01-01T00:00:00Z"))],
        );
        assert_eq!(issues[0].severity, Severity::Error);
    }

    #[test]
    fn unknown_history_blocks_rather_than_passes() {
        let missing_lookup = check_wrong_distribution_names(&[dep("cv2", Ecosystem::PyPI)], &[]);
        assert_eq!(missing_lookup[0].severity, Severity::Error);
        let no_date = check_wrong_distribution_names(
            &[dep("cv2", Ecosystem::PyPI)],
            &[lookup("cv2", None)],
        );
        assert_eq!(no_date[0].severity, Severity::Error);
    }

    #[test]
    fn spelling_variants_of_the_wrong_name_still_match() {
        for name in ["Huggingface_CLI", "huggingface.cli", "SKLEARN", "pil"] {
            let issues = check_wrong_distribution_names(&[dep(name, Ecosystem::PyPI)], &[]);
            assert_eq!(issues.len(), 1, "{name}");
        }
    }

    #[test]
    fn the_right_distribution_names_pass() {
        for name in ["scikit-learn", "opencv-python", "pillow", "huggingface-hub", "requests"] {
            assert!(check_wrong_distribution_names(&[dep(name, Ecosystem::PyPI)], &[]).is_empty());
        }
    }

    #[test]
    fn other_ecosystems_are_not_checked() {
        assert!(check_wrong_distribution_names(&[dep("yaml", Ecosystem::Npm)], &[]).is_empty());
    }

    #[test]
    fn a_name_listed_twice_reports_once() {
        let deps = [dep("yaml", Ecosystem::PyPI), dep("YAML", Ecosystem::PyPI)];
        assert_eq!(check_wrong_distribution_names(&deps, &[]).len(), 1);
    }

    #[test]
    fn table_has_no_self_mappings_or_duplicates() {
        let mut seen = HashSet::new();
        for (wrong, right) in WRONG_NAMES {
            assert_ne!(normalize_name(wrong), normalize_name(right), "{wrong}");
            assert!(seen.insert(normalize_name(wrong)), "duplicate {wrong}");
        }
    }
}
