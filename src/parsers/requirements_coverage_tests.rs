//! Red-team regressions for requirements.txt parsing.

use super::*;
use crate::parsers::test_utils::*;

fn write_include_chain(dir: &Path, length: usize) {
    for index in 1..length {
        std::fs::write(
            dir.join(format!("r{index}.txt")),
            format!("-r r{}.txt\n", index + 1),
        )
        .unwrap();
    }
    std::fs::write(dir.join(format!("r{length}.txt")), "requests==2.31.0\n").unwrap();
}

#[test]
fn deep_include_chains_fail_closed_instead_of_overflowing_the_stack() {
    let dir = empty_test_dir("req-chain-deep");
    write_include_chain(&dir, 4000);
    let root = dir.join("r1.txt");

    let err = parse_scoped_file(&root, &dir).unwrap_err();
    assert!(err.to_string().contains("include depth"), "{err}");
    let err = is_hash_locked_requirements_file(&root, &dir).unwrap_err();
    assert!(err.to_string().contains("include depth"), "{err}");
    let err = included_paths(&root, &dir).unwrap_err();
    assert!(err.to_string().contains("include depth"), "{err}");
    let err = source_provenance(&root, &dir).unwrap_err();
    assert!(err.to_string().contains("include depth"), "{err}");
    cleanup(&dir);
}

#[test]
fn nameless_requirement_lines_fail_closed() {
    for line in ["==1.0", "[extra]", ">=2", "[extra]==1.0"] {
        let dir = setup_test_dir(
            "req-nameless",
            "requirements.txt",
            &format!("requests==2.31\n{line}\n"),
        );
        let err = parse(&dir).expect_err(line);
        assert!(err.to_string().contains("missing a package name"), "{err}");
        cleanup(&dir);
    }
}

#[test]
fn utf8_bom_prefixed_requirements_parse() {
    let dir = setup_test_dir(
        "req-bom",
        "requirements.txt",
        "\u{feff}requests==2.31.0\nevil-bom==1.0\n",
    );
    let names: Vec<String> = parse(&dir).unwrap().into_iter().map(|d| d.name).collect();
    assert_eq!(names, vec!["requests".to_string(), "evil-bom".to_string()]);
    cleanup(&dir);
}

#[test]
fn utf8_bom_prefixed_python_manifests_parse() {
    let pyproject = setup_test_dir(
        "pyproject-bom",
        "pyproject.toml",
        "\u{feff}[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"requests\"]\n",
    );
    assert_eq!(
        crate::parsers::pyproject_toml::parse_legacy(&pyproject).unwrap()[0].name,
        "requests"
    );
    cleanup(&pyproject);

    let pipfile = setup_test_dir(
        "pipfile-bom",
        "Pipfile",
        "\u{feff}[packages]\nrequests = \"*\"\n",
    );
    assert_eq!(
        crate::parsers::pipfile::parse(&pipfile).unwrap()[0].name,
        "requests"
    );
    cleanup(&pipfile);

    let cfg = setup_test_dir(
        "cfg-bom",
        "setup.cfg",
        "\u{feff}[options]\ninstall_requires = requests==2.31.0\n",
    );
    assert_eq!(
        crate::parsers::setup_cfg::parse(&cfg).unwrap()[0].name,
        "requests"
    );
    cleanup(&cfg);
}

#[test]
fn moderate_include_chains_still_parse() {
    let dir = empty_test_dir("req-chain-ok");
    write_include_chain(&dir, 32);
    let deps = parse_scoped_file(&dir.join("r1.txt"), &dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].dependency.name, "requests");
    cleanup(&dir);
}

// PEP 508 allows the version specifier in parentheses; Poetry 2 projects emit
// it (`poetry-core (>=2.1.0,<3.0.0)`), so it must parse instead of being
// mistaken for part of the package name.
mod parenthesized_versions {
    use super::super::parse_requirement_spec;
    use std::path::Path;

    fn spec(raw: &str) -> anyhow::Result<Option<crate::Dependency>> {
        parse_requirement_spec(raw, Path::new("pyproject.toml"))
    }

    #[test]
    fn parenthesized_range_parses() {
        let dep = spec("poetry-core (>=2.1.0,<3.0.0)").unwrap().unwrap();
        assert_eq!(dep.name, "poetry-core");
        assert_eq!(dep.version.as_deref(), Some(">=2.1.0,<3.0.0"));
    }

    #[test]
    fn parenthesized_exact_pin_parses() {
        let dep = spec("requests(==2.32.3)").unwrap().unwrap();
        assert_eq!(dep.name, "requests");
        assert_eq!(dep.version.as_deref(), Some("==2.32.3"));
    }

    #[test]
    fn parenthesized_version_with_extras_and_marker_parses() {
        let dep = spec("httpx[http2] (>=0.27) ; python_version >= '3.9'")
            .unwrap()
            .unwrap();
        assert_eq!(dep.name, "httpx");
        assert_eq!(dep.version.as_deref(), Some(">=0.27"));
    }

    #[test]
    fn unbalanced_parentheses_are_rejected() {
        for raw in ["poetry-core (>=2.1.0", "poetry-core >=2.1.0)", "(>=1.0)"] {
            assert!(spec(raw).is_err(), "{raw:?} must be rejected");
        }
    }

    #[test]
    fn plain_specifiers_are_unchanged() {
        let dep = spec("requests>=2.0,<3").unwrap().unwrap();
        assert_eq!(dep.version.as_deref(), Some(">=2.0,<3"));
    }
}
