//! Gemfile entries with several version constraints are ordinary Bundler
//! syntax (`gem 'x', '~> 1.0', '>= 1.0.2'`) and must be parsed, keeping every
//! constraint, while anything dynamic still fails closed.

use super::*;
use crate::parsers::test_utils::*;

fn parse_body(body: &str) -> Result<Vec<Dependency>> {
    let dir = setup_test_dir("gemfile-multi", "Gemfile", body);
    let result = parse(&dir);
    cleanup(&dir);
    result
}

#[test]
fn multiple_version_constraints_are_kept_together() {
    let deps = parse_body("gem 'rails', '~> 7.0', '>= 7.0.2'").unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "rails");
    assert_eq!(deps[0].version.as_deref(), Some("~> 7.0, >= 7.0.2"));
}

#[test]
fn multiple_constraints_accept_parens_options_and_multiline_layouts() {
    for body in [
        "gem('rails', '~> 7.0', '>= 7.0.2')",
        "gem \"rails\", \">= 7.0\", \"< 8\", \"!= 7.0.3\", require: false",
        "gem 'rails',\n  '~> 7.0',\n  '>= 7.0.2',\n  group: :test",
    ] {
        let deps = parse_body(body).unwrap_or_else(|err| panic!("{body}: {err}"));
        assert_eq!(deps.len(), 1, "{body}");
        assert_eq!(deps[0].name, "rails", "{body}");
        let version = deps[0].version.as_deref().unwrap();
        assert!(version.contains(", "), "{body}: {version}");
    }
}

#[test]
fn multiple_constraints_never_count_as_an_exact_pin() {
    let deps = parse_body("gem 'rails', '7.0.4', '!= 7.0.3'").unwrap();
    assert_eq!(deps[0].exact_version(), None);
}

#[test]
fn malformed_or_dynamic_constraints_fail_closed() {
    for body in [
        "gem 'rails', '~> 7.0', version",
        "gem 'rails', '~> 7.0', \"#{v}\"",
        "gem 'rails', '~> 7.0', ''",
        "gem 'rails', '~> 7.0', 'not a version'",
        "gem 'rails', '~> 7.0', '>= 7.0, < 8'",
        "gem 'rails', '~> 7.0', '=> 7.0'",
        "gem 'rails', '~> 7.0', git: 'https://example.com/rails.git'",
    ] {
        assert!(parse_body(body).is_err(), "must fail closed: {body}");
    }
}

#[test]
fn multiple_constraints_resolve_from_the_lockfile_like_a_single_range() {
    let deps = parse_body("gem 'rails', '~> 7.0', '>= 7.0.2'").unwrap();
    let single = parse_body("gem 'rails', '~> 7.0'").unwrap();
    let lockfile = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n\nDEPENDENCIES\n  rails (~> 7.0, >= 7.0.2)\n";
    let dir = setup_test_dir("gemfile-multi-lock", "Gemfile.lock", lockfile);
    let multi = crate::lockfiles::resolve_versions(&dir, &deps).unwrap();
    let one = crate::lockfiles::resolve_versions(&dir, &single).unwrap();
    cleanup(&dir);
    assert_eq!(multi.exact_versions.len(), one.exact_versions.len());
    assert_eq!(multi.issues.len(), one.issues.len());
    let names = |issues: &[crate::report::Issue]| {
        issues.iter().map(|i| i.check.clone()).collect::<Vec<_>>()
    };
    assert_eq!(names(&multi.issues), names(&one.issues));
}
