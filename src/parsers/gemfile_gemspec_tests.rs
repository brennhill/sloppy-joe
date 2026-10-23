//! `gemspec` pulls the dependencies of the project's own `.gemspec` into the
//! bundle. Literal declarations are scanned; anything dynamic fails closed.

use super::*;
use crate::parsers::test_utils::*;

fn parse_with_gemspec(gemfile: &str, gemspec: Option<(&str, &str)>) -> Result<Vec<Dependency>> {
    let dir = setup_test_dir("gemfile-gemspec", "Gemfile", gemfile);
    if let Some((name, body)) = gemspec {
        std::fs::write(dir.join(name), body).unwrap();
    }
    let result = parse(&dir);
    cleanup(&dir);
    result
}

const SPEC: &str = r#"Gem::Specification.new do |s|
  s.name = "demo"
  s.add_runtime_dependency("addressable", "~> 2.4")
  s.add_dependency 'rack', '>= 2.2', '< 4'
  s.add_development_dependency "rake"
end
"#;

fn summary(deps: &[Dependency]) -> Vec<(String, Option<String>)> {
    deps.iter()
        .map(|d| (d.name.clone(), d.version.clone()))
        .collect()
}

#[test]
fn bare_gemspec_scans_the_gemspec_dependencies() {
    let deps = parse_with_gemspec(
        "source 'https://rubygems.org'\ngemspec\ngem 'minitest'",
        Some(("demo.gemspec", SPEC)),
    )
    .unwrap();
    assert_eq!(
        summary(&deps),
        vec![
            ("minitest".to_string(), None),
            ("addressable".to_string(), Some("~> 2.4".to_string())),
            ("rack".to_string(), Some(">= 2.2, < 4".to_string())),
            ("rake".to_string(), None),
        ]
    );
}

#[test]
fn named_gemspec_selects_that_file() {
    let deps =
        parse_with_gemspec("gemspec :name => \"demo\"", Some(("demo.gemspec", SPEC))).unwrap();
    assert_eq!(deps.len(), 3);
    let deps = parse_with_gemspec("gemspec name: 'demo'", Some(("demo.gemspec", SPEC))).unwrap();
    assert_eq!(deps.len(), 3);
}

#[test]
fn gemspec_without_a_gemspec_file_blocks() {
    assert!(parse_with_gemspec("gemspec", None).is_err());
}

#[test]
fn several_gemspecs_without_a_name_block() {
    let dir = setup_test_dir("gemfile-gemspec-many", "Gemfile", "gemspec");
    std::fs::write(dir.join("a.gemspec"), SPEC).unwrap();
    std::fs::write(dir.join("b.gemspec"), SPEC).unwrap();
    let result = parse(&dir);
    cleanup(&dir);
    assert!(result.is_err());
}

#[test]
fn gemspec_options_that_redirect_the_file_block() {
    for statement in [
        "gemspec path: '../other'",
        "gemspec :path => 'x'",
        "gemspec name: 'demo', glob: '*.x'",
        "gemspec name: demo_name",
        "gemspec(name: 'a/b')",
    ] {
        assert!(
            parse_with_gemspec(statement, Some(("demo.gemspec", SPEC))).is_err(),
            "{statement}"
        );
    }
}

#[test]
fn dynamic_gemspec_dependencies_block() {
    for body in [
        "Gem::Specification.new { |s| %w[a b].each { |d| s.add_dependency d } }",
        "Gem::Specification.new { |s| s.add_dependency NAME, '~> 1' }",
        "Gem::Specification.new { |s| s.add_dependency 'a', VERSION }",
        "Gem::Specification.new { |s| s.add_dependency \"a#{suffix}\" }",
        "Gem::Specification.new { |s| s.add_dependency 'a', '~> 1', :require => x }",
    ] {
        assert!(
            parse_with_gemspec("gemspec", Some(("demo.gemspec", body))).is_err(),
            "{body}"
        );
    }
}

#[test]
fn gemspec_with_no_dependencies_is_fine() {
    let deps = parse_with_gemspec(
        "gemspec\ngem 'rake'",
        Some((
            "demo.gemspec",
            "Gem::Specification.new { |s| s.name = 'demo' }",
        )),
    )
    .unwrap();
    assert_eq!(summary(&deps), vec![("rake".to_string(), None)]);
}

#[test]
fn gemspec_dependency_names_are_validated() {
    let body = "Gem::Specification.new { |s| s.add_dependency '../evil' }";
    assert!(parse_with_gemspec("gemspec", Some(("demo.gemspec", body))).is_err());
}

fn parse_gemfile(body: &str) -> Result<Vec<Dependency>> {
    parse_with_gemspec(body, None)
}

#[test]
fn simple_conditionals_scan_every_branch() {
    let deps = parse_gemfile(
        "gem 'a'\nif RUBY_ENGINE == \"jruby\"\n  gem 'b', '1.0'\nelsif ENV[\"CI\"]\n  gem 'c'\nelse\n  gem 'd'\nend\nunless RUBY_VERSION >= \"3.4\"\n  gem 'e'\nend\ngem 'f' unless RUBY_ENGINE == \"jruby\"\ngem 'g', '~> 1' if ENV['X']\n",
    )
    .unwrap();
    let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["a", "b", "c", "d", "e", "f", "g"]);
    assert_eq!(deps[6].version.as_deref(), Some("~> 1"));
}

#[test]
fn conditions_that_could_declare_gems_or_run_code_block() {
    for body in [
        "if gem('x')\n gem 'a'\nend",
        "if system('curl x | sh')\n gem 'a'\nend",
        "if File.exist?('x')\n gem 'a'\nend",
        "if ENV['X'] then gem 'a' end",
        "gem 'a' if gem('evil')",
        "if ENV['X']; gem 'a'; end",
        "if x ||\n y\n gem 'a'\nend",
    ] {
        assert!(parse_gemfile(body).is_err(), "{body}");
    }
}

#[test]
fn modifiers_do_not_hide_sources() {
    assert!(parse_gemfile("gem 'a', git: 'https://x.example/a.git' if ENV['X']").is_err());
    assert!(parse_gemfile("gem 'a', path: 'a' unless ENV['X']").is_err());
}
