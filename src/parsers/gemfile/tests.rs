use super::*;
use crate::parsers::test_utils::*;

fn setup_dir(content: &str) -> std::path::PathBuf {
    setup_test_dir("gemfile", "Gemfile", content)
}

#[test]
fn parse_single_quotes() {
    let dir = setup_dir("gem 'rails'");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "rails");
    assert_eq!(deps[0].ecosystem, crate::Ecosystem::Ruby);
    cleanup(&dir);
}

#[test]
fn parse_double_quotes() {
    let dir = setup_dir("gem \"rails\"");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "rails");
    cleanup(&dir);
}

#[test]
fn parse_literal_groups_and_multiline_gems_with_comments() {
    let dir = setup_dir(
        r#"
source("https://rubygems.org") # registry
ruby "3.2" # runtime
group :development, :test do
  gem(
"rake", # package name
"13.0.6" # pinned version
  )
end
"#,
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "rake");
    assert_eq!(deps[0].version.as_deref(), Some("13.0.6"));
    cleanup(&dir);
}

#[test]
fn parse_parenthesized_and_indented_gems() {
    for declaration in ["gem('rake', '13.0.6')", "  gem 'rake', '13.0.6'"] {
        let dir = setup_dir(declaration);
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rake");
        assert_eq!(deps[0].version.as_deref(), Some("13.0.6"));
        cleanup(&dir);
    }
}

#[test]
fn parse_with_version() {
    let dir = setup_dir("gem 'rails', '~> 7.0'");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "rails");
    assert_eq!(deps[0].version, Some("~> 7.0".to_string()));
    cleanup(&dir);
}

#[test]
fn parse_exact_version() {
    let dir = setup_dir("gem 'rails', '7.0.4'");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].version, Some("7.0.4".to_string()));
    cleanup(&dir);
}

#[test]
fn skip_comments_and_blank_lines() {
    let dir = setup_dir("# comment\n\ngem 'rails'\n  \n# another");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    cleanup(&dir);
}

#[test]
fn multiple_gems() {
    let dir = setup_dir("gem 'rails'\ngem \"puma\"\ngem 'sidekiq', '~> 6.0'");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 3);
    cleanup(&dir);
}

#[test]
fn extract_gem_name_single_quotes() {
    assert_eq!(
        extract_gem_spec("gem 'rails'"),
        Some(("rails".to_string(), None))
    );
}

#[test]
fn extract_gem_name_double_quotes() {
    assert_eq!(
        extract_gem_spec("gem \"puma\""),
        Some(("puma".to_string(), None))
    );
}

#[test]
fn extract_gem_name_no_quotes() {
    assert_eq!(extract_gem_spec("gem rails"), None);
}

#[test]
fn extract_gem_name_and_version() {
    assert_eq!(
        extract_gem_spec("gem 'rails', '7.0.4'"),
        Some(("rails".to_string(), Some("7.0.4".to_string())))
    );
}

#[test]
fn reject_repository_bundler_mirror_configuration() {
    let dir = setup_dir("source 'https://rubygems.org'\ngem 'rake', '13.0.6'\n");
    std::fs::create_dir(dir.join(".bundle")).unwrap();
    std::fs::write(
        dir.join(".bundle/config"),
        "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: https://attacker.example\n",
    )
    .unwrap();
    let err = parse(&dir).expect_err("Bundler mirrors can redirect otherwise trusted gems");
    assert!(err.to_string().contains(".bundle/config"));
    cleanup(&dir);
}

#[test]
fn reject_side_effects_in_otherwise_literal_gemfile_statements() {
    for body in [
        "gem 'rake', '13.0.6' and gem 'payload', '1.0.0'",
        "gem 'rake', '13.0.6', require: gem('payload', '1.0.0')",
        "group gem('payload', '1.0.0') do\nend",
        "ruby '3.2' if gem('payload', '1.0.0')",
    ] {
        let dir = setup_dir(body);
        assert!(
            parse(&dir).is_err(),
            "unmodeled expressions must fail closed: {body}"
        );
        cleanup(&dir);
    }
}

#[test]
fn reject_dynamic_or_hidden_gem_declarations() {
    for body in [
        "gem package_name",
        "eval_gemfile 'other.Gemfile'",
        "gemspec",
        "source 'https://rubygems.org'; gem('payload', '1.0.0')",
        "source 'https://rubygems.org' + '.attacker.example'",
        "group :test do gem 'payload', '1.0.0' end",
    ] {
        let dir = setup_dir(body);
        assert!(
            parse(&dir).is_err(),
            "unmodeled Gemfile code must fail closed: {body}"
        );
        cleanup(&dir);
    }
}

#[test]
fn reject_block_level_dependency_sources() {
    for source in [
        "git 'https://example.com/payload.git'",
        "path '../payload'",
        "source 'https://example.com/gems'",
    ] {
        let dir = setup_dir(&format!("{source} do\n gem 'rake', '13.0.6'\nend\n"));
        let err = parse(&dir).expect_err("block sources must not inherit public registry trust");
        assert!(err.to_string().contains("Gemfile dependency source"));
        cleanup(&dir);
    }
}

#[test]
fn reject_git_sourced_gems() {
    let dir = setup_dir("gem 'rails', git: 'https://github.com/rails/rails'");
    let err = parse(&dir).expect_err("Gemfile git sources must fail closed");
    assert!(
        err.to_string()
            .contains("non-registry Gemfile dependency source")
    );
    cleanup(&dir);
}

#[test]
fn reject_multiline_git_sourced_gems() {
    let dir = setup_dir(
        r#"
gem "rails",
  git: "https://github.com/rails/rails",
  branch: "main"
"#,
    );
    let err = parse(&dir).expect_err("multiline Gemfile sources must fail closed");
    assert!(
        err.to_string()
            .contains("non-registry Gemfile dependency source")
    );
    cleanup(&dir);
}
