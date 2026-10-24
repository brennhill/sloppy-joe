use super::*;
use crate::parsers::test_utils::*;

fn setup_dir(content: &str) -> std::path::PathBuf {
    setup_test_dir("req", "requirements.txt", content)
}

#[test]
fn parse_simple_version() {
    let dir = setup_dir("requests==2.28.0\nflask==2.3.0");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version, Some("==2.28.0".to_string()));
    assert_eq!(deps[0].ecosystem, crate::Ecosystem::PyPI);
    cleanup(&dir);
}

#[test]
fn parse_version_range() {
    let dir = setup_dir("requests>=1.0,<2.0");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version, Some(">=1.0,<2.0".to_string()));
    cleanup(&dir);
}

#[test]
fn skip_comments_and_blank_lines() {
    let dir = setup_dir("# this is a comment\n\nrequests==1.0\n  \n# another comment");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    cleanup(&dir);
}

#[test]
fn parse_bare_package_name() {
    let dir = setup_dir("requests\nflask");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    assert_eq!(deps[0].version, None);
    assert_eq!(deps[1].version, None);
    cleanup(&dir);
}

#[test]
fn parse_include_flag_with_following_dependency() {
    let dir = setup_dir("-r other.txt\nrequests==1.0");
    std::fs::write(dir.join("other.txt"), "flask==2.0\n").unwrap();
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.iter().any(|dep| dep.name == "requests"));
    assert!(deps.iter().any(|dep| dep.name == "flask"));
    cleanup(&dir);
}

#[test]
fn reject_malformed_long_requirement_directive() {
    let dir = setup_dir("--requirementother.txt\nrequests==1.0");
    let err = parse(&dir).expect_err("malformed long requirement directives must not parse");
    assert!(err.to_string().contains("--requirementother.txt"));
    cleanup(&dir);
}

#[test]
fn parse_long_requirement_equals_syntax() {
    let dir = setup_dir("--requirement=other.txt\nrequests==1.0");
    std::fs::write(dir.join("other.txt"), "flask==2.0\n").unwrap();
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.iter().any(|dep| dep.name == "requests"));
    assert!(deps.iter().any(|dep| dep.name == "flask"));
    cleanup(&dir);
}

#[test]
fn reject_url_based_requirements() {
    let dir = setup_dir("git+https://github.com/user/repo.git#egg=pkg\nrequests==1.0");
    let err = parse(&dir).expect_err("unsupported direct references must block scanning");
    assert!(
        err.to_string()
            .contains("git+https://github.com/user/repo.git#egg=pkg")
    );
    cleanup(&dir);
}

#[test]
fn reject_url_with_egg_fragment() {
    let dir = setup_dir("git+https://github.com/user/repo.git@v1.0#egg=mypkg\nflask==2.0");
    let err = parse(&dir).expect_err("egg-based direct references must block scanning");
    assert!(
        err.to_string()
            .contains("git+https://github.com/user/repo.git@v1.0#egg=mypkg")
    );
    cleanup(&dir);
}

#[test]
fn strip_environment_markers() {
    let dir = setup_dir("pywin32>=300; sys_platform == \"win32\"");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "pywin32");
    assert_eq!(deps[0].version, Some(">=300".to_string()));
    cleanup(&dir);
}

#[test]
fn trusted_pip_tools_preserves_marker() {
    let dep = parse_scoped_requirement_spec(
        "pywin32==306 ; sys_platform == \"win32\" --hash=sha256:deadbeef",
        Path::new("requirements.txt"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(dep.marker.as_deref(), Some(r#"sys_platform == "win32""#));
}

#[test]
fn trusted_pip_tools_does_not_treat_marker_bearing_dep_as_universal() {
    let dep = parse_scoped_requirement_spec(
        "pywin32==306 ; sys_platform == \"win32\" --hash=sha256:deadbeef",
        Path::new("requirements.txt"),
    )
    .unwrap()
    .unwrap();
    let profile = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
    assert!(!dep.is_in_scope(&profile).unwrap());
}

#[test]
fn environment_marker_bare_package() {
    let dir = setup_dir("pywin32; sys_platform == \"win32\"");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "pywin32");
    assert_eq!(deps[0].version, None);
    cleanup(&dir);
}

#[test]
fn strip_extras_from_distribution_name() {
    let dir = setup_dir("requests[socks]==2.28.0");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version, Some("==2.28.0".to_string()));
    cleanup(&dir);
}

#[test]
fn scoped_parser_preserves_requested_distribution_extras() {
    let dep = parse_scoped_requirement_spec(
        "requests[socks,security]==2.28.0",
        Path::new("requirements.txt"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(dep.dependency.name, "requests");
    assert!(dep.requested_extras.contains("socks"));
    assert!(dep.requested_extras.contains("security"));
}

#[test]
fn strip_inline_comments_after_exact_pin() {
    let dir = setup_dir("requests==2.31.0 # production pin\n");
    let deps = parse(&dir)
        .expect("inline comments after exact pins should not make the version unresolved");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version.as_deref(), Some("==2.31.0"));
    cleanup(&dir);
}

#[test]
fn strip_inline_hash_options_after_exact_pin() {
    let dir = setup_dir("requests==2.31.0 --hash=sha256:deadbeef\n");
    let deps = parse(&dir).expect("hash options should not make exact pins unreadable");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version.as_deref(), Some("==2.31.0"));
    cleanup(&dir);
}

#[test]
fn skip_hash_continuation_lines() {
    let dir = setup_dir("requests==2.31.0 \\\n    --hash=sha256:deadbeef\n");
    let deps = parse(&dir).expect("pip-compile hash continuation lines should not fail");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version.as_deref(), Some("==2.31.0"));
    cleanup(&dir);
}

// ── Environment marker edge cases ──

#[test]
fn environment_marker_with_single_quotes() {
    let dir = setup_dir("pywin32>=300; sys_platform == 'win32'");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "pywin32");
    assert_eq!(deps[0].version, Some(">=300".to_string()));
    cleanup(&dir);
}

#[test]
fn environment_marker_semicolon_inside_quotes_not_stripped() {
    // A semicolon inside quotes should NOT be treated as a marker delimiter
    // "pkg>=1.0; extra == \"foo;bar\"" — the ; inside quotes should be ignored
    let dir = setup_dir("pkg>=1.0; extra == \"foo;bar\"");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "pkg");
    assert_eq!(deps[0].version, Some(">=1.0".to_string()));
    cleanup(&dir);
}

// ── -r / --requirement include lines ──

#[test]
fn skip_r_include_flag() {
    let dir = setup_dir("-r base.txt\nflask==2.0");
    std::fs::write(dir.join("base.txt"), "requests==2.31.0\n").unwrap();
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.iter().any(|dep| dep.name == "flask"));
    assert!(deps.iter().any(|dep| dep.name == "requests"));
    cleanup(&dir);
}

#[test]
fn skip_requirement_long_flag() {
    let dir = setup_dir("--requirement base.txt\nflask==2.0");
    std::fs::write(dir.join("base.txt"), "requests==2.31.0\n").unwrap();
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.iter().any(|dep| dep.name == "flask"));
    assert!(deps.iter().any(|dep| dep.name == "requests"));
    cleanup(&dir);
}

#[test]
fn constraint_files_affect_trust_without_becoming_direct_dependencies() {
    let dir = setup_dir("-c base.txt\nflask==2.0 \\\n    --hash=sha256:deadbeef\n");
    std::fs::write(
        dir.join("base.txt"),
        "requests==2.31.0 \\\n    --hash=sha256:feedface\n",
    )
    .unwrap();

    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "flask");
    assert!(
        is_hash_locked_requirements_file(&dir.join("requirements.txt"), &dir)
            .expect("constraint includes should participate in trusted pip-tools classification")
    );
    cleanup(&dir);
}

#[test]
fn supported_index_directives_do_not_block_parsing() {
    let dir = setup_dir(
        "--index-url https://pypi.org/simple\n--extra-index-url https://packages.example.com/simple\nflask==2.0",
    );
    let deps = parse(&dir).expect("supported pip index directives should not block parsing");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "flask");
    cleanup(&dir);
}

#[test]
fn supported_index_directives_preserve_hash_locked_trust_classification() {
    let dir = setup_dir(
        "--index-url https://pypi.org/simple\n--extra-index-url https://packages.example.com/simple\nrequests==2.31.0 \\\n    --hash=sha256:deadbeef\n",
    );
    assert!(
        is_hash_locked_requirements_file(&dir.join("requirements.txt"), &dir)
            .expect("supported pip index directives should still allow trusted classification"),
        "supported file-bound index directives should not demote hash-locked pip-tools manifests"
    );
    cleanup(&dir);
}

#[test]
fn reject_editable_requirements() {
    let dir = setup_dir("-e .\nflask==2.0");
    let err = parse(&dir).expect_err("editable requirements must block scanning");
    assert!(err.to_string().contains("-e ."));
    cleanup(&dir);
}

#[test]
fn reject_other_unsupported_flags() {
    let dir = setup_dir("--trusted-host packages.example.com\nflask==2.0");
    let err = parse(&dir).expect_err("unsupported flags must block scanning");
    assert!(
        err.to_string()
            .contains("--trusted-host packages.example.com")
    );
    cleanup(&dir);
}

#[test]
fn reject_vcs_url_requirements() {
    let dir = setup_dir("git+https://github.com/user/repo.git#egg=mypkg\n");
    let err = parse(&dir).expect_err("unsupported direct references must block scanning");
    assert!(
        err.to_string()
            .contains("git+https://github.com/user/repo.git#egg=mypkg")
    );
    cleanup(&dir);
}

#[test]
fn reject_pep508_direct_url_requirements() {
    let dir = setup_dir("mypkg @ https://example.com/mypkg-1.0.0.tar.gz\n");
    let err = parse(&dir).expect_err("direct URL requirements must block scanning");
    assert!(
        err.to_string()
            .contains("https://example.com/mypkg-1.0.0.tar.gz")
    );
    cleanup(&dir);
}

#[test]
fn reject_local_project_requirements() {
    let dir = setup_dir(".[prod]\n");
    let err = parse(&dir).expect_err("local project requirements must block scanning");
    assert!(err.to_string().contains("Unsupported local requirement"));
    cleanup(&dir);
}

#[test]
fn reject_relative_path_requirements() {
    let dir = setup_dir("./vendor/pkg.whl\n");
    let err = parse(&dir).expect_err("relative path requirements must block scanning");
    assert!(err.to_string().contains("Unsupported local requirement"));
    cleanup(&dir);
}

#[cfg(unix)]
#[test]
fn detect_include_cycles_across_symlink_aliases() {
    let dir = setup_test_dir("req-cycle", "requirements.txt", "-r a/base.txt\n");
    std::fs::create_dir_all(dir.join("real")).unwrap();
    std::fs::write(dir.join("real/base.txt"), "-r ../b/base.txt\n").unwrap();
    std::os::unix::fs::symlink(dir.join("real"), dir.join("a")).unwrap();
    std::os::unix::fs::symlink(dir.join("real"), dir.join("b")).unwrap();

    let err = parse(&dir).expect_err("include cycles through symlink aliases must be detected");
    assert!(err.to_string().contains("include cycle"));
    cleanup(&dir);
}

// ── PEP 503 normalization edge cases ──

#[test]
fn normalize_underscores_and_dots() {
    let dir = setup_dir("My_Package.Name==1.0");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps[0].name, "my-package-name");
    cleanup(&dir);
}

#[test]
fn normalize_consecutive_separators() {
    let dir = setup_dir("my__package..name==1.0");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps[0].name, "my-package-name");
    cleanup(&dir);
}

// ── Tilde-equals version specifier ──

#[test]
fn parse_tilde_equals_version() {
    let dir = setup_dir("Django~=4.2");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps[0].name, "django");
    assert_eq!(deps[0].version, Some("~=4.2".to_string()));
    cleanup(&dir);
}

// ── Not-equals version specifier ──

#[test]
fn parse_not_equals_version() {
    let dir = setup_dir("requests!=2.28.0");
    let deps = parse(&dir).unwrap();
    assert_eq!(deps[0].name, "requests");
    assert_eq!(deps[0].version, Some("!=2.28.0".to_string()));
    cleanup(&dir);
}

// ── find_unquoted_semicolon unit tests ──

#[test]
fn find_unquoted_semicolon_basic() {
    assert_eq!(find_unquoted_semicolon("foo; bar"), Some(3));
}

#[test]
fn find_unquoted_semicolon_none() {
    assert_eq!(find_unquoted_semicolon("foo bar"), None);
}

#[test]
fn find_unquoted_semicolon_in_double_quotes() {
    assert_eq!(find_unquoted_semicolon(r#"foo "a;b" ; bar"#), Some(10));
}

#[test]
fn find_unquoted_semicolon_in_single_quotes() {
    assert_eq!(find_unquoted_semicolon("foo 'a;b' ; bar"), Some(10));
}

// ── normalize_distribution_name unit tests ──

#[test]
fn normalize_distribution_name_strips_extras() {
    assert_eq!(normalize_distribution_name("requests[socks]"), "requests");
}

#[test]
fn normalize_distribution_name_lowercases() {
    assert_eq!(normalize_distribution_name("Flask"), "flask");
}

#[test]
fn normalize_distribution_name_empty_input() {
    assert_eq!(normalize_distribution_name(""), "");
}
