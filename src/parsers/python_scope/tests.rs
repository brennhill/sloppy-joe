use super::*;

#[test]
fn default_profile_includes_group_only_dependency() {
    let dep = PythonScopedDependency::group_only("pytest", "==8.1.1", "dev");
    let profile = PythonProfile::runtime_for_current_host();
    assert!(dep.is_in_scope(&profile).unwrap());
}

#[test]
fn narrowed_profile_excludes_unselected_group_only_dependency() {
    let dep = PythonScopedDependency::group_only("pytest", "==8.1.1", "dev");
    let profile = PythonProfile::runtime_for_current_host().with_no_groups();
    assert!(!dep.is_in_scope(&profile).unwrap());
}

#[test]
fn selected_group_includes_group_only_dependency() {
    let dep = PythonScopedDependency::group_only("pytest", "==8.1.1", "dev");
    let profile = PythonProfile::runtime_for_current_host().with_group("dev");
    assert!(dep.is_in_scope(&profile).unwrap());
}

#[test]
fn group_selection_compares_normalized_names() {
    let dep = PythonScopedDependency::group_only("pytest", "==8.1.1", "Test_Utils");
    let profile = PythonProfile::runtime_for_current_host().with_group("test-utils");
    assert!(dep.is_in_scope(&profile).unwrap());
}

#[test]
fn all_extras_profile_matches_extra_markers() {
    let profile = PythonProfile::for_target("linux", "3.12");
    assert!(evaluate_marker_for_profile_extras(r#"extra == "cli""#, &profile).unwrap());
    assert!(
        !evaluate_marker_for_profile_extras(
            r#"extra == "cli" and sys_platform == "win32""#,
            &profile
        )
        .unwrap()
    );
}

#[test]
fn non_matching_marker_excludes_dependency() {
    let dep = PythonScopedDependency::runtime_with_marker(
        "pywin32",
        "==306",
        r#"sys_platform == "win32""#,
    );
    let profile = PythonProfile::for_target("linux", "3.12");
    assert!(!dep.is_in_scope(&profile).unwrap());
}

#[test]
fn matching_marker_includes_dependency() {
    let dep = PythonScopedDependency::runtime_with_marker(
        "pywin32",
        "==306",
        r#"sys_platform == "win32""#,
    );
    let profile = PythonProfile::for_target("win32", "3.12");
    assert!(dep.is_in_scope(&profile).unwrap());
}

#[test]
fn python_version_marker_uses_numeric_comparison() {
    let dep = PythonScopedDependency::runtime_with_marker(
        "requests",
        "==2.31.0",
        r#"python_version < "3.13""#,
    );
    let profile = PythonProfile::for_target("linux", "3.12");
    assert!(dep.is_in_scope(&profile).unwrap());
}

#[test]
fn marker_in_operator_uses_pep508_substring_semantics() {
    let linux = PythonProfile::for_target("linux", "3.12");
    assert!(evaluate_marker(r#""lin" in sys_platform"#, &linux).unwrap());
    assert!(evaluate_marker(r#"sys_platform in "linux,darwin""#, &linux).unwrap());
    assert!(!evaluate_marker(r#""win" in sys_platform"#, &linux).unwrap());
}

#[test]
fn parse_detected_python_version_output_reads_short_and_full_version() {
    let detected = parse_detected_python_version_output(b"3.12\n3.12.7\n").unwrap();
    assert_eq!(detected.python_version, "3.12");
    assert_eq!(detected.python_full_version, "3.12.7");
}

#[test]
fn platform_machine_marker_uses_selected_target_arch() {
    let profile = PythonProfile::for_target_with_arch("linux", "3.12", "aarch64");
    assert!(evaluate_marker(r#"platform_machine == "aarch64""#, &profile).unwrap());
    assert!(!evaluate_marker(r#"platform_machine == "x86_64""#, &profile).unwrap());
}

#[test]
fn implementation_version_marker_uses_full_python_version() {
    let profile = PythonProfile::for_target("linux", "3.12");
    assert!(evaluate_marker(r#"implementation_version == "3.12.0""#, &profile).unwrap());
}

#[test]
fn platform_release_marker_uses_profile_value() {
    let profile = PythonProfile::runtime_for_current_host();
    assert!(
        resolve_marker_variable("platform_release", &profile, None).is_some(),
        "platform_release should resolve for the host"
    );
}

#[test]
fn platform_version_marker_uses_profile_value() {
    let profile = PythonProfile::runtime_for_current_host();
    assert!(
        resolve_marker_variable("platform_version", &profile, None).is_some(),
        "platform_version should resolve for the host"
    );
}

#[test]
fn python_version_wildcards_match_like_pip() {
    let profile = PythonProfile::for_target("linux", "3.12");
    assert!(evaluate_marker(r#"python_version == "3.*""#, &profile).unwrap());
    assert!(!evaluate_marker(r#"python_version != "3.*""#, &profile).unwrap());
    assert!(!evaluate_marker(r#"python_version == "2.*""#, &profile).unwrap());
}

#[test]
fn prerelease_interpreters_compare_by_pep440() {
    let mut profile = PythonProfile::for_target("linux", "3.13");
    profile.python_full_version = Some("3.13.0rc1".to_string());
    assert!(!evaluate_marker(r#"python_full_version >= "3.13""#, &profile).unwrap());
    // PEP 440 (pip) excludes 3.13.0rc1 from `< 3.13`; uv's ordering includes it. Undecided,
    // so the dependency stays in scope.
    assert!(evaluate_marker(r#"python_full_version < "3.13""#, &profile).unwrap());
    assert!(evaluate_marker(r#"python_full_version < "3.12""#, &profile).is_ok_and(|v| !v));
    assert!(evaluate_marker(r#"python_full_version >= "3.13.0rc1""#, &profile).unwrap());
}

#[test]
fn platform_machine_uses_the_name_python_reports_on_each_os() {
    let mac = PythonProfile::for_target_with_arch("darwin", "3.12", "aarch64");
    assert!(evaluate_marker(r#"platform_machine == "arm64""#, &mac).unwrap());
    assert!(!evaluate_marker(r#"platform_machine == "aarch64""#, &mac).unwrap());
    let linux = PythonProfile::for_target_with_arch("linux", "3.12", "arm64");
    assert!(evaluate_marker(r#"platform_machine == "aarch64""#, &linux).unwrap());
    let windows = PythonProfile::for_target_with_arch("win32", "3.12", "x86_64");
    assert!(evaluate_marker(r#"platform_machine == "AMD64""#, &windows).unwrap());
}

#[test]
fn comparisons_the_tools_disagree_on_count_as_true() {
    let linux = PythonProfile::for_target("linux", "3.12");
    // `< "3.*"` is not a PEP 440 specifier: pip falls back to strings, uv rejects it.
    assert!(evaluate_marker(r#"python_version < "3.*""#, &linux).unwrap());
    assert!(evaluate_marker(r#"python_version >= "3.*""#, &linux).unwrap());
    // A decided false still settles an `and`.
    assert!(
        !evaluate_marker(
            r#"python_version < "3.*" and sys_platform == "win32""#,
            &linux
        )
        .unwrap()
    );
    // An OS whose machine names the table does not know.
    let other = PythonProfile::for_target_with_arch("freebsd", "3.12", "aarch64");
    assert!(evaluate_marker(r#"platform_machine == "x86_64""#, &other).unwrap());
    assert!(evaluate_marker(r#"platform_machine != "x86_64""#, &other).unwrap());
}

#[test]
fn an_unknown_python_version_is_undecided_not_an_error() {
    let mut profile = PythonProfile::for_target("linux", "3.12");
    profile.python_version = None;
    profile.python_full_version = None;
    assert!(evaluate_marker(r#"python_version >= "3.8""#, &profile).unwrap());
    assert!(evaluate_marker(r#"python_version < "3.8""#, &profile).unwrap());
    let mut dep = PythonScopedDependency::runtime(
        crate::test_helpers::dep_with("legacy", Some("==1.0"), crate::Ecosystem::PyPI),
        None,
    );
    dep.python_constraint = Some("<3.8".to_string());
    assert!(dep.is_in_scope(&profile).unwrap());
}

#[test]
fn extra_names_compare_normalized() {
    let profile = PythonProfile::for_target("linux", "3.12");
    let selected = BTreeSet::from(["foo-bar".to_string()]);
    assert!(evaluate_marker_for_extras(r#"extra == "Foo_Bar""#, &profile, &selected).unwrap());
    assert!(evaluate_marker_for_profile_extras(r#"extra == "Foo_Bar""#, &profile).unwrap());
}

#[test]
fn compatible_release_and_dotted_aliases_are_supported() {
    let profile = PythonProfile::for_target("linux", "3.12");
    assert!(evaluate_marker(r#"python_full_version ~= "3.12.0""#, &profile).unwrap());
    assert!(!evaluate_marker(r#"python_full_version ~= "3.11.0""#, &profile).unwrap());
    assert!(evaluate_marker(r#"sys.platform == "linux""#, &profile).unwrap());
    assert!(evaluate_marker(r#"os.name == "posix""#, &profile).unwrap());
}

#[test]
fn deeply_nested_markers_are_refused_instead_of_overflowing_the_stack() {
    let profile = PythonProfile::for_target("linux", "3.12");
    let nested = |depth: usize| {
        format!(
            "{}sys_platform == 'linux'{}",
            "(".repeat(depth),
            ")".repeat(depth)
        )
    };
    assert!(evaluate_marker(&nested(MAX_MARKER_DEPTH), &profile).unwrap());
    let err = evaluate_marker(&nested(MAX_MARKER_DEPTH + 1), &profile).unwrap_err();
    assert!(err.to_string().contains("nested"), "{err}");
    let err = evaluate_marker(&nested(200_000), &profile).unwrap_err();
    assert!(err.to_string().contains("tokens"), "{err}");
}

#[test]
fn long_marker_chains_stay_flat_and_bounded() {
    let profile = PythonProfile::for_target("linux", "3.12");
    let chain = |clauses: usize| {
        (0..clauses)
            .map(|i| format!("platform_release != 'x{i}'"))
            .collect::<Vec<_>>()
            .join(" and ")
    };
    // 1000 clauses evaluate without deep recursion.
    assert!(evaluate_marker(&chain(1000), &profile).is_ok());
    let err = evaluate_marker(&chain(20_000), &profile).unwrap_err();
    assert!(err.to_string().contains("tokens"), "{err}");
    // The refusal quotes the start of the marker, not all 600 KB of it.
    assert!(err.to_string().len() < 400, "{}", err.to_string().len());
}

fn versions_with(
    settings: &[(&str, &str)],
    detected: Option<(&str, &str)>,
) -> (Option<String>, Option<String>) {
    let lookup = |name: &str| {
        settings
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_string())
    };
    python_versions_from(lookup, || {
        detected.map(|(version, full)| DetectedPythonVersion {
            python_version: version.to_string(),
            python_full_version: full.to_string(),
        })
    })
}

fn pair(version: &str, full: &str) -> (Option<String>, Option<String>) {
    (Some(version.to_string()), Some(full.to_string()))
}

#[test]
fn a_configured_python_version_is_trimmed_and_split_into_markers() {
    assert_eq!(
        versions_with(&[("PYTHON_VERSION", " 3.12 \n")], None),
        pair("3.12", "3.12.0")
    );
    // Docker images set PYTHON_VERSION to the full version.
    assert_eq!(
        versions_with(&[("PYTHON_VERSION", "3.12.1")], None),
        pair("3.12", "3.12.1")
    );
    assert_eq!(
        versions_with(&[("SLOPPY_JOE_PYTHON_VERSION", "3.13.0rc1")], None),
        pair("3.13", "3.13.0rc1")
    );
}

#[test]
fn an_unreadable_python_version_setting_is_unknown_not_the_host() {
    assert_eq!(
        versions_with(&[("PYTHON_VERSION", "banana")], Some(("3.12", "3.12.4"))),
        (None, None)
    );
    // A blank setting is no setting.
    assert_eq!(
        versions_with(&[("PYTHON_VERSION", "  ")], Some(("3.12", "3.12.4"))),
        pair("3.12", "3.12.4")
    );
}

#[test]
fn a_configured_version_never_mixes_with_the_host_full_version() {
    assert_eq!(
        versions_with(&[("PYTHON_VERSION", "3.11")], Some(("3.12", "3.12.4"))),
        pair("3.11", "3.11.0")
    );
    assert_eq!(
        versions_with(
            &[
                ("PYTHON_VERSION", "3.11"),
                ("PYTHON_FULL_VERSION", "3.11.2")
            ],
            None
        ),
        pair("3.11", "3.11.2")
    );
    assert_eq!(
        versions_with(
            &[
                ("PYTHON_VERSION", "3.11"),
                ("PYTHON_FULL_VERSION", "3.12.1")
            ],
            None
        ),
        (Some("3.11".to_string()), None)
    );
    assert_eq!(
        versions_with(
            &[("PYTHON_FULL_VERSION", " 3.12.1 ")],
            Some(("3.10", "3.10.2"))
        ),
        pair("3.12", "3.12.1")
    );
}
