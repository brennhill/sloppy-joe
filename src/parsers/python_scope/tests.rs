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
        resolve_marker_variable("platform_release", &profile, None).is_ok(),
        "platform_release should be a supported marker variable"
    );
}

#[test]
fn platform_version_marker_uses_profile_value() {
    let profile = PythonProfile::runtime_for_current_host();
    assert!(
        resolve_marker_variable("platform_version", &profile, None).is_ok(),
        "platform_version should be a supported marker variable"
    );
}
