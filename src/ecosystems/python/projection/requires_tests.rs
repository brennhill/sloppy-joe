use super::*;

fn profile() -> PythonProfile {
    let mut profile = PythonProfile::runtime_for_current_host().for_every_environment();
    profile.all_extras = true;
    profile
}

fn none() -> Extras {
    Extras::Requested(BTreeSet::new())
}

fn requested(extras: &[&str]) -> Extras {
    Extras::Requested(extras.iter().map(|extra| extra.to_string()).collect())
}

#[test]
fn a_plain_requirement_is_read_with_its_normalized_name_specifier_and_extras() {
    let req = applicable(
        "Foo_Bar[Socks,security] (<3,>=1.21.1)",
        "owner",
        &none(),
        &profile(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(req.name, "foo-bar");
    assert_eq!(req.specifier, "<3,>=1.21.1");
    assert_eq!(
        req.extras,
        ["security", "socks"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    );
    let bare = applicable("idna", "owner", &none(), &profile())
        .unwrap()
        .unwrap();
    assert_eq!(bare.specifier, "");
}

#[test]
fn environment_markers_never_drop_a_requirement() {
    for marker in [
        "sys_platform == \"win32\"",
        "python_version < \"3.8\"",
        "platform_machine == \"arm64\" and os_name == \"nt\"",
    ] {
        let raw = format!("colorama; {marker}");
        assert!(
            applicable(&raw, "owner", &none(), &profile())
                .unwrap()
                .is_some(),
            "{marker}"
        );
    }
}

#[test]
fn extra_markers_follow_the_requested_extras() {
    let raw = "PySocks!=1.5.7,>=1.5.6; extra == \"socks\"";
    assert!(
        applicable(raw, "requests", &none(), &profile())
            .unwrap()
            .is_none()
    );
    assert!(
        applicable(raw, "requests", &requested(&["socks"]), &profile())
            .unwrap()
            .is_some()
    );
    assert!(
        applicable(raw, "requests", &requested(&["other"]), &profile())
            .unwrap()
            .is_none()
    );
}

#[test]
fn unknown_extras_count_every_extra_a_marker_names() {
    let raw = "PySocks>=1.5.6; extra == \"socks\" and sys_platform == \"linux\"";
    assert!(
        applicable(raw, "requests", &Extras::Any, &profile())
            .unwrap()
            .is_some()
    );
}

#[test]
fn an_unreadable_marker_keeps_the_requirement() {
    assert!(
        applicable("evil; not a ( marker", "owner", &none(), &profile())
            .unwrap()
            .is_some()
    );
}

#[test]
fn direct_url_and_local_requirements_cannot_be_projected() {
    for raw in [
        "evil @ https://example.com/evil.whl",
        "git+https://example.com/evil.git",
        "./vendored",
    ] {
        assert!(
            applicable(raw, "owner", &none(), &profile()).is_err(),
            "{raw}"
        );
    }
}
