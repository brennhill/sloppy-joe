//! Red-team regressions: setuptools accepts dashed option names, so they must be scanned.

use super::*;
use crate::parsers::test_utils::*;

#[test]
fn dashed_install_requires_is_scanned() {
    let dir = setup_test_dir(
        "cfg-dashed",
        "setup.cfg",
        "[metadata]\nname = demo\n\n[options]\ninstall-requires =\n    evil-dash==1\n",
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(
        deps.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
        vec!["evil-dash"]
    );
    cleanup(&dir);
}

#[test]
fn dashed_setup_and_tests_requires_and_extras_section_are_scanned() {
    let dir = setup_test_dir(
        "cfg-dashed-all",
        "setup.cfg",
        "[options]\nsetup-requires = evil-setup==1\ntests-require = evil-tests==1\n[options.extras-require]\ndev = evil-extra==1\n",
    );
    let names: Vec<String> = parse(&dir).unwrap().into_iter().map(|d| d.name).collect();
    for expected in ["evil-setup", "evil-tests", "evil-extra"] {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
    cleanup(&dir);
}
