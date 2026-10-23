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

fn assert_cfg_blocked(name: &str, body: &str) {
    let dir = setup_test_dir(name, "setup.cfg", body);
    let err = parse(&dir).expect_err("setup.cfg must be rejected");
    assert!(
        err.to_string().contains("Scan not supported"),
        "unexpected error: {err}"
    );
    cleanup(&dir);
}

#[test]
fn non_empty_dependency_links_block() {
    assert_cfg_blocked(
        "cfg-dep-links",
        "[options]\ndependency_links =\n    https://evil.example/pkg-1.0.tar.gz#egg=pkg-1.0\n",
    );
}

#[test]
fn dashed_dependency_links_block() {
    assert_cfg_blocked(
        "cfg-dep-links-dashed",
        "[options]\ndependency-links = https://evil.example/pkg.tar.gz\n",
    );
}

#[test]
fn empty_dependency_links_are_allowed() {
    let dir = setup_test_dir(
        "cfg-dep-links-empty",
        "setup.cfg",
        "[options]\ndependency_links =\ninstall_requires = requests==2.0.0\n",
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    cleanup(&dir);
}

#[test]
fn easy_install_section_with_index_url_blocks() {
    assert_cfg_blocked(
        "cfg-easy-install",
        "[easy_install]\nindex_url = https://evil.example/simple\n",
    );
}

#[test]
fn easy_install_find_links_blocks() {
    assert_cfg_blocked(
        "cfg-easy-install-links",
        "[easy_install]\nfind-links = https://evil.example/\n",
    );
}

#[test]
fn empty_easy_install_section_is_allowed() {
    let dir = setup_test_dir(
        "cfg-easy-install-empty",
        "setup.cfg",
        "[easy_install]\n[options]\ninstall_requires = requests==2.0.0\n",
    );
    assert_eq!(parse(&dir).unwrap().len(), 1);
    cleanup(&dir);
}

#[test]
fn unknown_dependency_looking_options_key_blocks() {
    assert_cfg_blocked(
        "cfg-unknown-dep-key",
        "[options]\ninstall_requires_extra = evil==1\n",
    );
}

#[test]
fn metadata_and_packaging_options_are_ignored() {
    let dir = setup_test_dir(
        "cfg-meta-ok",
        "setup.cfg",
        "[metadata]\nname = demo\nversion = 1.0\n[options]\npackages = find:\npython_requires = >=3.8\ninclude_package_data = True\nzip_safe = False\ninstall_requires = requests==2.0.0\n",
    );
    assert_eq!(parse(&dir).unwrap().len(), 1);
    cleanup(&dir);
}
