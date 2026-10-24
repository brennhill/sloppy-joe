use super::*;
use crate::parsers::test_utils::*;

#[test]
fn reject_unmodeled_setup_dependencies() {
    for (i, content) in [
        "setup(install_requires=['company-core==1.0.0'] + ['payload==1.0.0'])",
        "setup(**{'install_requires': ['payload==1.0.0']})",
        "setup(install_requires=['company-core==1.0.0'], **options)",
        "setup (install_requires=['payload==1.0.0'])",
    ]
    .iter()
    .enumerate()
    {
        let dir = setup_test_dir(&format!("setup-unmodeled-{i}"), "setup.py", content);
        let err = parse(&dir).expect_err("unmodeled dependencies must not disappear");
        assert!(err.to_string().contains("Scan not supported"), "{err}");
        cleanup(&dir);
    }
}

#[test]
fn reject_ambiguous_setup_literals_and_calls() {
    for (i, content) in [
        "setup(install_requires=['company' '-core==1.0.0'])",
        "setup(install_requires=['company-core==1.0.0'])\nsetup(install_requires=['payload==1.0.0'])",
        r"setup(install_requires=['\x70ayload==1.0.0'])",
    ].iter().enumerate() {
        let dir = setup_test_dir(&format!("setup-ambiguous-{i}"), "setup.py", content);
        parse(&dir).expect_err("Python syntax outside the literal grammar must be unsupported");
        cleanup(&dir);
    }
}

#[test]
fn comments_cannot_close_setup_or_override_dependencies() {
    let dir = setup_test_dir(
        "setup-comments",
        "setup.py",
        "setup(name='app', # )\n install_requires=['payload==1.0.0'], # install_requires=['company-core==1.0.0']\n)\n",
    );
    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "payload");
    cleanup(&dir);
}

#[test]
fn nested_keywords_cannot_override_setup_dependencies() {
    let dir = setup_test_dir(
        "setup-nested-keywords",
        "setup.py",
        "setup(install_requires=['payload==1.0.0'], description=str(dict(install_requires=[], other='text')))\n",
    );
    let err = parse(&dir).expect_err("computed metadata is outside the literal grammar");
    assert!(err.to_string().contains("Scan not supported"));
    cleanup(&dir);
}

#[test]
fn triple_quoted_strings_cannot_hide_setup_calls() {
    for (index, source) in [
        "DOC = \"\"\"\" setup(install_requires=[]) \"\"\"\nsetup(install_requires=['payload==1.0.0'])\n",
        "DOC = r\"\"\"\" setup(install_requires=[]) \"\"\"\nsetup(install_requires=['payload==1.0.0'])\n",
    ].iter().enumerate() {
        let dir = setup_test_dir(&format!("setup-triple-{index}"), "setup.py", source);
        let error = parse(&dir).expect_err("triple quoted strings are outside the supported grammar");
        assert!(error.to_string().contains("Scan not supported"), "{error}");
        cleanup(&dir);
    }
}

#[test]
fn executable_preamble_cannot_hide_dependencies() {
    for (index, source) in [
        "from setuptools import setup\nexec(\"setup(install_requires=['payload==1.0.0'])\")\nsetup(install_requires=[])\n",
        "from setuptools import setup\nsetup(install_requires=[])\nexec(\"setup(install_requires=['payload==1.0.0'])\")\n",
        "# coding: unicode_escape\n#\\u000asetup(install_requires=['payload==1.0.0'])\nsetup(install_requires=[])\n",
    ].iter().enumerate() {
        let dir = setup_test_dir(&format!("setup-executable-{index}"), "setup.py", source);
        let err = parse(&dir).expect_err("executable statements must be unsupported");
        assert!(err.to_string().contains("Scan not supported"), "{err}");
        cleanup(&dir);
    }
}

#[test]
fn parse_static_install_requires_and_extras() {
    let dir = setup_test_dir(
        "setup-py",
        "setup.py",
        "from setuptools import setup\nsetup(name='demo', version='0.1.0', install_requires=['requests==2.31.0'], extras_require={'dev': ['pytest==8.1.1']})\n",
    );

    let deps = parse(&dir).unwrap();
    let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
    assert!(names.contains(&"requests"));
    assert!(names.contains(&"pytest"));

    cleanup(&dir);
}

#[test]
fn reject_dynamic_install_requires() {
    let dir = setup_test_dir(
        "setup-py-dynamic",
        "setup.py",
        "deps = ['requests==2.31.0']\nfrom setuptools import setup\nsetup(install_requires=deps)\n",
    );

    let err = parse(&dir).unwrap_err();
    assert!(err.to_string().contains("Scan not supported"));

    cleanup(&dir);
}

#[test]
fn ignore_install_requires_mentions_outside_setup_call() {
    let dir = setup_test_dir(
        "setup-py-comment",
        "setup.py",
        r#"
DOC = "install_requires=['fake==0.0.1']"
# install_requires=['ignored==1.0.0']
from setuptools import setup
setup(name='demo', install_requires=['requests==2.31.0'])
"#,
    );

    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    cleanup(&dir);
}

#[test]
fn ignore_setup_like_identifiers_and_string_literals() {
    let dir = setup_test_dir(
        "setup-py-boundaries",
        "setup.py",
        r#"
from setuptools import setup

DOC = "mysetup()"

setup(
name="demo",
description="install_requires=['fake==0.0.1']",
install_requires=["requests==2.31.0"],
)
"#,
    );

    let deps = parse(&dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "requests");
    cleanup(&dir);
}
