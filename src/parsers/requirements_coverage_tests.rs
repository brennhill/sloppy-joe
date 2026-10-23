//! Red-team regressions for requirements.txt parsing.

use super::*;
use crate::parsers::test_utils::*;

fn write_include_chain(dir: &Path, length: usize) {
    for index in 1..length {
        std::fs::write(
            dir.join(format!("r{index}.txt")),
            format!("-r r{}.txt\n", index + 1),
        )
        .unwrap();
    }
    std::fs::write(dir.join(format!("r{length}.txt")), "requests==2.31.0\n").unwrap();
}

#[test]
fn deep_include_chains_fail_closed_instead_of_overflowing_the_stack() {
    let dir = empty_test_dir("req-chain-deep");
    write_include_chain(&dir, 4000);
    let root = dir.join("r1.txt");

    let err = parse_scoped_file(&root, &dir).unwrap_err();
    assert!(err.to_string().contains("include depth"), "{err}");
    let err = is_hash_locked_requirements_file(&root, &dir).unwrap_err();
    assert!(err.to_string().contains("include depth"), "{err}");
    let err = included_paths(&root, &dir).unwrap_err();
    assert!(err.to_string().contains("include depth"), "{err}");
    let err = source_provenance(&root, &dir).unwrap_err();
    assert!(err.to_string().contains("include depth"), "{err}");
    cleanup(&dir);
}

#[test]
fn moderate_include_chains_still_parse() {
    let dir = empty_test_dir("req-chain-ok");
    write_include_chain(&dir, 32);
    let deps = parse_scoped_file(&dir.join("r1.txt"), &dir).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].dependency.name, "requests");
    cleanup(&dir);
}
