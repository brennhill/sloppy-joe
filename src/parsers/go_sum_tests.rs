//! go.sum content checks: every required module version needs a checksum.

use super::check_go_sum_entries;

const HASH_A: &str = "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=";
const HASH_B: &str = "h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=";

fn go_mod(requires: &str) -> String {
    format!("module example.com/app\n\ngo 1.22\n\n{requires}\n")
}

#[test]
fn matching_go_mod_hash_passes() {
    let sum = format!(
        "github.com/google/uuid v1.6.0 {HASH_A}\ngithub.com/google/uuid v1.6.0/go.mod {HASH_B}\n"
    );
    check_go_sum_entries(&go_mod("require github.com/google/uuid v1.6.0"), &sum).unwrap();
}

#[test]
fn indirect_dependency_needs_only_the_go_mod_hash() {
    let sum = format!("github.com/x/y v1.0.0/go.mod {HASH_B}\n");
    check_go_sum_entries(&go_mod("require github.com/x/y v1.0.0 // indirect"), &sum).unwrap();
}

#[test]
fn required_version_with_no_go_sum_entry_blocks() {
    let sum = format!("github.com/google/uuid v1.6.0/go.mod {HASH_B}\n");
    let err = check_go_sum_entries(
        &go_mod("require (\n\tgithub.com/google/uuid v1.6.0\n\tgithub.com/evil/pkg v1.0.0\n)"),
        &sum,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("github.com/evil/pkg"), "{err}");
    assert!(err.contains("go mod download all"), "{err}");
    assert!(err.contains("sloppy-joe fix-lockfile"), "{err}");
}

#[test]
fn hash_for_a_different_version_does_not_count() {
    let sum = format!("github.com/google/uuid v1.5.0/go.mod {HASH_B}\n");
    assert!(check_go_sum_entries(&go_mod("require github.com/google/uuid v1.6.0"), &sum).is_err());
}

#[test]
fn zip_hash_alone_without_go_mod_hash_blocks() {
    let sum = format!("github.com/google/uuid v1.6.0 {HASH_A}\n");
    assert!(check_go_sum_entries(&go_mod("require github.com/google/uuid v1.6.0"), &sum).is_err());
}

#[test]
fn conflicting_duplicate_hashes_block() {
    let sum = format!(
        "github.com/google/uuid v1.6.0/go.mod {HASH_A}\ngithub.com/google/uuid v1.6.0/go.mod {HASH_B}\n"
    );
    let err = check_go_sum_entries(&go_mod("require github.com/google/uuid v1.6.0"), &sum)
        .unwrap_err()
        .to_string();
    assert!(err.contains("conflicting"), "{err}");
}

#[test]
fn identical_duplicate_hashes_are_fine() {
    let sum = format!(
        "github.com/google/uuid v1.6.0 {HASH_A}\ngithub.com/google/uuid v1.6.0/go.mod {HASH_B}\ngithub.com/google/uuid v1.6.0/go.mod {HASH_B}\n"
    );
    check_go_sum_entries(&go_mod("require github.com/google/uuid v1.6.0"), &sum).unwrap();
}

#[test]
fn malformed_lines_block() {
    for bad in [
        "github.com/google/uuid v1.6.0/go.mod\n",
        "github.com/google/uuid v1.6.0/go.mod sha256:abc\n",
        "github.com/google/uuid v1.6.0/go.mod h1:not-base64!!\n",
        "a b c d\n",
    ] {
        let sum = format!("{bad}github.com/google/uuid v1.6.0/go.mod {HASH_B}\n");
        assert!(
            check_go_sum_entries(&go_mod("require github.com/google/uuid v1.6.0"), &sum).is_err(),
            "{bad:?} must block"
        );
    }
}

#[test]
fn unrelated_extra_entries_are_allowed() {
    let sum = format!(
        "github.com/old/dep v0.1.0 {HASH_A}\ngithub.com/old/dep v0.1.0/go.mod {HASH_B}\ngithub.com/google/uuid v1.6.0 {HASH_A}\ngithub.com/google/uuid v1.6.0/go.mod {HASH_B}\n"
    );
    check_go_sum_entries(&go_mod("require github.com/google/uuid v1.6.0"), &sum).unwrap();
}

#[test]
fn local_replace_modules_need_no_checksum() {
    let content =
        go_mod("require github.com/local/mod v0.0.0\nreplace github.com/local/mod => ../mod");
    check_go_sum_entries(&content, "").unwrap();
}

#[test]
fn modules_without_requirements_pass_with_empty_go_sum() {
    check_go_sum_entries(&go_mod(""), "").unwrap();
}

#[test]
fn direct_requirement_with_only_the_go_mod_hash_blocks() {
    let sum = format!("github.com/google/uuid v1.6.0/go.mod {HASH_B}\n");
    let err = check_go_sum_entries(&go_mod("require github.com/google/uuid v1.6.0"), &sum)
        .unwrap_err()
        .to_string();
    assert!(err.contains("content hash"), "{err}");
    assert!(err.contains("github.com/google/uuid v1.6.0"), "{err}");
}

#[test]
fn indirect_requirement_in_a_block_needs_only_the_go_mod_hash() {
    let sum = format!(
        "github.com/a/b v1.0.0 {HASH_A}\ngithub.com/a/b v1.0.0/go.mod {HASH_B}\ngithub.com/x/y v1.0.0/go.mod {HASH_B}\n"
    );
    check_go_sum_entries(
        &go_mod("require (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/x/y v1.0.0 // indirect\n)"),
        &sum,
    )
    .unwrap();
}

#[test]
fn vendoring_applies_from_go_1_14() {
    use super::vendoring_applies;
    assert!(vendoring_applies("module m\n\ngo 1.22\n"));
    assert!(vendoring_applies("module m\n\ngo 1.14\n"));
    assert!(vendoring_applies("module m\n\ngo 1.22.3\n"));
    assert!(!vendoring_applies("module m\n\ngo 1.13\n"));
    assert!(!vendoring_applies("module m\n"));
}

#[test]
fn vendor_listing_must_cover_every_requirement() {
    use super::check_vendor_modules;
    let go_mod = go_mod("require (\n\tgolang.org/x/text v0.14.0\n\tgithub.com/a/b v1.0.0\n)");
    let full = "# golang.org/x/text v0.14.0\n## explicit; go 1.18\ngolang.org/x/text/unicode\n# github.com/a/b v1.0.0\n## explicit\ngithub.com/a/b\n";
    check_vendor_modules(&go_mod, full).unwrap();
    // The red-team case: a one-line listing of an unrelated module.
    let err = check_vendor_modules(&go_mod, "# example.com/unrelated v1.0.0\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("golang.org/x/text v0.14.0"), "{err}");
    assert!(err.contains("go mod vendor"), "{err}");
    // A listing for another version of the module does not count.
    assert!(
        check_vendor_modules(
            &go_mod,
            "# golang.org/x/text v0.13.0\n# github.com/a/b v1.0.0\n"
        )
        .is_err()
    );
    // Replaced versions are listed with their replacement; the requirement side still matches.
    check_vendor_modules(
        &go_mod,
        "# golang.org/x/text v0.14.0 => golang.org/x/text v0.14.1\n# github.com/a/b v1.0.0\n",
    )
    .unwrap();
}
