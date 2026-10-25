use super::*;

fn listing(entries: &[(&str, bool)]) -> Vec<PypiVersionListing> {
    entries
        .iter()
        .map(|(version, yanked)| PypiVersionListing {
            version: version.to_string(),
            yanked: *yanked,
        })
        .collect()
}

fn specs(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| item.to_string()).collect()
}

#[test]
fn the_newest_final_version_wins_without_specifiers() {
    let versions = listing(&[("1.0", false), ("2.0", false), ("1.10", false)]);
    assert_eq!(choose(&versions, &specs(&[])).versions, vec!["2.0"]);
    assert_eq!(choose(&versions, &specs(&[""])).versions, vec!["2.0"]);
}

#[test]
fn every_collected_specifier_must_allow_the_version() {
    let versions = listing(&[
        ("1.0", false),
        ("1.5", false),
        ("2.0", false),
        ("3.0", false),
    ]);
    let choice = choose(&versions, &specs(&[">=1.2", "<3", "!=2.0"]));
    assert_eq!(choice.versions, vec!["1.5"]);
    assert!(choice.conflict.is_none());
}

#[test]
fn versions_compare_by_pep_440_not_as_text() {
    let versions = listing(&[("1.9", false), ("1.10", false), ("1.2", false)]);
    assert_eq!(choose(&versions, &specs(&["<2"])).versions, vec!["1.10"]);
}

#[test]
fn yanked_versions_are_skipped_unless_pinned_exactly() {
    let versions = listing(&[("1.0", false), ("2.0", true)]);
    assert_eq!(choose(&versions, &specs(&[">=1"])).versions, vec!["1.0"]);
    assert_eq!(choose(&versions, &specs(&["==2.0"])).versions, vec!["2.0"]);
}

#[test]
fn prereleases_are_chosen_only_when_no_final_version_matches() {
    let versions = listing(&[("1.0", false), ("2.0rc1", false), ("2.0.dev1", false)]);
    assert_eq!(choose(&versions, &specs(&[])).versions, vec!["1.0"]);
    assert_eq!(
        choose(&versions, &specs(&[">=2.0a1"])).versions,
        vec!["2.0rc1"]
    );
}

#[test]
fn wildcard_and_compatible_release_specifiers_are_understood() {
    let versions = listing(&[("1.4.2", false), ("1.5.0", false), ("2.0.0", false)]);
    assert_eq!(
        choose(&versions, &specs(&["==1.4.*"])).versions,
        vec!["1.4.2"]
    );
    assert_eq!(
        choose(&versions, &specs(&["~=1.4"])).versions,
        vec!["1.5.0"]
    );
}

#[test]
fn conflicting_specifiers_check_the_newest_version_each_allows_and_say_so() {
    let versions = listing(&[("1.0", false), ("2.0", false), ("3.0", false)]);
    let choice = choose(&versions, &specs(&["<2", ">=3"]));
    assert_eq!(choice.versions, vec!["1.0", "3.0"]);
    let conflict = choice.conflict.unwrap();
    assert!(
        conflict.contains("'<2'") && conflict.contains("'>=3'"),
        "{conflict}"
    );
    assert!(conflict.contains("1.0, 3.0"), "{conflict}");
}

#[test]
fn a_specifier_nothing_satisfies_is_reported_with_no_version_checked() {
    let versions = listing(&[("1.0", false)]);
    let choice = choose(&versions, &specs(&[">=5"]));
    assert!(choice.versions.is_empty());
    assert!(choice.conflict.unwrap().contains("none was checked"));
}

#[test]
fn unreadable_specifiers_are_ignored_but_reported() {
    let versions = listing(&[("1.0", false), ("2.0", false)]);
    let choice = choose(&versions, &specs(&["<3", ">=garbage!"]));
    assert_eq!(choice.versions, vec!["2.0"]);
    assert!(choice.conflict.unwrap().contains("not valid PEP 440"));
}

#[test]
fn listed_versions_that_are_not_pep_440_are_skipped() {
    let versions = listing(&[("1.0", false), ("not-a-version", false)]);
    assert_eq!(choose(&versions, &specs(&[])).versions, vec!["1.0"]);
}

#[test]
fn an_exact_pin_needs_no_listing_when_every_other_specifier_allows_it() {
    assert_eq!(exact_pin(&specs(&["==2.31.0"])), Some("2.31.0".to_string()));
    assert_eq!(
        exact_pin(&specs(&["==2.31.0", ">=2", ""])),
        Some("2.31.0".to_string())
    );
    assert_eq!(exact_pin(&specs(&["==2.31.0", "<2"])), None);
    assert_eq!(exact_pin(&specs(&[">=2"])), None);
    assert_eq!(exact_pin(&specs(&["==2.*"])), None);
    assert_eq!(exact_pin(&specs(&["==2.0", "garbage!"])), None);
}
