use super::*;
use crate::remedy;

fn error(remedy: &'static Remedy) -> Problem {
    Problem::from_error(&remedy::problem(remedy, "broken."))
}

fn issue(check: &str) -> Problem {
    Problem::from_issue(&Issue::new("pkg", check, Severity::Error).message("m"))
}

fn recipe() -> Recipe {
    Recipe::new("tool --fix", PathBuf::from("/p"))
}

#[test]
fn untagged_errors_and_attack_findings_are_human() {
    let problems = vec![
        Problem::from_error(&anyhow::anyhow!("something unknown")),
        issue(checks::names::METADATA_LOCKFILE_INTEGRITY_MISMATCH),
        issue(checks::names::RESOLUTION_LOCKFILE_OUT_OF_SYNC),
        issue(checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE),
    ];
    let plan = plan(&problems, |_| panic!("no recipe for human problems")).unwrap();
    assert!(plan.recipe.is_none());
    assert!(
        plan.verdicts.iter().all(|v| v.class == FixClass::Human),
        "{:?}",
        plan.verdicts
    );
    assert!(
        plan.verdicts[1]
            .reason
            .as_deref()
            .unwrap()
            .contains("hide a possible attack")
    );
}

#[test]
fn decisions_are_human_and_manual_remedies_are_guided() {
    let problems = vec![
        error(&remedy::JS_DEPENDENCY_REWRITE),
        error(&remedy::BUNDLE_LOCK),
    ];
    let plan = plan(&problems, |_| panic!("not asked")).unwrap();
    assert_eq!(plan.verdicts[0].class, FixClass::Human);
    assert_eq!(plan.verdicts[1].class, FixClass::Guided);
    assert_eq!(plan.verdicts[1].command.as_deref(), Some("bundle lock"));
}

#[test]
fn a_tool_remedy_with_a_recipe_is_fixable() {
    let problems = vec![error(&remedy::PNPM_LOCKFILE)];
    let plan = plan(&problems, |remedy| {
        assert_eq!(remedy.id, "pnpm-lockfile");
        Ok(Ok(Some(recipe())))
    })
    .unwrap();
    assert_eq!(plan.verdicts[0].class, FixClass::Fixable);
    assert_eq!(plan.verdicts[0].command.as_deref(), Some("tool --fix"));
    assert!(plan.recipe.is_some());
}

#[test]
fn a_precondition_refusal_is_guided_with_the_reason() {
    let problems = vec![error(&remedy::PNPM_LOCKFILE)];
    let plan = plan(&problems, |_| {
        Ok(Err(".pnpmfile.cjs runs code".to_string()))
    })
    .unwrap();
    assert_eq!(plan.verdicts[0].class, FixClass::Guided);
    assert_eq!(
        plan.verdicts[0].reason.as_deref(),
        Some(".pnpmfile.cjs runs code")
    );
    assert_eq!(
        plan.verdicts[0].command.as_deref(),
        Some(remedy::PNPM_LOCKFILE.command)
    );
    assert!(plan.recipe.is_none());
}

#[test]
fn a_tool_remedy_next_to_a_human_problem_is_not_run() {
    let problems = vec![
        error(&remedy::NPM_LOCKFILE),
        issue(checks::names::RESOLUTION_SOURCE_MISMATCH),
    ];
    let plan = plan(&problems, |_| panic!("must not build a recipe")).unwrap();
    assert!(plan.recipe.is_none());
    assert_eq!(plan.verdicts[0].class, FixClass::Guided);
    assert_eq!(plan.verdicts[1].class, FixClass::Human);
}

#[test]
fn two_different_tool_remedies_are_not_combined() {
    let problems = vec![
        error(&remedy::NPM_LOCKFILE),
        error(&remedy::NPM_LOCKFILE_UPGRADE),
    ];
    let plan = plan(&problems, |_| panic!("must not build a recipe")).unwrap();
    assert!(plan.verdicts.iter().all(|v| v.class == FixClass::Guided));
}

#[test]
fn a_remedy_the_plugin_does_not_own_is_guided() {
    let problems = vec![error(&remedy::GO_SUM)];
    let plan = plan(&problems, |_| Ok(Ok(None))).unwrap();
    assert_eq!(plan.verdicts[0].class, FixClass::Guided);
    assert!(
        plan.verdicts[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("no automatic fix")
    );
}

#[test]
fn missing_entries_and_orphans_get_the_lockfile_remedy() {
    let problems = vec![
        issue(checks::names::RESOLUTION_MISSING_LOCKFILE_ENTRY),
        Problem::from_issue(&Issue::new(
            "yarn.lock",
            crate::lockfiles::yarn::LOCKFILE_ORPHAN_ENTRIES,
            Severity::Warning,
        )),
        issue(checks::names::RESOLUTION_SOURCE_MISMATCH),
    ];
    let attached = attach_issue_remedies(&problems, &remedy::YARN_BERRY_LOCKFILE);
    assert_eq!(
        attached[0].remedy.map(|r| r.id),
        Some("yarn-berry-lockfile")
    );
    assert_eq!(
        attached[1].remedy.map(|r| r.id),
        Some("yarn-berry-lockfile")
    );
    assert!(attached[2].remedy.is_none());
}

#[test]
fn planned_issues_are_blocking_errors_catalog_warnings_and_attack_findings() {
    let warning = |check: &str| Issue::new("p", check, Severity::Warning);
    assert!(planned_issue(&Issue::new("p", "anything", Severity::Error)));
    assert!(planned_issue(&warning(
        crate::lockfiles::yarn::LOCKFILE_ORPHAN_ENTRIES
    )));
    assert!(planned_issue(&warning(
        checks::names::RESOLUTION_PRIVATE_REGISTRY_UNVETTED
    )));
    assert!(!planned_issue(&warning(
        checks::names::RESOLUTION_NPM_ALIAS
    )));
}
