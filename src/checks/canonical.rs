use crate::config::SloppyJoeConfig;
use crate::report::Issue;
use crate::Dependency;

/// Check dependencies against the canonical allowlist.
/// If a dependency is listed as an alternative to a canonical package, flag it.
pub fn check_canonical(
    deps: &[Dependency],
    config: &SloppyJoeConfig,
    ecosystem: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let alternatives = config.alternatives_map(ecosystem);

    for dep in deps {
        if let Some(canonical) = alternatives.get(&dep.name) {
            issues.push(Issue {
                package: dep.name.clone(),
                check: "canonical".to_string(),
                message: format!(
                    "'{}' is not the canonical choice. Use '{}' instead.",
                    dep.name, canonical
                ),
                suggestion: Some(canonical.clone()),
            });
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }
    }

    #[test]
    fn no_issues_when_deps_dont_match_alternatives() {
        let config = SloppyJoeConfig {
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([("lodash".to_string(), vec!["underscore".to_string()])]),
            )]),
            ..Default::default()
        };
        let deps = vec![dep("react"), dep("express")];
        let issues = check_canonical(&deps, &config, "npm");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_dep_matching_alternative() {
        let config = SloppyJoeConfig {
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([("lodash".to_string(), vec!["underscore".to_string()])]),
            )]),
            ..Default::default()
        };
        let deps = vec![dep("underscore")];
        let issues = check_canonical(&deps, &config, "npm");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].package, "underscore");
        assert_eq!(issues[0].check, "canonical");
    }

    #[test]
    fn suggests_canonical_replacement() {
        let config = SloppyJoeConfig {
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([("dayjs".to_string(), vec!["moment".to_string()])]),
            )]),
            ..Default::default()
        };
        let deps = vec![dep("moment")];
        let issues = check_canonical(&deps, &config, "npm");
        assert_eq!(issues[0].suggestion, Some("dayjs".to_string()));
    }

    #[test]
    fn multiple_deps_flagged() {
        let config = SloppyJoeConfig {
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([
                    ("lodash".to_string(), vec!["underscore".to_string(), "ramda".to_string()]),
                ]),
            )]),
            ..Default::default()
        };
        let deps = vec![dep("underscore"), dep("ramda")];
        let issues = check_canonical(&deps, &config, "npm");
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn empty_config_no_issues() {
        let config = SloppyJoeConfig::default();
        let deps = vec![dep("anything")];
        let issues = check_canonical(&deps, &config, "npm");
        assert!(issues.is_empty());
    }
}
