use crate::Dependency;
use crate::Ecosystem;
use crate::checks::metadata::MetadataLookup;
use crate::registry::Registry;
use crate::report::{Issue, Severity};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;

pub(crate) fn registry_url(ecosystem: Ecosystem, name: &str) -> String {
    ecosystem.registry_url_for(name)
}

/// Check whether each dependency actually exists on its registry.
/// Uses a concurrency limit of 10 simultaneous requests.
pub async fn check_existence(registry: &dyn Registry, deps: &[Dependency]) -> Result<Vec<Issue>> {
    let ecosystem: Ecosystem = registry.ecosystem().parse().unwrap_or(Ecosystem::Npm);
    let names: Vec<String> = deps.iter().map(|d| d.package_name().to_string()).collect();

    // Collect all results including errors (don't abort on first failure)
    let results: Vec<(String, std::result::Result<bool, anyhow::Error>)> = stream::iter(names)
        .map(|name| async move {
            let result = registry.exists(&name).await;
            (name, result)
        })
        .buffer_unordered(10)
        .collect()
        .await;

    let total_queries = results.len();
    let mut error_count = 0usize;
    let mut issues = Vec::new();

    for (name, result) in &results {
        match result {
            Ok(true) => {}
            Ok(false) => {
                let url = registry_url(ecosystem, name);
                issues.push(
                    Issue::new(name, super::names::EXISTENCE, Severity::Error)
                        .message(format!(
                            "Package '{}' does not exist on the {} registry. It may be hallucinated by an AI code generator, or it may be a private package that needs to be added to the 'allowed' list in your config.",
                            name, ecosystem
                        ))
                        .fix(format!(
                            "Remove '{}' from your dependencies, or if this is a private/internal package, add it to the 'allowed' list in your sloppy-joe config.",
                            name
                        ))
                        .registry_url(url),
                );
            }
            Err(_) => {
                error_count += 1;
            }
        }
    }

    // Fail closed if registry is unreachable
    if super::has_query_errors(error_count) {
        let error_rate = error_count as f64 / total_queries.max(1) as f64;
        issues.push(
            Issue::new(
                "<registry>",
                super::names::EXISTENCE_REGISTRY_UNREACHABLE,
                Severity::Error,
            )
            .message(format!(
                "Registry queries failed for {} of {} existence checks ({:.0}%). \
                     Existence detection is unreliable. Fix network connectivity or retry.",
                error_count,
                total_queries,
                error_rate * 100.0
            ))
            .fix("Ensure the registry is reachable and retry the scan."),
        );
    }

    Ok(issues)
}

pub(crate) fn check_existence_from_metadata(
    ecosystem: Ecosystem,
    deps: &[Dependency],
    lookups: &[MetadataLookup],
) -> Vec<Issue> {
    let lookup_map: HashMap<(String, Option<String>), bool> = lookups
        .iter()
        .map(|lookup| {
            (
                (lookup.package.clone(), lookup.version.clone()),
                lookup.exists,
            )
        })
        .collect();

    let mut issues = Vec::new();
    for dep in deps {
        let known = lookup_map
            .get(&(dep.package_name().to_string(), dep.version.clone()))
            .copied();
        if known == Some(true) {
            continue;
        }
        let url = registry_url(ecosystem, dep.package_name());
        let issue = if known == Some(false) {
            Issue::new(dep.package_name(), super::names::EXISTENCE, Severity::Error)
                .message(format!(
                    "Package '{}' does not exist on the {} registry. It may be hallucinated by an AI code generator, or it may be a private package that needs to be added to the 'allowed' list in your config.",
                    dep.package_name(),
                    ecosystem
                ))
                .fix(format!(
                    "Remove '{}' from your dependencies, or if this is a private/internal package, add it to the 'allowed' list in your sloppy-joe config.",
                    dep.package_name()
                ))
        } else {
            // The lookup itself failed (rate limit, timeout, server error): the package is
            // unverified, not known to be missing. It still blocks.
            Issue::new(dep.package_name(), super::names::EXISTENCE, Severity::Error)
                .message(format!(
                    "Could not verify that package '{}' exists on the {} registry because its registry lookup failed. This is a registry or network problem, not evidence that the package is missing.",
                    dep.package_name(),
                    ecosystem
                ))
                .fix("Retry the scan. If it keeps failing, check connectivity to the registry or rate limiting.")
        };
        issues.push(issue.registry_url(url));
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{RegistryExistence, RegistryMetadata};
    use async_trait::async_trait;

    struct FakeRegistry {
        existing: Vec<String>,
        fail: bool,
    }

    #[async_trait]
    impl RegistryExistence for FakeRegistry {
        async fn exists(&self, package_name: &str) -> Result<bool> {
            if self.fail {
                anyhow::bail!("registry unavailable");
            }
            Ok(self.existing.contains(&package_name.to_string()))
        }

        fn ecosystem(&self) -> &str {
            "npm"
        }
    }

    #[async_trait]
    impl RegistryMetadata for FakeRegistry {}

    use crate::test_helpers::npm_dep as dep;

    #[tokio::test]
    async fn existing_package_no_issue() {
        let registry = FakeRegistry {
            existing: vec!["react".to_string()],
            fail: false,
        };
        let deps = vec![dep("react")];
        let issues = check_existence(&registry, &deps).await.unwrap();
        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn missing_package_creates_issue() {
        let registry = FakeRegistry {
            existing: vec![],
            fail: false,
        };
        let deps = vec![dep("nonexistent-pkg")];
        let issues = check_existence(&registry, &deps).await.unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].package, "nonexistent-pkg");
        assert_eq!(issues[0].check, "existence");
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].registry_url.is_some());
        assert!(!issues[0].fix.is_empty());
    }

    #[tokio::test]
    async fn mixed_existing_and_missing() {
        let registry = FakeRegistry {
            existing: vec!["react".to_string()],
            fail: false,
        };
        let deps = vec![dep("react"), dep("fake-pkg")];
        let issues = check_existence(&registry, &deps).await.unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].package, "fake-pkg");
    }

    #[tokio::test]
    async fn empty_deps_no_issues() {
        let registry = FakeRegistry {
            existing: vec![],
            fail: false,
        };
        let issues = check_existence(&registry, &[]).await.unwrap();
        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn registry_errors_emit_blocking_issue() {
        let registry = FakeRegistry {
            existing: vec![],
            fail: true,
        };
        // With many deps, high error rate triggers fail-closed
        let deps: Vec<_> = (0..10).map(|i| dep(&format!("pkg-{}", i))).collect();
        let issues = check_existence(&registry, &deps).await.unwrap();
        assert!(
            issues
                .iter()
                .any(|i| i.check.contains("registry-unreachable")),
            "Expected fail-closed blocking issue, got: {:?}",
            issues.iter().map(|i| &i.check).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn single_error_triggers_fail_closed() {
        let registry = FakeRegistry {
            existing: vec![],
            fail: true,
        };
        let deps = vec![dep("react")];
        let issues = check_existence(&registry, &deps).await.unwrap();
        assert!(
            issues
                .iter()
                .any(|i| i.check.contains("registry-unreachable")),
            "Any existence lookup failure should trigger fail-closed"
        );
    }
}

#[cfg(test)]
mod lookup_failure_message_tests {
    use super::*;

    fn dep() -> Dependency {
        Dependency {
            name: "anyhow".into(),
            version: Some("1.0.0".into()),
            ecosystem: Ecosystem::Cargo,
            actual_name: None,
        }
    }

    #[test]
    fn a_failed_lookup_blocks_without_claiming_the_package_is_missing() {
        let issues = check_existence_from_metadata(Ecosystem::Cargo, &[dep()], &[]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(
            issues[0].message.contains("Could not verify"),
            "{}",
            issues[0].message
        );
        assert!(!issues[0].message.contains("hallucinated"));
    }

    #[test]
    fn a_confirmed_missing_package_still_reports_non_existence() {
        let lookup = MetadataLookup {
            package: "anyhow".into(),
            ecosystem: Ecosystem::Cargo,
            version: Some("1.0.0".into()),
            resolved_version: None,
            unresolved_version: false,
            exists: false,
            metadata: None,
        };
        let issues = check_existence_from_metadata(Ecosystem::Cargo, &[dep()], &[lookup]);
        assert!(issues[0].message.contains("does not exist"));
    }
}
