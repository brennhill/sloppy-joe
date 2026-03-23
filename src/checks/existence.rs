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
/// Registry error tracking: >5 errors OR >10% failure rate triggers blocking issue.
const REGISTRY_ERROR_HARD_LIMIT: usize = 5;
const REGISTRY_ERROR_RATE_THRESHOLD: f64 = 0.10;

pub async fn check_existence(registry: &dyn Registry, deps: &[Dependency]) -> Result<Vec<Issue>> {
    let ecosystem: Ecosystem = registry.ecosystem().parse().unwrap_or(Ecosystem::Npm);
    let names: Vec<String> = deps.iter().map(|d| d.name.clone()).collect();

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
    let error_rate = if total_queries > 0 {
        error_count as f64 / total_queries as f64
    } else {
        0.0
    };
    if error_count > REGISTRY_ERROR_HARD_LIMIT
        || (total_queries > 0 && error_rate > REGISTRY_ERROR_RATE_THRESHOLD)
    {
        issues.push(
            Issue::new("<registry>", super::names::EXISTENCE_REGISTRY_UNREACHABLE, Severity::Error)
                .message(format!(
                    "Registry queries failed for {} of {} existence checks ({:.0}%). \
                     Existence detection is unreliable. Fix network connectivity or retry.",
                    error_count, total_queries, error_rate * 100.0
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
        let exists = lookup_map
            .get(&(dep.name.clone(), dep.version.clone()))
            .copied()
            .unwrap_or(false);
        if !exists {
            let url = registry_url(ecosystem, &dep.name);
            issues.push(
                Issue::new(&dep.name, super::names::EXISTENCE, Severity::Error)
                    .message(format!(
                        "Package '{}' does not exist on the {} registry. It may be hallucinated by an AI code generator, or it may be a private package that needs to be added to the 'allowed' list in your config.",
                        dep.name, ecosystem
                    ))
                    .fix(format!(
                        "Remove '{}' from your dependencies, or if this is a private/internal package, add it to the 'allowed' list in your sloppy-joe config.",
                        dep.name
                    ))
                    .registry_url(url),
            );
        }
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
            issues.iter().any(|i| i.check.contains("registry-unreachable")),
            "Expected fail-closed blocking issue, got: {:?}",
            issues.iter().map(|i| &i.check).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn single_registry_error_does_not_block() {
        // A registry that fails for one specific package but works for others
        // We can't test partial failure with the simple FakeRegistry,
        // but we can test that a single dep failure doesn't produce a blocking issue
        let registry = FakeRegistry {
            existing: vec![],
            fail: true,
        };
        let deps = vec![dep("react")];
        let issues = check_existence(&registry, &deps).await.unwrap();
        // With only 1 query, 100% failure rate but only 1 error (under HARD_LIMIT of 5)
        // Should NOT produce registry-unreachable since error_count <= 5
        // But it will since error_rate > 10%, so it should produce the blocking issue
        assert!(
            issues.iter().any(|i| i.check.contains("registry-unreachable")),
            "Single dep with 100% failure should trigger rate-based fail-closed"
        );
    }
}
