use crate::registry::Registry;
use crate::report::Issue;
use crate::Dependency;
use anyhow::Result;
use futures::stream::{self, StreamExt};

/// Check whether each dependency actually exists on its registry.
/// Uses a concurrency limit of 10 simultaneous requests.
pub async fn check_existence(
    registry: &dyn Registry,
    deps: &[Dependency],
) -> Result<Vec<Issue>> {
    let results = stream::iter(deps)
        .map(|dep| {
            let name = dep.name.clone();
            async move {
                let exists = registry.exists(&name).await.unwrap_or(true);
                (name, exists)
            }
        })
        .buffer_unordered(10)
        .collect::<Vec<_>>()
        .await;

    let mut issues = Vec::new();
    for (name, exists) in results {
        if !exists {
            issues.push(Issue {
                package: name.clone(),
                check: "existence".to_string(),
                message: format!(
                    "Package '{}' was not found on the {} registry. This may be hallucinated.",
                    name,
                    registry.ecosystem()
                ),
                suggestion: None,
            });
        }
    }

    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct FakeRegistry {
        existing: Vec<String>,
    }

    #[async_trait]
    impl Registry for FakeRegistry {
        async fn exists(&self, package_name: &str) -> Result<bool> {
            Ok(self.existing.contains(&package_name.to_string()))
        }

        fn ecosystem(&self) -> &str {
            "npm"
        }
    }

    fn dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }
    }

    #[tokio::test]
    async fn existing_package_no_issue() {
        let registry = FakeRegistry {
            existing: vec!["react".to_string()],
        };
        let deps = vec![dep("react")];
        let issues = check_existence(&registry, &deps).await.unwrap();
        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn missing_package_creates_issue() {
        let registry = FakeRegistry {
            existing: vec![],
        };
        let deps = vec![dep("nonexistent-pkg")];
        let issues = check_existence(&registry, &deps).await.unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].package, "nonexistent-pkg");
        assert_eq!(issues[0].check, "existence");
    }

    #[tokio::test]
    async fn mixed_existing_and_missing() {
        let registry = FakeRegistry {
            existing: vec!["react".to_string()],
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
        };
        let issues = check_existence(&registry, &[]).await.unwrap();
        assert!(issues.is_empty());
    }
}
