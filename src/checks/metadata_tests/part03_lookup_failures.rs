use super::*;

/// Fails every lookup with the error a crates.io burst produces.
struct RateLimitedRegistry;

const RATE_LIMITED: &str =
    "crates.io metadata lookup for 'windows-sys' returned HTTP 429 Too Many Requests";

#[async_trait]
impl RegistryExistence for RateLimitedRegistry {
    async fn exists(&self, _name: &str) -> Result<bool> {
        anyhow::bail!("unused")
    }
    fn ecosystem(&self) -> &str {
        "cargo"
    }
}

#[async_trait]
impl RegistryMetadata for RateLimitedRegistry {
    async fn metadata(
        &self,
        _name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        anyhow::bail!("{RATE_LIMITED}\u{1b}[2J")
    }
}

#[tokio::test]
async fn a_failed_lookup_is_recorded_with_its_cause() {
    let deps = vec![dep_with(
        "windows-sys",
        Some("0.59.0"),
        crate::Ecosystem::Cargo,
    )];
    let fetch = fetch_metadata(&RateLimitedRegistry, &deps, &no_resolution()).await;
    assert!(fetch.lookups.is_empty());
    assert_eq!(fetch.failures.len(), 1);
    let failure = &fetch.failures[0];
    assert_eq!(failure.package, "windows-sys");
    assert_eq!(failure.version.as_deref(), Some("0.59.0"));
    assert!(failure.cause.starts_with(RATE_LIMITED), "{}", failure.cause);
    assert!(!failure.cause.contains('\u{1b}'), "{}", failure.cause);
}

#[tokio::test]
async fn the_unreachable_summary_names_what_went_wrong_and_still_blocks() {
    let deps = vec![
        dep_with("windows-sys", Some("0.59.0"), crate::Ecosystem::Cargo),
        dep_with("windows-sys", Some("0.52.0"), crate::Ecosystem::Cargo),
    ];
    let fetch = fetch_metadata(&RateLimitedRegistry, &deps, &no_resolution()).await;
    let issue = fetch
        .issues
        .iter()
        .find(|issue| issue.check == crate::names::METADATA_REGISTRY_UNREACHABLE)
        .expect("a failed lookup must block");
    assert_eq!(issue.severity, Severity::Error);
    assert!(
        issue.message.contains("2 of 2 metadata checks"),
        "{}",
        issue.message
    );
    assert!(issue.message.contains("HTTP 429"), "{}", issue.message);
}
