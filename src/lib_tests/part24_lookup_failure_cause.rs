//! A registry lookup that fails still blocks, and the issue says why it failed
//! (bd sj-g5p: CI runs blocked on "registry lookup failed" with the HTTP 429 hidden).

use super::*;

struct RateLimitedRegistry;

#[async_trait]
impl RegistryExistence for RateLimitedRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        anyhow::bail!("npm lookup for '{package_name}' returned HTTP 429 Too Many Requests")
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for RateLimitedRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        anyhow::bail!(
            "npm metadata lookup for '{package_name}' returned HTTP 429 Too Many Requests"
        )
    }
}

#[tokio::test]
async fn a_failed_existence_lookup_blocks_and_names_its_cause() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"left-pad": "1.3.0"}}"#,
    )
    .unwrap();
    let report = scan_with_services_inner(
        &dir,
        config::SloppyJoeConfig::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &RateLimitedRegistry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let existence = report
        .issues
        .iter()
        .find(|issue| issue.package == "left-pad" && issue.check == checks::names::EXISTENCE)
        .unwrap_or_else(|| panic!("{:?}", report.issues));
    assert_eq!(existence.severity, Severity::Error);
    assert!(
        existence.message.contains("Could not verify")
            && existence
                .message
                .contains("returned HTTP 429 Too Many Requests"),
        "{}",
        existence.message
    );
    let unreachable = report
        .issues
        .iter()
        .find(|issue| issue.check == checks::names::METADATA_REGISTRY_UNREACHABLE)
        .unwrap_or_else(|| panic!("{:?}", report.issues));
    assert!(
        unreachable.message.contains("HTTP 429"),
        "{}",
        unreachable.message
    );
    assert!(report.has_errors());
    let _ = std::fs::remove_dir_all(&dir);
}
