use super::*;

use crate::registry::{RegistryExistence, RegistryMetadata};

use crate::report::Severity;

use async_trait::async_trait;

struct FakeRegistry {
    metadata_response: Option<PackageMetadata>,
    owners_response: Option<Vec<String>>,
}

#[async_trait]
impl RegistryExistence for FakeRegistry {
    async fn exists(&self, _name: &str) -> Result<bool> {
        Ok(true)
    }
    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for FakeRegistry {
    async fn metadata(
        &self,
        _name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        Ok(self.metadata_response.clone())
    }

    async fn owners(&self, _name: &str) -> Result<Option<Vec<String>>> {
        Ok(self.owners_response.clone())
    }
}

use crate::test_helpers::dep_with;

use crate::test_helpers::npm_dep as dep;

fn dep_with_version(name: &str, version: &str) -> Dependency {
    dep_with(name, Some(version), crate::Ecosystem::Npm)
}

fn config_with_age(hours: u64) -> SloppyJoeConfig {
    SloppyJoeConfig {
        min_version_age_hours: hours,
        ..Default::default()
    }
}

fn default_meta() -> PackageMetadata {
    PackageMetadata {
        created: Some("2020-01-01T00:00:00Z".to_string()),
        latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
        downloads: Some(50000),
        repository_url: Some("https://github.com/example/pkg".to_string()),
        ..Default::default()
    }
}

fn empty_similarity() -> HashSet<String> {
    HashSet::new()
}

fn no_resolution() -> ResolutionResult {
    ResolutionResult::default()
}

fn chrono_free_now() -> String {
    crate::cache::now_iso8601()
}

#[path = "metadata_tests/part01_age_in_hours.rs"]
mod part01_age_in_hours;

#[path = "metadata_tests/part02_review_candidates_skip.rs"]
mod part02_review_candidates_skip;
