//! Check implementations that wrap existing check functions.
//! Each struct implements the `Check` trait and delegates to the
//! existing function-based API, reading from / writing to the accumulator.

use super::{Check, CheckContext, ScanAccumulator};
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

/// Canonical check: flags deps that have a preferred alternative in config.
pub struct CanonicalCheck;

impl Check for CanonicalCheck {
    fn name(&self) -> &str {
        "canonical"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext<'a>,
        acc: &'a mut ScanAccumulator,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let results =
                super::canonical::check_canonical(ctx.non_internal_deps, ctx.config, ctx.ecosystem);
            acc.issues.extend(results);
            Ok(())
        })
    }
}

/// Similarity check: generates mutations and queries registry.
/// Populates acc.similarity_flagged for downstream checks.
pub struct SimilarityCheck;

impl Check for SimilarityCheck {
    fn name(&self) -> &str {
        "similarity"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext<'a>,
        acc: &'a mut ScanAccumulator,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let results = super::similarity::check_similarity_with_cache(
                ctx.registry,
                ctx.checkable_deps,
                ctx.ecosystem,
                ctx.opts.cache_dir,
                ctx.opts.no_cache,
                ctx.opts.paranoid,
                acc.metadata_lookups.as_deref(),
            )
            .await?;

            for issue in &results {
                acc.similarity_flagged.insert(issue.package.clone());
            }
            acc.issues.extend(results);
            Ok(())
        })
    }
}

/// Metadata check: fetches registry metadata, checks age/scripts/deps/publisher.
/// Populates acc.metadata_lookups for ExistenceCheck.
pub struct MetadataCheck;

impl Check for MetadataCheck {
    fn name(&self) -> &str {
        "metadata"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext<'a>,
        acc: &'a mut ScanAccumulator,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            acc.issues.extend(ctx.resolution.issues.clone());
            acc.issues.extend(crate::unresolved_version_policy_issues(
                ctx.non_internal_deps,
                ctx.resolution,
                ctx.config,
            ));

            // Always fetch metadata lookups and store in accumulator.
            // For metadata-supporting ecosystems (npm, pypi, cargo, ruby, jvm),
            // this calls metadata() + conditional exists() fallback per dep.
            // For non-metadata ecosystems (go, php, dotnet), metadata() returns
            // None immediately and exists() is called once as fallback.
            // Either way, ExistenceCheck reads from acc.metadata_lookups
            // instead of making redundant registry calls.
            let (lookups, fetch_issues) = super::metadata::fetch_metadata(
                ctx.registry,
                ctx.non_internal_deps,
                ctx.resolution,
            )
            .await;
            acc.issues.extend(fetch_issues);
            acc.issues.extend(super::metadata::issues_from_lookups(
                &lookups,
                ctx.config,
                &acc.similarity_flagged,
            ));
            acc.metadata_lookups = Some(lookups);

            Ok(())
        })
    }
}

/// Existence check: verifies deps exist on the registry.
/// Reads acc.metadata_lookups if available.
pub struct ExistenceCheck;

impl Check for ExistenceCheck {
    fn name(&self) -> &str {
        "existence"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext<'a>,
        acc: &'a mut ScanAccumulator,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let results = if let Some(ref lookups) = acc.metadata_lookups {
                super::existence::check_existence_from_metadata(
                    ctx.ecosystem,
                    ctx.checkable_deps,
                    lookups,
                )
            } else {
                super::existence::check_existence(ctx.registry, ctx.checkable_deps).await?
            };
            acc.issues.extend(results);
            Ok(())
        })
    }
}

/// Malicious/vulnerability check via OSV database.
pub struct MaliciousCheck;

impl Check for MaliciousCheck {
    fn name(&self) -> &str {
        "malicious"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext<'a>,
        acc: &'a mut ScanAccumulator,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let results = if ctx.opts.disable_osv_disk_cache {
                super::malicious::check_malicious_with_cache(
                    ctx.osv_client,
                    ctx.non_internal_deps,
                    ctx.resolution,
                    None,
                )
                .await?
            } else {
                super::malicious::check_malicious(
                    ctx.osv_client,
                    ctx.non_internal_deps,
                    ctx.resolution,
                )
                .await?
            };
            acc.issues.extend(results);
            Ok(())
        })
    }
}

/// Returns the default pipeline of checks in execution order.
/// Order matters: similarity -> metadata -> existence (data dependencies via accumulator).
pub fn default_pipeline() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(CanonicalCheck),
        Box::new(SimilarityCheck),
        Box::new(MetadataCheck),
        Box::new(ExistenceCheck),
        Box::new(MaliciousCheck),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pipeline_has_five_checks() {
        let pipeline = default_pipeline();
        assert_eq!(pipeline.len(), 5);
        assert_eq!(pipeline[0].name(), "canonical");
        assert_eq!(pipeline[1].name(), "similarity");
        assert_eq!(pipeline[2].name(), "metadata");
        assert_eq!(pipeline[3].name(), "existence");
        assert_eq!(pipeline[4].name(), "malicious");
    }

    #[test]
    fn accumulator_starts_empty() {
        let acc = ScanAccumulator::new();
        assert!(acc.issues.is_empty());
        assert!(acc.similarity_flagged.is_empty());
        assert!(acc.metadata_lookups.is_none());
    }
}
