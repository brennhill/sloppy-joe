//! Wheel core metadata during a projection. PyPI's JSON API takes a release's `requires_dist`
//! from the first file uploaded, which may be an sdist that declares nothing (or something else),
//! so a release whose wheel has a core metadata file is followed by that file's `Requires-Dist`:
//! what pip installs from the wheel. Each read counts against the fetch bound; a failed read
//! blocks and nothing of that release is followed.

use super::*;
use registry::pypi_release::{PypiCoreMetadata, PypiRequiresDist};

impl Projector<'_> {
    /// Read the core metadata of every fetched release that has a wheel to read, and replace the
    /// JSON API's requirements with the wheel's.
    pub(super) async fn read_wheel_metadata(&mut self) {
        let wanted: Vec<((String, String), PypiCoreMetadata)> = self
            .requires
            .iter()
            .filter(|(key, _)| !self.failed.contains(&key.0))
            .filter_map(|(key, declared)| {
                Some((key.clone(), declared.as_ref()?.wheel_metadata.clone()?))
            })
            .collect();
        if wanted.is_empty() || !self.reserve(wanted.len()) {
            return;
        }
        let registry = self.registry;
        let results: Vec<_> = futures::stream::iter(wanted)
            .map(|(key, wheel)| async move {
                let result = registry.pypi_wheel_requires_dist(&key.0, &wheel).await;
                (key, result)
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .collect()
            .await;
        for ((name, version), result) in results {
            match result {
                Ok(requirements) => {
                    let declared = PypiRequiresDist {
                        requirements,
                        ..PypiRequiresDist::default()
                    };
                    self.requires.insert((name, version), Some(declared));
                }
                Err(error) => {
                    self.requires.remove(&(name.clone(), version.clone()));
                    let error = error.context("could not read the wheel's core metadata");
                    self.fail(&name, Some(&version), &error);
                }
            }
        }
    }
}
