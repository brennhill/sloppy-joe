//! Release timing around a selected version: how long the package had been
//! quiet and how many releases landed just before it.

use serde::Serialize;

const DAY_SECONDS: i64 = 24 * 3600;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReleaseCadence {
    /// Epoch seconds of the selected version's publication.
    pub published_epoch: i64,
    /// Epoch seconds of the latest earlier release, if any.
    pub previous_release_epoch: Option<i64>,
    /// Other releases published within the 24 hours up to the selected one.
    pub releases_prior_24h: u32,
}

/// Cadence of `published` against the publication times of the package's
/// other versions. Versions published after `published` (backports, later
/// releases) are ignored.
pub(crate) fn cadence_from_epochs(
    published: i64,
    others: impl IntoIterator<Item = i64>,
) -> ReleaseCadence {
    let mut previous: Option<i64> = None;
    let mut prior_24h = 0u32;
    for epoch in others {
        if epoch > published {
            continue;
        }
        previous = Some(previous.map_or(epoch, |current| current.max(epoch)));
        if published - epoch < DAY_SECONDS {
            prior_24h += 1;
        }
    }
    ReleaseCadence {
        published_epoch: published,
        previous_release_epoch: previous,
        releases_prior_24h: prior_24h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_later_versions_and_counts_the_prior_day() {
        let cadence =
            cadence_from_epochs(1_000_000, [1_000_000 - 100, 1_000_000 - 90_000, 2_000_000]);
        assert_eq!(cadence.releases_prior_24h, 1);
        assert_eq!(cadence.previous_release_epoch, Some(1_000_000 - 100));
    }

    #[test]
    fn no_other_versions_means_no_previous() {
        let cadence = cadence_from_epochs(5, []);
        assert_eq!(cadence.previous_release_epoch, None);
    }
}
