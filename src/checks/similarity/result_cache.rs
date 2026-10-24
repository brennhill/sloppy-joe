use super::*;

pub(crate) const SIMILARITY_CACHE_TTL_SECS: u64 = 7 * 24 * 3600; // 7 days

/// On-disk similarity existence cache.
///
/// Each entry carries its own `checked_at` so that rewriting the file with new
/// results never renews the lifetime of older entries (a stale negative entry
/// would otherwise hide a typosquat target registered after the first scan).
/// The file-level `timestamp` records the last write.
#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub(crate) struct SimilarityCache {
    pub(crate) timestamp: u64,
    pub(crate) entries: HashMap<String, SimilarityCacheEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum SimilarityCacheEntry {
    Timed {
        exists: bool,
        checked_at: u64,
    },
    /// Pre-per-entry format: a bare bool aged by the file timestamp.
    Legacy(bool),
}

impl SimilarityCache {
    /// Normalize legacy entries to the file timestamp and drop every entry
    /// older than the TTL (or dated in the future).
    pub(crate) fn normalize_and_expire(mut self, now: u64, ttl_secs: u64) -> Self {
        let file_ts = self.timestamp;
        self.entries = self
            .entries
            .into_iter()
            .filter_map(|(name, entry)| {
                let (exists, checked_at) = match entry {
                    SimilarityCacheEntry::Timed { exists, checked_at } => (exists, checked_at),
                    SimilarityCacheEntry::Legacy(exists) => (exists, file_ts),
                };
                let age = now.checked_sub(checked_at)?;
                (age < ttl_secs)
                    .then_some((name, SimilarityCacheEntry::Timed { exists, checked_at }))
            })
            .collect();
        self
    }

    pub(crate) fn get(&self, name: &str) -> Option<bool> {
        self.entries.get(name).map(|entry| match *entry {
            SimilarityCacheEntry::Timed { exists, .. } | SimilarityCacheEntry::Legacy(exists) => {
                exists
            }
        })
    }
}

pub(crate) fn cache_path_for(ecosystem: Ecosystem, cache_dir: Option<&Path>) -> PathBuf {
    let base = cache_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
    base.join(format!("similarity-{}.json", ecosystem))
}
