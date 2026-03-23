use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Abstract cache service. Enables disk caching in production and
/// deterministic in-memory caching in tests.
/// TTL is the caller's responsibility (check timestamps in the cached data).
pub trait CacheService: Send + Sync {
    fn read_raw(&self, key: &str) -> Option<String>;
    fn write_raw(&self, key: &str, data: &str) -> Result<()>;
}

/// Extension methods for typed cache operations.
pub trait CacheServiceExt: CacheService {
    fn read<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        let raw = self.read_raw(key)?;
        serde_json::from_str(&raw).ok()
    }

    fn write<T: serde::Serialize>(&self, key: &str, data: &T) -> Result<()> {
        let json = serde_json::to_string(data)?;
        self.write_raw(key, &json)
    }
}

impl<S: CacheService + ?Sized> CacheServiceExt for S {}

/// Disk-backed cache with symlink protection, atomic writes, 0o600 permissions.
/// Keys are mapped to files under a base directory.
pub struct DiskCacheService {
    base_dir: PathBuf,
}

impl DiskCacheService {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn path_for(&self, key: &str) -> Option<PathBuf> {
        // Reject path traversal components before joining
        if key.contains("..") || key.contains('\0') {
            return None;
        }
        Some(self.base_dir.join(key))
    }
}

impl CacheService for DiskCacheService {
    fn read_raw(&self, key: &str) -> Option<String> {
        let path = self.path_for(key)?;
        if ensure_no_symlink(&path).is_err() {
            return None;
        }
        std::fs::read_to_string(&path).ok()
    }

    fn write_raw(&self, key: &str, data: &str) -> Result<()> {
        let Some(path) = self.path_for(key) else {
            return Ok(());
        };
        if ensure_no_symlink(&path).is_err() {
            return Ok(());
        }
        if let Some(parent) = path.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            return Ok(());
        }
        let tmp_path = cache_tmp_path(&path);
        if std::fs::write(&tmp_path, data).is_err() {
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&tmp_path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&tmp_path, perms);
            }
        }
        let _ = std::fs::rename(&tmp_path, &path);
        Ok(())
    }
}

/// In-memory cache for testing. No disk I/O, fully deterministic.
pub struct InMemoryCacheService {
    store: Mutex<HashMap<String, String>>,
}

impl InMemoryCacheService {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryCacheService {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheService for InMemoryCacheService {
    fn read_raw(&self, key: &str) -> Option<String> {
        self.store.lock().ok()?.get(key).cloned()
    }

    fn write_raw(&self, key: &str, data: &str) -> Result<()> {
        if let Ok(mut store) = self.store.lock() {
            store.insert(key.to_string(), data.to_string());
        }
        Ok(())
    }
}

/// Return the platform-appropriate user cache directory.
pub fn user_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        return path.into();
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return Path::new(&home).join("Library").join("Caches");
    }
    #[cfg(target_os = "windows")]
    if let Some(path) = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA")) {
        return path.into();
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Path::new(&home).join(".cache");
    }
    std::env::temp_dir()
}

/// Current time as seconds since Unix epoch.
pub fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Current time as nanoseconds since Unix epoch (for unique temp file names).
fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Convert epoch milliseconds to an approximate ISO 8601 string.
/// Returns None for negative timestamps. Shared by maven.rs and metadata tests.
pub fn epoch_millis_to_iso8601(millis: i64) -> Option<String> {
    if millis < 0 {
        return None;
    }
    let secs = millis / 1000;
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hour = remaining / 3600;
    let min = (remaining % 3600) / 60;
    let mut year = 1970i64;
    let mut rem_days = days;
    loop {
        let ydays = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if rem_days < ydays {
            break;
        }
        rem_days -= ydays;
        year += 1;
    }
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_per_month = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1i64;
    for &dm in &days_per_month {
        if rem_days < dm {
            break;
        }
        rem_days -= dm;
        month += 1;
    }
    let day = rem_days + 1;
    Some(format!("{:04}-{:02}-{:02}T{:02}:{:02}:00Z", year, month, day, hour, min))
}

/// Reject symlinked cache files to prevent symlink attacks.
pub fn ensure_no_symlink(path: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        anyhow::bail!(
            "refusing to use symlinked cache file: {}",
            path.display()
        );
    }
    Ok(())
}

/// Generate a unique temporary file path next to the target path.
fn cache_tmp_path(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!("tmp-{}-{}-{}", std::process::id(), now_nanos(), id))
}

/// Atomically write JSON to a cache file (write to temp, set 0o600, rename).
pub fn atomic_write_json<T: serde::Serialize>(path: &Path, data: &T) -> Result<()> {
    if ensure_no_symlink(path).is_err() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(parent) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(parent, perms);
            }
        }
    }
    let Ok(json) = serde_json::to_string(data) else {
        return Ok(());
    };
    let tmp_path = cache_tmp_path(path);
    if std::fs::write(&tmp_path, json).is_err() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&tmp_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&tmp_path, perms);
        }
    }
    let _ = std::fs::rename(&tmp_path, path);
    Ok(())
}

/// Read and deserialize a JSON cache file, returning None if expired, missing,
/// symlinked, or unparseable.
pub fn read_json_cache<T: serde::de::DeserializeOwned>(
    path: &Path,
    ttl_secs: u64,
    timestamp_extractor: impl FnOnce(&T) -> u64,
) -> Option<T> {
    if ensure_no_symlink(path).is_err() {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    let data: T = serde_json::from_str(&content).ok()?;
    let age = now_epoch().saturating_sub(timestamp_extractor(&data));
    if age < ttl_secs {
        Some(data)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("sj-cache-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct TestCache {
        timestamp: u64,
        value: String,
    }

    #[test]
    fn atomic_write_json_round_trips() {
        let dir = unique_dir();
        let path = dir.join("test-cache.json");
        let data = TestCache {
            timestamp: now_epoch(),
            value: "hello".to_string(),
        };
        atomic_write_json(&path, &data).unwrap();
        let loaded: TestCache =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.value, "hello");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_json_cache_rejects_expired() {
        let dir = unique_dir();
        let path = dir.join("expired.json");
        let data = TestCache {
            timestamp: now_epoch().saturating_sub(10000), // 10000 seconds ago
            value: "old".to_string(),
        };
        atomic_write_json(&path, &data).unwrap();
        let loaded = read_json_cache::<TestCache>(&path, 3600, |d| d.timestamp);
        assert!(loaded.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_json_cache_accepts_fresh() {
        let dir = unique_dir();
        let path = dir.join("fresh.json");
        let data = TestCache {
            timestamp: now_epoch(),
            value: "new".to_string(),
        };
        atomic_write_json(&path, &data).unwrap();
        let loaded = read_json_cache::<TestCache>(&path, 3600, |d| d.timestamp);
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().value, "new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn read_json_cache_rejects_symlink() {
        let dir = unique_dir();
        let real = dir.join("real.json");
        let link = dir.join("link.json");
        let data = TestCache {
            timestamp: now_epoch(),
            value: "symlinked".to_string(),
        };
        atomic_write_json(&real, &data).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let loaded = read_json_cache::<TestCache>(&link, 3600, |d| d.timestamp);
        assert!(loaded.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_no_symlink_rejects_symlinks() {
        let dir = unique_dir();
        let real = dir.join("real.json");
        let link = dir.join("link.json");
        std::fs::write(&real, "{}").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(ensure_no_symlink(&link).is_err());
        assert!(ensure_no_symlink(&real).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn user_cache_dir_returns_path() {
        let path = user_cache_dir();
        // Should return some valid path
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn now_epoch_returns_reasonable_value() {
        let epoch = now_epoch();
        // Should be after 2024
        assert!(epoch > 1_700_000_000);
    }

    #[test]
    fn cache_tmp_path_is_unique() {
        let base = Path::new("/tmp/test.json");
        let a = cache_tmp_path(base);
        let b = cache_tmp_path(base);
        assert_ne!(a, b);
    }

    // -- CacheService trait tests --

    #[test]
    fn in_memory_cache_round_trips() {
        let cache = InMemoryCacheService::new();
        assert!(cache.read_raw("key").is_none());
        cache.write_raw("key", "value").unwrap();
        assert_eq!(cache.read_raw("key"), Some("value".to_string()));
    }

    #[test]
    fn in_memory_cache_typed_round_trips() {
        let cache = InMemoryCacheService::new();
        let data = TestCache {
            timestamp: now_epoch(),
            value: "typed".to_string(),
        };
        cache.write("typed-key", &data).unwrap();
        let loaded: TestCache = cache.read("typed-key").unwrap();
        assert_eq!(loaded.value, "typed");
    }

    #[test]
    fn disk_cache_service_round_trips() {
        let dir = unique_dir();
        let cache = DiskCacheService::new(dir.clone());
        assert!(cache.read_raw("test.json").is_none());
        cache.write_raw("test.json", r#"{"hello":"world"}"#).unwrap();
        assert_eq!(
            cache.read_raw("test.json"),
            Some(r#"{"hello":"world"}"#.to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_cache_rejects_path_traversal() {
        let dir = unique_dir();
        let cache = DiskCacheService::new(dir.clone());
        // Attempt to write outside base_dir via path traversal
        assert!(cache.write_raw("../../etc/evil", "payload").is_ok()); // silently rejected
        assert!(cache.read_raw("../../etc/evil").is_none());
        // Normal key still works
        cache.write_raw("safe.json", "ok").unwrap();
        assert_eq!(cache.read_raw("safe.json"), Some("ok".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
