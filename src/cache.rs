use anyhow::Result;
use std::path::{Path, PathBuf};

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

/// Convert epoch seconds to date components. Canonical implementation —
/// all date math in the codebase should go through this function.
fn epoch_secs_to_parts(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let min = (time_of_day % 3600) / 60;
    let sec = time_of_day % 60;
    let mut year = 1970i64;
    let mut rem_days = days;
    loop {
        if year > 2200 { break; } // safety cap
        let ydays = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if rem_days < ydays { break; }
        rem_days -= ydays;
        year += 1;
    }
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_per_month = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1i64;
    for &dm in &days_per_month {
        if rem_days < dm { break; }
        rem_days -= dm;
        month += 1;
    }
    let day = rem_days + 1;
    (year, month, day, hour, min, sec)
}

/// Convert date components to epoch seconds. Inverse of epoch_secs_to_parts.
/// Handles leap years. Used by metadata age_in_hours.
pub fn date_to_epoch(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    let days_per_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
    }
    for m in 0..((month - 1) as usize) {
        days += days_per_month.get(m).copied().unwrap_or(30) as i64;
    }
    if month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        days += 1;
    }
    days += day - 1;
    days * 86400 + hour * 3600 + min * 60 + sec
}

/// Convert epoch milliseconds to ISO 8601 string. Returns None for negative timestamps.
pub fn epoch_millis_to_iso8601(millis: i64) -> Option<String> {
    if millis < 0 { return None; }
    let (year, month, day, hour, min, _sec) = epoch_secs_to_parts(millis / 1000);
    Some(format!("{:04}-{:02}-{:02}T{:02}:{:02}:00Z", year, month, day, hour, min))
}

/// Convert current time to ISO 8601 string. Used by test helpers.
#[allow(dead_code)]
pub fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (year, month, day, hour, min, sec) = epoch_secs_to_parts(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, min, sec)
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
    if std::fs::rename(&tmp_path, path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
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

}
