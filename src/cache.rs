use anyhow::Result;
use std::path::{Path, PathBuf};

/// Return the platform-appropriate user cache directory.
pub fn user_cache_dir() -> PathBuf {
    user_cache_dir_from(|name| std::env::var_os(name))
}

/// Relative or empty environment values are ignored (as the XDG spec requires):
/// they would resolve against the working directory, which is often the
/// scanned repository.
pub(crate) fn user_cache_dir_from(env: impl Fn(&str) -> Option<std::ffi::OsString>) -> PathBuf {
    let env = |name: &str| env(name).filter(|value| Path::new(value).is_absolute());
    if let Some(path) = env("XDG_CACHE_HOME") {
        return path.into();
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = env("HOME") {
        return Path::new(&home).join("Library").join("Caches");
    }
    #[cfg(target_os = "windows")]
    if let Some(path) = env("LOCALAPPDATA").or_else(|| env("APPDATA")) {
        return path.into();
    }
    if let Some(home) = env("HOME") {
        return Path::new(&home).join(".cache");
    }
    std::env::temp_dir()
}

/// Reject a cache directory inside the scanned project's git root (or the scan
/// root when there is no git root). Committed files there could forge cached
/// OSV, similarity, and scan-state results.
pub fn ensure_cache_dir_outside_project(cache_dir: &Path, project_dir: &Path) -> Result<()> {
    let boundary = match crate::cache::find_git_root(project_dir).map_err(|e| anyhow::anyhow!(e))? {
        Some(root) => root,
        None => std::fs::canonicalize(project_dir)?,
    };
    let resolved = crate::cache::canonicalize_with_existing_ancestors(cache_dir).map_err(|e| {
        anyhow::anyhow!("Could not resolve cache directory for security validation: {e}")
    })?;
    if resolved.starts_with(&boundary) {
        anyhow::bail!(
            "Cache directory must live outside the project directory.\n  Cache: {}\n  Project: {}\n  Fix: Pass --cache-dir with a path outside the repository, or set XDG_CACHE_HOME to an absolute path outside it.",
            resolved.display(),
            boundary.display()
        );
    }
    Ok(())
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
        if year > 2200 {
            break;
        } // safety cap
        let ydays = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if rem_days < ydays {
            break;
        }
        rem_days -= ydays;
        year += 1;
    }
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_per_month = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1i64;
    for &dm in &days_per_month {
        if rem_days < dm {
            break;
        }
        rem_days -= dm;
        month += 1;
    }
    let day = rem_days + 1;
    (year, month, day, hour, min, sec)
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> Option<i64> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    })
}

/// Convert date components to epoch seconds. Inverse of epoch_secs_to_parts.
/// Handles leap years. Used by metadata age_in_hours.
pub fn date_to_epoch(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    checked_date_to_epoch(year, month, day, hour, min, sec).unwrap_or(0)
}

/// Convert date components to epoch seconds if they form a valid UTC timestamp.
pub fn checked_date_to_epoch(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    min: i64,
    sec: i64,
) -> Option<i64> {
    if year < 1970
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=59).contains(&sec)
    {
        return None;
    }
    let max_day = days_in_month(year, month)?;
    if !(1..=max_day).contains(&day) {
        return None;
    }

    let days_per_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 0..((month - 1) as usize) {
        days += days_per_month.get(m).copied().unwrap_or(30) as i64;
    }
    if month > 2 && is_leap_year(year) {
        days += 1;
    }
    days += day - 1;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

/// Convert epoch milliseconds to ISO 8601 string. Returns None for negative timestamps.
pub fn epoch_millis_to_iso8601(millis: i64) -> Option<String> {
    if millis < 0 {
        return None;
    }
    let (year, month, day, hour, min, _sec) = epoch_secs_to_parts(millis / 1000);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:00Z",
        year, month, day, hour, min
    ))
}

/// Convert current time to ISO 8601 string. Used by test helpers.
/// Split an ISO 8601 timestamp into its local part and the UTC offset in seconds.
fn split_utc_offset(date_str: &str) -> Option<(&str, i64)> {
    if let Some(utc) = date_str.strip_suffix('Z') {
        return Some((utc, 0));
    }
    let Some(offset_start) = date_str
        .rfind(['+', '-'])
        .filter(|index| date_str[..*index].contains('T'))
    else {
        // Legacy registry timestamps such as PyPI upload_time represent UTC without a suffix.
        return Some((date_str, 0));
    };
    let (local, offset) = date_str.split_at(offset_start);
    let (hours, minutes) = offset[1..].split_once(':')?;
    if hours.len() != 2 || minutes.len() != 2 {
        return None;
    }
    let hours: i64 = hours.parse().ok()?;
    let minutes: i64 = minutes.parse().ok()?;
    if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
        return None;
    }
    let seconds = hours * 3600 + minutes * 60;
    Some((
        local,
        if offset.starts_with('-') {
            -seconds
        } else {
            seconds
        },
    ))
}

/// Parse an ISO 8601 date string and return the age in hours.
pub(crate) fn age_in_hours(date_str: &str) -> Option<u64> {
    let diff_seconds = now_epoch() as i64 - iso_to_epoch(date_str)?;
    if diff_seconds < 0 {
        return None;
    }
    Some((diff_seconds / 3600) as u64)
}

/// Parse an ISO 8601 date string into Unix epoch seconds.
pub(crate) fn iso_to_epoch(date_str: &str) -> Option<i64> {
    // Parse common ISO 8601 formats: "2026-03-21T10:30:00.000Z"
    let (cleaned, offset_seconds) = split_utc_offset(date_str.trim())?;
    // Try parsing with chrono-like manual parsing (avoid adding chrono dep)
    // Format: YYYY-MM-DDTHH:MM:SS
    let parts: Vec<&str> = cleaned.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || !(2..=3).contains(&time_parts.len()) {
        return None;
    }
    let year: i64 = date_parts[0].parse().ok()?;
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let month: i64 = date_parts[1].parse().ok()?;
    let day: i64 = date_parts[2].parse().ok()?;
    let hour: i64 = time_parts[0].parse().ok()?;
    let min: i64 = time_parts[1].parse().ok()?;
    let sec = time_parts.get(2).copied().unwrap_or("0");
    let seconds = if let Some((seconds, fraction)) = sec.split_once('.') {
        if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        seconds
    } else {
        sec
    };
    let sec: i64 = seconds.parse().ok()?;

    Some(crate::cache::checked_date_to_epoch(year, month, day, hour, min, sec)? - offset_seconds)
}

/// Walk up from `dir` looking for a `.git` directory or file (worktrees/submodules
/// use a `.git` file). Returns the canonicalized repo root.
///
/// Returns `Err` if `dir` cannot be canonicalized (permissions, deleted).
/// Returns `Ok(None)` if no `.git` exists in the ancestry.
pub fn find_git_root(dir: &Path) -> Result<Option<PathBuf>, String> {
    let mut current = std::fs::canonicalize(dir).map_err(|e| {
        format!(
            "Could not resolve project directory.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists and is accessible.",
            dir.display(),
            e
        )
    })?;
    loop {
        if current.join(".git").exists() {
            return Ok(Some(current));
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}

/// Resolve `path` for boundary checks even when its tail does not exist yet.
/// Fails closed when the missing tail cannot be resolved without guessing:
/// `..` below a missing directory, or a dangling symlink.
pub(crate) fn canonicalize_with_existing_ancestors(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("Could not resolve current directory: {}", e))?
            .join(path)
    };

    let mut suffix = Vec::new();
    let mut existing = absolute.as_path();
    while !existing.exists() {
        if std::fs::symlink_metadata(existing).is_ok() {
            return Err(format!(
                "Could not resolve path '{}': it is a dangling symlink",
                existing.display()
            ));
        }
        let Some(std::path::Component::Normal(name)) = existing.components().next_back() else {
            return Err(format!(
                "Could not resolve path '{}': '..' below a missing directory cannot be resolved safely",
                absolute.display()
            ));
        };
        suffix.push(name.to_os_string());
        let Some(parent) = existing.parent() else {
            return Err(format!("Could not resolve path '{}'", absolute.display()));
        };
        existing = parent;
    }

    let mut resolved = std::fs::canonicalize(existing)
        .map_err(|e| format!("Could not resolve path '{}': {}", existing.display(), e))?;
    for component in suffix.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(test)]
pub fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (year, month, day, hour, min, sec) = epoch_secs_to_parts(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// Reject symlinked cache files to prevent symlink attacks.
pub fn ensure_no_symlink(path: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        anyhow::bail!("refusing to use symlinked cache file: {}", path.display());
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
pub fn atomic_write_json<T: serde::Serialize>(path: &Path, data: &T) {
    if ensure_no_symlink(path).is_err() {
        return;
    }
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
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
        return;
    };
    let tmp_path = cache_tmp_path(path);
    if std::fs::write(&tmp_path, json).is_err() {
        return;
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
}

/// Atomically write JSON to a file, returning errors instead of swallowing them.
/// Same logic as `atomic_write_json` but with actionable error messages.
pub fn atomic_write_json_checked<T: serde::Serialize>(path: &Path, data: &T) -> Result<(), String> {
    ensure_no_symlink(path).map_err(|e| {
        format!(
            "Refusing to write symlinked file.\n  Path: {}\n  Error: {}\n  Fix: Remove the symlink.",
            path.display(),
            e
        )
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Could not create parent directory.\n  Path: {}\n  Error: {}\n  Fix: Check directory permissions.",
                parent.display(),
                e
            )
        })?;
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
    let json = serde_json::to_string(data).map_err(|e| {
        format!(
            "Could not serialize data to JSON.\n  Path: {}\n  Error: {}",
            path.display(),
            e
        )
    })?;
    let tmp_path = cache_tmp_path(path);
    std::fs::write(&tmp_path, json).map_err(|e| {
        format!(
            "Could not write temporary file.\n  Path: {}\n  Error: {}\n  Fix: Check disk space and permissions.",
            tmp_path.display(),
            e
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&tmp_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&tmp_path, perms);
        }
    }
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!(
            "Could not rename temporary file to target.\n  Path: {}\n  Error: {}\n  Fix: Check filesystem permissions.",
            path.display(),
            e
        )
    })
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
    let age = now_epoch().checked_sub(timestamp_extractor(&data))?;
    if age < ttl_secs { Some(data) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-cache-{}-{}", std::process::id(), id));
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
        atomic_write_json(&path, &data);
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
        atomic_write_json(&path, &data);
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
        atomic_write_json(&path, &data);
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
        atomic_write_json(&real, &data);
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
