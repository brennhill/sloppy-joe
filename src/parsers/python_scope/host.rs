use super::*;

#[derive(Clone, Debug)]
pub(crate) struct DetectedPythonVersion {
    pub(crate) python_version: String,
    pub(crate) python_full_version: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DetectedHostPlatformMetadata {
    pub(crate) platform_release: Option<String>,
    pub(crate) platform_version: Option<String>,
}

pub(crate) static DETECTED_HOST_PYTHON_VERSION: OnceLock<Option<DetectedPythonVersion>> =
    OnceLock::new();

pub(crate) static DETECTED_HOST_PLATFORM_METADATA: OnceLock<DetectedHostPlatformMetadata> =
    OnceLock::new();

pub(crate) fn detected_host_python_version() -> Option<DetectedPythonVersion> {
    DETECTED_HOST_PYTHON_VERSION
        .get_or_init(detect_host_python_version_uncached)
        .clone()
}

pub(crate) fn detected_host_platform_metadata() -> DetectedHostPlatformMetadata {
    DETECTED_HOST_PLATFORM_METADATA
        .get_or_init(detect_host_platform_metadata_uncached)
        .clone()
}

pub(crate) fn detect_host_python_version_uncached() -> Option<DetectedPythonVersion> {
    ["python3", "python"]
        .into_iter()
        .find_map(detect_python_version_from_command)
}

pub(crate) fn detect_host_platform_metadata_uncached() -> DetectedHostPlatformMetadata {
    DetectedHostPlatformMetadata {
        platform_release: detect_uname_value("-r"),
        platform_version: detect_uname_value("-v"),
    }
}

pub(crate) fn detect_uname_value(flag: &str) -> Option<String> {
    let output = std::process::Command::new("uname")
        .arg(flag)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

pub(crate) fn detect_python_version_from_command(command: &str) -> Option<DetectedPythonVersion> {
    let output = std::process::Command::new(command)
        .args([
            "-c",
            // `platform.python_version()` is what PEP 508 calls python_full_version: it keeps
            // a prerelease suffix (`3.13.0rc1`) that `major.minor.micro` would drop.
            "import platform, sys; print(f'{sys.version_info.major}.{sys.version_info.minor}'); print(platform.python_version())",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_detected_python_version_output(&output.stdout)
}

pub(crate) fn parse_detected_python_version_output(output: &[u8]) -> Option<DetectedPythonVersion> {
    let output = std::str::from_utf8(output).ok()?;
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let python_version = lines.next()?.to_string();
    let python_full_version = lines
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| normalize_python_full_version(&python_version));
    Some(DetectedPythonVersion {
        python_version,
        python_full_version,
    })
}

pub(crate) fn normalize_python_full_version(version: &str) -> String {
    if version.matches('.').count() >= 2 {
        version.to_string()
    } else {
        format!("{version}.0")
    }
}

pub(crate) fn current_sys_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

/// `platform_release` / `platform_version` for the profile: the `SLOPPY_JOE_<NAME>` or `<NAME>`
/// setting, else `uname` when the profile is the host. `None` (undecided) otherwise.
pub(crate) fn resolve_host_platform_metadata(
    profile: &PythonProfile,
    uname_flag: &str,
    env_name: &str,
) -> Option<String> {
    for name in [format!("SLOPPY_JOE_{env_name}"), env_name.to_string()] {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            return Some(value.trim().to_string());
        }
    }
    if profile.target_platform != current_sys_platform()
        || profile.target_arch != std::env::consts::ARCH
    {
        return None;
    }
    let detected = detected_host_platform_metadata();
    match uname_flag {
        "-r" => detected.platform_release,
        "-v" => detected.platform_version,
        _ => None,
    }
}

pub(crate) fn poetry_platform_constraint_matches(
    target_platform: &str,
    constraint: &str,
) -> Result<bool> {
    let target = normalize_poetry_platform_token(target_platform)?;
    let allowed = parse_poetry_platform_constraint(constraint)?;
    Ok(allowed.contains(&target))
}

pub(crate) fn parse_poetry_platform_constraint(constraint: &str) -> Result<BTreeSet<String>> {
    let mut allowed = BTreeSet::new();
    for token in constraint
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        allowed.insert(normalize_poetry_platform_token(token)?);
    }
    if allowed.is_empty() {
        bail!("empty Poetry platform shorthand cannot be trusted exactly");
    }
    Ok(allowed)
}

pub(crate) fn normalize_poetry_platform_token(token: &str) -> Result<String> {
    let lowered = token.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        bail!("empty Poetry platform shorthand cannot be trusted exactly");
    }
    if lowered
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
    {
        bail!(
            "Unsupported Poetry platform shorthand '{}'",
            crate::report::sanitize_for_terminal(token)
        );
    }
    Ok(match lowered.as_str() {
        "macos" | "darwin" => "darwin".to_string(),
        "windows" | "win32" => "win32".to_string(),
        "linux" => "linux".to_string(),
        other => other.to_string(),
    })
}
