//! Loading, parsing and overlaying config files and URLs.
use super::*;

/// Resolve config source with full resolution cascade:
/// 1. `--config` CLI flag (highest priority)
/// 2. `SLOPPY_JOE_CONFIG` env var
/// 3. Registry lookup (if project_dir is Some)
/// 4. None (caller must handle — usually a blocking error)
///
/// Never reads from the project directory.
/// Accepts a file path or a URL (http:// or https://).
pub fn resolve_config_source(
    cli_config: Option<&str>,
    project_dir: Option<&Path>,
) -> Result<Option<String>, String> {
    // Step 1: --config flag
    if let Some(source) = cli_config {
        return Ok(Some(source.to_string()));
    }

    // Step 2: SLOPPY_JOE_CONFIG env var (skip if empty)
    if let Ok(source) = std::env::var("SLOPPY_JOE_CONFIG")
        && !source.is_empty()
    {
        return Ok(Some(source));
    }

    // Step 3: Registry lookup (only if project_dir is Some)
    if let Some(dir) = project_dir {
        return registry::lookup(dir);
    }

    // Step 4: No config found
    Ok(None)
}

/// Load config from a resolved path. Fails hard on malformed config —
/// a broken config should never silently fall back to no protection.
pub fn load_config(config_path: Option<&Path>) -> Result<SloppyJoeConfig, String> {
    load_config_with_project(config_path, None)
}

pub fn load_config_with_project(
    config_path: Option<&Path>,
    project_dir: Option<&Path>,
) -> Result<SloppyJoeConfig, String> {
    let mut config = if let Some(path) = config_path {
        ensure_config_outside_project(path, project_dir)?;

        let content = std::fs::read_to_string(path).map_err(|e| {
            format!(
                "Could not read config file: {}\n  Path: {}\n  Fix: Check that the file exists and is readable.\n       Use 'sloppy-joe init --register' or write a template to a safe external path with 'sloppy-joe init > /secure/sloppy-joe.json'.",
                e, path.display()
            )
        })?;

        parse_config_content(&content, &path.display().to_string())?
    } else {
        SloppyJoeConfig::default()
    };

    config = maybe_apply_local_overlay(config, project_dir)?;
    Ok(config)
}

/// Load config from a string source — either a file path or a URL.
/// Fails hard on errors — a misconfigured CI pipeline should not
/// silently run without protection.
pub async fn load_config_from_source(
    source: Option<&str>,
    project_dir: Option<&Path>,
) -> Result<SloppyJoeConfig, String> {
    let mut config = if let Some(source) = source {
        if config_source_has_scheme(source, "http") {
            return Err(format!(
                "Config URL must use HTTPS.\n  URL: {}\n  Fix: Use an https:// URL or a local path outside the project directory.",
                redact_url_for_display(source)
            ));
        } else if config_source_has_scheme(source, "https") {
            fetch_config_from_url(source).await?
        } else {
            return load_config_with_project(Some(Path::new(source)), project_dir);
        }
    } else {
        SloppyJoeConfig::default()
    };

    config = maybe_apply_local_overlay(config, project_dir)?;
    Ok(config)
}

/// Fetch config JSON from a URL.
async fn fetch_config_from_url(url: &str) -> Result<SloppyJoeConfig, String> {
    let display_url = redact_url_for_display(url);
    // Use a dedicated client with no redirects to prevent SSRF via redirect chains
    let client = reqwest::Client::builder()
        .user_agent("sloppy-joe")
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build config HTTP client");
    let response = client.get(url).send().await.map_err(|e| {
        format!(
            "Could not fetch config from URL: {}\n  URL: {}\n  Fix: Check that the URL is reachable and returns valid JSON.\n       For private repos, ensure your CI token has read access.",
            e, display_url
        )
    })?;

    if !response.status().is_success() {
        return Err(format!(
            "Config URL returned HTTP {}\n  URL: {}\n  Fix: Check that the URL points to a valid JSON file.\n       For GitHub raw URLs, use: https://raw.githubusercontent.com/org/repo/main/sloppy-joe.json",
            response.status(),
            display_url
        ));
    }

    // Reject oversized responses BEFORE reading the body into memory.
    // Check Content-Length header first (fast path), then cap the read.
    const MAX_CONFIG_BYTES: u64 = 1_024 * 1_024;
    if let Some(len) = response.content_length()
        && len > MAX_CONFIG_BYTES
    {
        return Err(format!(
            "Config response too large ({} bytes, max {} bytes)\n  URL: {}",
            len, MAX_CONFIG_BYTES, display_url
        ));
    }
    // Read body in chunks with a hard size cap to prevent OOM from chunked responses
    // that bypass Content-Length (the header check above only works when the server sends it).
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| format!("Could not read response body from {}: {}", display_url, e))?;
        body.extend_from_slice(&chunk);
        if body.len() as u64 > MAX_CONFIG_BYTES {
            return Err(format!(
                "Config response too large (>{} bytes)\n  URL: {}",
                MAX_CONFIG_BYTES, display_url
            ));
        }
    }
    let bytes = body;
    let content = String::from_utf8(bytes)
        .map_err(|e| format!("Config response is not valid UTF-8: {}", e))?;

    parse_config_content(&content, &display_url)
}

pub(crate) fn redact_url_for_display(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return "<invalid URL redacted>".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

/// Walks any JSON value and rejects objects that repeat a key. serde_json
/// otherwise keeps the last value for map keys, silently dropping policy.
pub(super) struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateKeysVisitor)
    }
}

pub(super) struct NoDuplicateKeysVisitor;

impl<'de> serde::de::Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key `{key}`")));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

pub(super) fn reject_duplicate_keys(
    content: &str,
    label: &str,
    source: &str,
) -> Result<(), String> {
    match serde_json::from_str::<NoDuplicateKeys>(content) {
        // Syntax errors are reported by the typed parse with better hints.
        Err(e) if e.is_data() => Err(format!(
            "{label} has a duplicate key.\n  Source: {source}\n  Error: {e}\n  Fix: Remove the repeated key; only one value per key is allowed."
        )),
        _ => Ok(()),
    }
}

/// Parse config JSON content with actionable error messages.
pub(super) fn parse_config_content(content: &str, source: &str) -> Result<SloppyJoeConfig, String> {
    if content.trim().is_empty() {
        return Err(format!(
            "Config is empty.\n  Source: {}\n  Fix: Use 'sloppy-joe init > /secure/location/sloppy-joe.json' to generate a template outside the repo.",
            source
        ));
    }

    reject_duplicate_keys(content, "Config", source)?;
    let mut config: SloppyJoeConfig = serde_json::from_str(content).map_err(|e| {
        let mut msg = format!(
            "Config is not valid JSON.\n  Source: {}\n  Error: {}",
            source, e
        );

        // Add specific hints for common mistakes
        if content.contains("//") {
            msg.push_str("\n  Hint: JSON does not support comments. Remove lines starting with //.");
        }
        if content.contains(",\n}") || content.contains(",\n]") || content.contains(", }") || content.contains(", ]") {
            msg.push_str("\n  Hint: Trailing commas are not allowed in JSON. Remove the comma before } or ].");
        }
        if !content.starts_with('{') {
            msg.push_str("\n  Hint: Config must be a JSON object starting with {.");
        }

        msg.push_str("\n  Fix: Validate your JSON at https://jsonlint.com or use 'sloppy-joe init' for a template.");
        msg
    })?;

    for indexes in config.trusted_indexes.values_mut() {
        for index in indexes.iter_mut() {
            *index = normalize_python_index_url(index);
        }
    }

    let validation_errors = config.validate();
    if !validation_errors.is_empty() {
        return Err(format!(
            "Config validation failed:\n  {}",
            validation_errors.join("\n  ")
        ));
    }

    Ok(config)
}

pub(super) fn parse_local_overlay_content(
    content: &str,
    source: &str,
) -> Result<LocalOverlayConfig, String> {
    if content.trim().is_empty() {
        return Err(format!(
            "Local overlay config is empty.\n  Source: {}\n  Fix: Remove the file or provide valid JSON.",
            source
        ));
    }

    reject_duplicate_keys(content, "Local overlay config", source)?;
    serde_json::from_str(content).map_err(|e| {
        format!(
            "Local overlay config is not valid JSON.\n  Source: {}\n  Error: {}\n  Fix: Use a JSON object with only local provenance fields.",
            source, e
        )
    })
}

pub(super) fn overlay_relaxation_messages(overlay: &LocalOverlayConfig) -> Vec<String> {
    let mut messages = Vec::new();
    if !overlay.trusted_local_paths.is_empty() {
        messages.push("local trusted Cargo path allowlist".to_string());
    }
    if !overlay.trusted_registries.is_empty() {
        messages.push("local trusted Cargo registry allowlist".to_string());
    }
    if !overlay.trusted_git_sources.is_empty() {
        messages.push("local trusted Cargo git allowlist".to_string());
    }
    if overlay.cargo_git_policy == Some(CargoGitPolicy::WarnPinned) {
        messages.push("reduced-confidence Cargo git policy".to_string());
    }
    if overlay.allow_host_local_cargo_config {
        messages.push("host-local Cargo config trust".to_string());
    }
    messages
}

pub(super) fn apply_local_overlay(
    mut base: SloppyJoeConfig,
    overlay: LocalOverlayConfig,
) -> SloppyJoeConfig {
    let relaxation_messages = overlay_relaxation_messages(&overlay);
    for (ecosystem, paths) in overlay.trusted_local_paths {
        base.trusted_local_paths
            .entry(ecosystem)
            .or_default()
            .extend(paths);
    }
    for (ecosystem, registries) in overlay.trusted_registries {
        base.trusted_registries
            .entry(ecosystem)
            .or_default()
            .extend(registries);
    }
    for (ecosystem, sources) in overlay.trusted_git_sources {
        base.trusted_git_sources
            .entry(ecosystem)
            .or_default()
            .extend(sources);
    }
    if overlay.cargo_git_policy == Some(CargoGitPolicy::WarnPinned) {
        base.cargo_git_policy = CargoGitPolicy::WarnPinned;
    }
    if overlay.allow_host_local_cargo_config {
        base.allow_host_local_cargo_config = true;
    }
    base.active_local_overlay_relaxations = relaxation_messages;
    base
}

pub(super) fn local_overlay_path() -> Result<PathBuf, String> {
    registry::config_home().map(|home| home.join("local-overlay.json"))
}

pub(super) fn running_in_ci() -> bool {
    std::env::var("CI")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

pub(super) fn config_source_has_scheme(source: &str, scheme: &str) -> bool {
    source
        .get(..scheme.len() + 3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&format!("{scheme}://")))
}

pub(super) fn maybe_apply_local_overlay(
    config: SloppyJoeConfig,
    project_dir: Option<&Path>,
) -> Result<SloppyJoeConfig, String> {
    if running_in_ci() {
        return Ok(config);
    }

    let overlay_path = local_overlay_path()?;
    if !overlay_path.exists() {
        return Ok(config);
    }
    if let Some(dir) = project_dir
        && let Some(config_home) = overlay_path.parent()
    {
        registry::ensure_config_home_outside_project(dir, config_home)?;
    }

    load_local_overlay_from_path(config, &overlay_path)
}

pub(super) fn load_local_overlay_from_path(
    base: SloppyJoeConfig,
    path: &Path,
) -> Result<SloppyJoeConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Could not read local overlay config: {}\n  Path: {}\n  Fix: Check file permissions or remove the local overlay file.",
            e, path.display()
        )
    })?;
    let overlay = parse_local_overlay_content(&content, &path.display().to_string())?;
    Ok(apply_local_overlay(base, overlay))
}

pub(super) fn ensure_config_outside_project(
    path: &Path,
    project_dir: Option<&Path>,
) -> Result<(), String> {
    let Some(project_dir) = project_dir else {
        return Ok(());
    };

    let project_dir = registry::find_git_root(project_dir)?
        .unwrap_or(std::fs::canonicalize(project_dir).map_err(|err| err.to_string())?);
    let path = std::fs::canonicalize(path).map_err(|e| {
        format!(
            "Could not resolve config path for security validation.\n  Path: {}\n  Error: {}\n  Fix: Check that the config file exists and is accessible.",
            path.display(),
            e
        )
    })?;

    if path.starts_with(&project_dir) {
        return Err(format!(
            "Config file must live outside the project directory.\n  Config: {}\n  Project: {}\n  Fix: Move the config file outside the repo or use an https:// URL.",
            path.display(),
            project_dir.display()
        ));
    }

    Ok(())
}
