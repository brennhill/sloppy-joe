//! Cross-check of `composer.lock` download locations against Packagist.
//!
//! `composer install` fetches each package from the lock's `dist.url` / `source.url`, so a lock
//! can name Packagist's `psr/log` and still download an attacker's repository on a trusted host.
//! The p2 metadata lists where Packagist says each version lives; the lock must agree.

use super::*;

const PACKAGIST_URL: &str = "https://repo.packagist.org";

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_PACKAGIST_URL: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

fn packagist_url() -> String {
    #[cfg(test)]
    if let Some(url) = TEST_PACKAGIST_URL.with(|url| url.borrow().clone()) {
        return url;
    }
    PACKAGIST_URL.to_string()
}

#[derive(Debug, PartialEq)]
struct Published {
    source_url: Option<String>,
    source_reference: Option<String>,
    dist_url: Option<String>,
    dist_reference: Option<String>,
}

/// Lowercased, without a trailing slash or `.git`, so spellings of one repository compare equal.
fn normalize_url(url: &str) -> String {
    let url = url.trim().trim_end_matches('/').to_ascii_lowercase();
    url.strip_suffix(".git").unwrap_or(&url).to_string()
}

/// p2 responses are minified: each version lists only the fields that changed from the one
/// before it, and `"__unset"` removes a field.
fn published_version(body: &serde_json::Value, name: &str, version: &str) -> Option<Published> {
    let mut current = serde_json::Map::new();
    for entry in body["packages"][name].as_array()? {
        for (key, value) in entry.as_object()? {
            if value.as_str() == Some("__unset") {
                current.remove(key);
            } else {
                current.insert(key.clone(), value.clone());
            }
        }
        let matches = |field: &str| current.get(field).and_then(|v| v.as_str()) == Some(version);
        if matches("version") || matches("version_normalized") {
            let text = |outer: &str, inner: &str| {
                current
                    .get(outer)
                    .and_then(|value| value.get(inner))
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            };
            return Some(Published {
                source_url: text("source", "url"),
                source_reference: text("source", "reference"),
                dist_url: text("dist", "url"),
                dist_reference: text("dist", "reference"),
            });
        }
    }
    None
}

fn disagreement(entry: &serde_json::Value, published: &Published) -> Option<&'static str> {
    let field = |outer: &str, inner: &str| {
        entry
            .get(outer)
            .and_then(|value| value.get(inner))
            .and_then(|value| value.as_str())
    };
    let url_differs = |locked: Option<&str>, expected: &Option<String>| match (locked, expected) {
        (Some(locked), Some(expected)) => normalize_url(locked) != normalize_url(expected),
        (None, None) => false,
        _ => true,
    };
    if url_differs(field("source", "url"), &published.source_url) {
        return Some("source.url");
    }
    if field("source", "reference") != published.source_reference.as_deref() {
        return Some("source.reference");
    }
    if url_differs(field("dist", "url"), &published.dist_url) {
        return Some("dist.url");
    }
    if field("dist", "reference") != published.dist_reference.as_deref() {
        return Some("dist.reference");
    }
    None
}

/// Every locked package must resolve on Packagist to the locations the lock records. A lookup
/// that fails, or a version Packagist does not list, blocks.
pub(crate) async fn verify_lock_locations(
    client: &reqwest::Client,
    lockfile: &Path,
) -> Result<Vec<Issue>> {
    let content = parsers::read_file_limited(lockfile, parsers::MAX_MANIFEST_BYTES)?;
    let lock: serde_json::Value = serde_json::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", lockfile.display(), err))?;
    let base = packagist_url();
    let mut issues = Vec::new();
    for section in ["packages", "packages-dev"] {
        for entry in lock[section].as_array().into_iter().flatten() {
            let (Some(name), Some(version)) = (entry["name"].as_str(), entry["version"].as_str())
            else {
                anyhow::bail!(
                    "Broken lockfile '{}': a package has no name or version",
                    lockfile.display()
                );
            };
            if !registry::validate_package_name(name) {
                anyhow::bail!("Invalid package name in '{}'", lockfile.display());
            }
            let url = format!("{base}/p2/{}.json", name.to_ascii_lowercase());
            let response = crate::http::retry_get(client, &url).await?;
            let status = response.status();
            let published = if status.is_success() {
                let body: serde_json::Value = response.json().await?;
                published_version(&body, &name.to_ascii_lowercase(), version)
            } else if status == reqwest::StatusCode::NOT_FOUND {
                None
            } else {
                anyhow::bail!("Packagist returned HTTP {status} for '{name}'");
            };
            let problem = match &published {
                None => Some(format!("Packagist does not list {name} {version}")),
                Some(published) => disagreement(entry, published).map(|field| {
                    format!("the lock's {field} for {name} {version} differs from Packagist's")
                }),
            };
            if let Some(problem) = problem {
                issues.push(
                    Issue::new(
                        name,
                        checks::names::RESOLUTION_SOURCE_MISMATCH,
                        Severity::Error,
                    )
                    .message(format!(
                        "composer.lock downloads {name} from a location Packagist does not publish: {problem}."
                    ))
                    .fix("Regenerate composer.lock from Packagist (composer update) and review the diff."),
                );
            }
        }
    }
    Ok(issues)
}

#[cfg(test)]
#[path = "provenance_tests.rs"]
mod tests;
