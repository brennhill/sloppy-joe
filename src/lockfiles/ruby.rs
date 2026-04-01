use crate::Dependency;
use anyhow::Result;
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;
use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, missing_entry_issue, out_of_sync_issue,
};

/// Resolve versions from a pre-read Gemfile.lock content string.
pub(super) fn resolve_from_content(content: &str, deps: &[Dependency]) -> Result<ResolutionResult> {
    let versions = parse_gem_versions(content);
    let mut result = ResolutionResult::default();

    for dep in deps {
        match versions.get(&dep.name) {
            Some(version) => {
                if let Some(exact_manifest) = dep.exact_version()
                    && exact_manifest != *version
                {
                    result.issues.push(out_of_sync_issue(dep, version));
                    add_manifest_exact_fallback(&mut result, dep);
                    continue;
                }
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: version.clone(),
                        source: ResolutionSource::Lockfile,
                    },
                );
            }
            None => {
                result.issues.push(missing_entry_issue(dep, "Gemfile.lock"));
                add_manifest_exact_fallback(&mut result, dep);
            }
        }
    }

    Ok(result)
}

/// Parse all gems from Gemfile.lock content.
pub(super) fn parse_all_from_content(content: &str) -> Result<Vec<Dependency>> {
    let versions = parse_gem_versions(content);
    Ok(versions
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::Ruby,
        })
        .collect())
}

/// Read Gemfile.lock if it exists, return content.
pub(super) fn read_lockfile(project_dir: &Path) -> Option<String> {
    let path = project_dir.join("Gemfile.lock");
    if !crate::parsers::path_detected(&path).ok()? {
        return None;
    }
    crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES).ok()
}

/// Resolve from disk (used by resolve_versions test API).
#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(content) = read_lockfile(project_dir) else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    resolve_from_content(&content, deps)
}

/// Parse "GEM / specs:" section of Gemfile.lock.
/// Format:
/// ```text
/// GEM
///   remote: https://rubygems.org/
///   specs:
///     rails (7.0.4)
///       actioncable (= 7.0.4)
///     actioncable (7.0.4)
/// ```
/// Top-level gem entries are indented 4 spaces, sub-deps are indented 6+.
fn parse_gem_versions(content: &str) -> std::collections::HashMap<String, String> {
    let mut versions = std::collections::HashMap::new();
    let mut in_specs = false;

    for line in content.lines() {
        if line.trim() == "specs:" {
            in_specs = true;
            continue;
        }

        // End of specs section: a line that's not indented enough
        if in_specs && !line.starts_with("    ") && !line.trim().is_empty() {
            in_specs = false;
            // Could be another section (PLATFORMS, etc.)
            if line.trim() == "specs:" {
                in_specs = true;
            }
            continue;
        }

        if !in_specs {
            continue;
        }

        // Top-level gems are indented exactly 4 spaces: "    name (version)"
        // Sub-dependencies are indented 6+ spaces, skip them
        if line.starts_with("      ") {
            continue;
        }

        let trimmed = line.trim();
        if let Some((name, rest)) = trimmed.split_once(' ') {
            let version = rest.trim_start_matches('(').trim_end_matches(')');
            if !name.is_empty() && !version.is_empty() {
                versions.insert(name.to_string(), version.to_string());
            }
        }
    }

    versions
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEMFILE_LOCK: &str = r#"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)
      actioncable (= 7.0.4)
      actionmailer (= 7.0.4)
    actioncable (7.0.4)
      actionpack (= 7.0.4)
    actionmailer (7.0.4)
    pg (1.4.5)
    puma (6.0.2)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0)
  pg
  puma
"#;

    fn dep(name: &str, version: Option<&str>) -> Dependency {
        crate::test_helpers::dep_with(name, version, crate::Ecosystem::Ruby)
    }

    #[test]
    fn parse_gem_versions_extracts_all() {
        let versions = parse_gem_versions(GEMFILE_LOCK);
        assert_eq!(versions.get("rails"), Some(&"7.0.4".to_string()));
        assert_eq!(versions.get("actioncable"), Some(&"7.0.4".to_string()));
        assert_eq!(versions.get("pg"), Some(&"1.4.5".to_string()));
        assert_eq!(versions.get("puma"), Some(&"6.0.2".to_string()));
    }

    #[test]
    fn resolve_finds_version() {
        let deps = vec![dep("rails", Some("~> 7.0")), dep("pg", None)];
        let result = resolve_from_content(GEMFILE_LOCK, &deps).unwrap();
        assert_eq!(result.exact_version(&deps[0]), Some("7.0.4"));
        assert_eq!(result.exact_version(&deps[1]), Some("1.4.5"));
        assert!(result.issues.is_empty());
    }

    #[test]
    fn resolve_missing_dep_reports_issue() {
        let deps = vec![dep("nonexistent-gem", None)];
        let result = resolve_from_content(GEMFILE_LOCK, &deps).unwrap();
        assert!(result.exact_version(&deps[0]).is_none());
        assert!(!result.issues.is_empty());
        assert!(result.issues[0].check.contains("missing"));
    }

    #[test]
    fn parse_all_extracts_transitive() {
        let all = parse_all_from_content(GEMFILE_LOCK).unwrap();
        let names: Vec<&str> = all.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"rails"));
        assert!(names.contains(&"actioncable"));
        assert!(names.contains(&"actionmailer"));
        assert!(names.contains(&"pg"));
        assert!(names.contains(&"puma"));
        // All should have versions
        assert!(all.iter().all(|d| d.version.is_some()));
    }
}
