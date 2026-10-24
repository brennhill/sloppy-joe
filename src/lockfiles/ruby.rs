use crate::Dependency;
use anyhow::Result;
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;
use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, missing_entry_issue, no_trusted_lockfile_sync_issue,
    out_of_sync_issue,
};

/// Resolve versions from a pre-read Gemfile.lock content string.
#[cfg(test)]
pub(super) fn resolve_from_content(content: &str, deps: &[Dependency]) -> Result<ResolutionResult> {
    resolve_from_content_with_mode(content, deps, ResolutionMode::Direct)
}

pub(super) fn resolve_from_content_with_mode(
    content: &str,
    deps: &[Dependency],
    mode: ResolutionMode,
) -> Result<ResolutionResult> {
    let versions = parse_gem_versions(content)?;
    let mut result = ResolutionResult::default();

    for dep in deps {
        match versions.get(&dep.name) {
            Some(version) => {
                if let Some(exact_manifest) = dep.exact_version()
                    && exact_manifest != *version
                {
                    result.push_issue_for(dep, out_of_sync_issue(dep, version));
                    add_manifest_exact_fallback(&mut result, dep);
                    continue;
                }
                if mode == ResolutionMode::Direct
                    && dep.version.is_some()
                    && dep.exact_version().is_none()
                {
                    result.push_issue_for(dep, no_trusted_lockfile_sync_issue(dep, "Gemfile.lock"));
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
                result.push_issue_for(dep, missing_entry_issue(dep, "Gemfile.lock"));
                add_manifest_exact_fallback(&mut result, dep);
            }
        }
    }

    Ok(result)
}

/// Parse all gems from Gemfile.lock content.
pub(super) fn parse_all_from_content(content: &str) -> Result<Vec<Dependency>> {
    let versions = parse_gem_versions(content)?;
    Ok(versions
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::Ruby,
            actual_name: None,
        })
        .collect())
}

/// Read Gemfile.lock if it exists, return content. A lockfile that exists but
/// cannot be inspected or read is an error, never "no lockfile".
pub(super) fn read_lockfile(project_dir: &Path) -> Result<Option<String>> {
    let path = project_dir.join("Gemfile.lock");
    if !crate::parsers::path_detected(&path)? {
        return Ok(None);
    }
    crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)
        .map(Some)
        .map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })
}

/// Resolve from disk (used by resolve_versions test API).
#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(content) = read_lockfile(project_dir)? else {
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
///
/// Only `GEM` (registry) sections are trusted. `GIT`, `PATH`, and
/// `PLUGIN SOURCE` sections install code that never came from a registry, and
/// `specs:` under any other section cannot be attributed to one, so both are
/// blocking errors rather than being mistaken for registry gems.
/// A `remote:` line of the GEM section must be RubyGems itself.
fn check_gem_remote(section: &str, line: &str) -> Result<()> {
    if section == "GEM"
        && let Some(remote) = line.trim().strip_prefix("remote:")
        && remote.trim().trim_end_matches('/') != "https://rubygems.org"
    {
        anyhow::bail!(
            "Gemfile.lock GEM remote '{}' is not https://rubygems.org/; sloppy-joe only trusts gems resolved from RubyGems",
            crate::report::sanitize_for_terminal(remote.trim())
        );
    }
    Ok(())
}

fn parse_gem_versions(content: &str) -> Result<std::collections::HashMap<String, String>> {
    let mut versions = std::collections::HashMap::new();
    let mut in_specs = false;
    let mut section = "";

    for line in content.lines() {
        if !line.is_empty() && !line.starts_with(char::is_whitespace) {
            section = line.trim();
            if matches!(section, "GIT" | "PATH" | "PLUGIN SOURCE") {
                anyhow::bail!(
                    "Gemfile.lock contains a {} source section. sloppy-joe only trusts gems resolved from a registry GEM source; git, path, and plugin sources cannot be verified.",
                    section
                );
            }
        }
        check_gem_remote(section, line)?;
        if line.trim() == "specs:" {
            if section != "GEM" {
                anyhow::bail!(
                    "Gemfile.lock lists specs under unsupported section '{}'. sloppy-joe only trusts gems resolved from a registry GEM source.",
                    crate::report::sanitize_for_terminal(section)
                );
            }
            in_specs = true;
            continue;
        }

        // End of specs section: a line that's not indented enough
        if in_specs && !line.starts_with("    ") && !line.trim().is_empty() {
            in_specs = false;
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

    Ok(versions)
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
        let versions = parse_gem_versions(GEMFILE_LOCK).unwrap();
        assert_eq!(versions.get("rails"), Some(&"7.0.4".to_string()));
        assert_eq!(versions.get("actioncable"), Some(&"7.0.4".to_string()));
        assert_eq!(versions.get("pg"), Some(&"1.4.5".to_string()));
        assert_eq!(versions.get("puma"), Some(&"6.0.2".to_string()));
    }

    #[test]
    fn resolve_finds_version() {
        let deps = vec![dep("rails", Some("7.0.4")), dep("pg", None)];
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

#[cfg(test)]
mod remote_tests {
    use super::*;

    #[test]
    fn only_rubygems_org_is_a_trusted_gem_remote() {
        let lock = |remote: &str| {
            format!("GEM\n  remote: {remote}\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n")
        };
        assert!(parse_gem_versions(&lock("https://rubygems.org/")).is_ok());
        assert!(parse_gem_versions(&lock("https://evil.example.com/")).is_err());
    }
}
