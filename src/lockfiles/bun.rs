use crate::Dependency;
use anyhow::Result;

use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, add_manifest_exact_fallbacks, missing_entry_issue,
    out_of_sync_issue, parse_failed_issue,
};

pub(super) fn resolve_from_value(
    parsed: &serde_json::Value,
    deps: &[Dependency],
    importer_key: &str,
) -> Result<ResolutionResult> {
    let Some(workspaces) = parsed.get("workspaces").and_then(|value| value.as_object()) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "bun.lock",
            "lockfile did not contain a workspaces section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    let Some(importer) = workspaces.get(importer_key) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "bun.lock",
            format!("lockfile did not contain workspace '{}'", importer_key),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let Some(packages) = parsed.get("packages").and_then(|value| value.as_object()) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "bun.lock",
            "lockfile did not contain a packages section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let mut result = ResolutionResult::default();
    for dep in deps {
        let Some(specifier) = importer_dependency_specifier(importer, dep.package_name()) else {
            result.push_issue_for(dep, missing_entry_issue(dep, "bun.lock"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };

        let matching_versions = packages
            .iter()
            .filter_map(|(_key, value)| bun_package_descriptor(value))
            .filter_map(|descriptor| {
                let (name, version) = bun_descriptor_parts(descriptor)?;
                (name == dep.package_name()).then_some(version.to_string())
            })
            .collect::<Vec<_>>();

        let resolved = match matching_versions.as_slice() {
            [] => {
                result.push_issue_for(dep, missing_entry_issue(dep, "bun.lock"));
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
            [version] => version.clone(),
            _ => {
                result.push_issue_for(
                    dep,
                    parse_failed_issue(
                        "bun.lock",
                        format!(
                            "lockfile contained multiple package entries for '{}'",
                            dep.package_name()
                        ),
                    ),
                );
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
        };

        if let Some(exact_manifest) = dep.exact_version()
            && exact_manifest != resolved
        {
            result.push_issue_for(dep, out_of_sync_issue(dep, &resolved));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        }

        if dep
            .version
            .as_deref()
            .is_some_and(|requested| requested != specifier)
        {
            result.push_issue_for(dep, out_of_sync_issue(dep, &resolved));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        }

        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version: resolved,
                source: ResolutionSource::Lockfile,
            },
        );
    }

    Ok(result)
}

pub(super) fn parse_all_from_value(parsed: &serde_json::Value) -> Result<Vec<Dependency>> {
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_object()) else {
        return Ok(vec![]);
    };
    let mut deps = Vec::new();
    for value in packages.values() {
        let Some(descriptor) = bun_package_descriptor(value) else {
            continue;
        };
        let Some((name, version)) = bun_descriptor_parts(descriptor) else {
            continue;
        };
        if !crate::registry::validate_package_name(name) {
            continue;
        }
        deps.push(Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: crate::Ecosystem::Npm,
            actual_name: None,
        });
    }
    Ok(deps)
}

fn importer_dependency_specifier<'a>(
    importer: &'a serde_json::Value,
    dep_name: &str,
) -> Option<&'a str> {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let specifier = importer
            .get(section)
            .and_then(|value| value.get(dep_name))
            .and_then(|value| value.as_str());
        if specifier.is_some() {
            return specifier;
        }
    }
    None
}

fn bun_package_descriptor(value: &serde_json::Value) -> Option<&str> {
    value.as_array()?.first()?.as_str()
}

fn bun_descriptor_parts(descriptor: &str) -> Option<(&str, &str)> {
    let descriptor = descriptor.trim();
    if descriptor.is_empty()
        || descriptor.contains("@workspace:")
        || descriptor.contains("@file:")
        || descriptor.contains("@link:")
    {
        return None;
    }
    if let Some(stripped) = descriptor.strip_prefix('@') {
        let slash = stripped.find('/')?;
        let after_scope = 1 + slash + 1;
        let version_at = descriptor[after_scope..].rfind('@')?;
        let split = after_scope + version_at;
        let (name, version) = descriptor.split_at(split);
        return Some((name, version.trim_start_matches('@')));
    }
    let split = descriptor.rfind('@')?;
    let (name, version) = descriptor.split_at(split);
    Some((name, version.trim_start_matches('@')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_reads_scoped_and_unscoped_packages() {
        let parsed: serde_json::Value = json5::from_str(
            r#"{
  "packages": {
    "react": ["react@18.3.1"],
    "@scope/pkg": ["@scope/pkg@1.2.3"],
    "web": ["web@workspace:apps/web"],
  },
}"#,
        )
        .unwrap();
        let deps = parse_all_from_value(&parsed).unwrap();
        let names = deps.iter().map(|dep| dep.name.as_str()).collect::<Vec<_>>();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"@scope/pkg"));
        assert!(!names.contains(&"web"));
    }
}
