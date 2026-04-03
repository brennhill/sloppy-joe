use crate::Dependency;
use anyhow::Result;

use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, add_manifest_exact_fallbacks, missing_entry_issue,
    out_of_sync_issue, parse_failed_issue,
};

pub(super) fn resolve_from_value(
    parsed: &serde_yaml::Value,
    deps: &[Dependency],
    importer_key: &str,
) -> Result<ResolutionResult> {
    let Some(importers) = parsed.get("importers").and_then(|value| value.as_mapping()) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "pnpm-lock.yaml",
            "lockfile did not contain an importers section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    let Some(importer) = importers.get(importer_key) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "pnpm-lock.yaml",
            format!("lockfile did not contain importer '{}'", importer_key),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let mut result = ResolutionResult::default();
    for dep in deps {
        let Some(reference) = importer_dependency_reference(importer, dep.package_name()) else {
            result.push_issue_for(dep, missing_entry_issue(dep, "pnpm-lock.yaml"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };
        let Some(version) = normalized_pnpm_reference(reference, dep.package_name()) else {
            result.push_issue_for(dep, missing_entry_issue(dep, "pnpm-lock.yaml"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };
        if let Some(exact_manifest) = dep.exact_version()
            && exact_manifest != version
        {
            result.push_issue_for(dep, out_of_sync_issue(dep, &version));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        }
        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version,
                source: ResolutionSource::Lockfile,
            },
        );
    }

    Ok(result)
}

pub(super) fn parse_all_from_value(parsed: &serde_yaml::Value) -> Result<Vec<Dependency>> {
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_mapping()) else {
        return Ok(vec![]);
    };
    let mut deps = Vec::new();
    for (key, _value) in packages {
        let Some(key) = key.as_str() else {
            continue;
        };
        let Some((name, version)) = pnpm_package_key_parts(key) else {
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

fn importer_dependency_reference<'a>(
    importer: &'a serde_yaml::Value,
    dep_name: &str,
) -> Option<&'a str> {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let version = importer
            .get(section)
            .and_then(|value| value.get(dep_name))
            .and_then(|value| value.get("version"))
            .and_then(|value| value.as_str());
        if version.is_some() {
            return version;
        }
    }
    None
}

fn normalized_pnpm_reference(reference: &str, fallback_name: &str) -> Option<String> {
    let reference = reference.trim();
    if reference.is_empty()
        || reference.starts_with("link:")
        || reference.starts_with("file:")
        || reference.starts_with("workspace:")
    {
        return None;
    }
    let base = reference.split('(').next().unwrap_or(reference).trim();
    if let Some((name, version)) = pnpm_package_key_parts(base)
        && name == fallback_name
    {
        return Some(version.to_string());
    }
    Some(base.to_string())
}

fn pnpm_package_key_parts(key: &str) -> Option<(&str, &str)> {
    let base = key.split('(').next().unwrap_or(key).trim();
    if base.is_empty() || base.starts_with("link:") || base.starts_with("file:") {
        return None;
    }
    if let Some(stripped) = base.strip_prefix('@') {
        let slash = stripped.find('/')?;
        let after_scope = 1 + slash + 1;
        let version_at = base[after_scope..].rfind('@')?;
        let split = after_scope + version_at;
        let (name, version) = base.split_at(split);
        return Some((name, version.trim_start_matches('@')));
    }
    let split = base.rfind('@')?;
    let (name, version) = base.split_at(split);
    Some((name, version.trim_start_matches('@')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_reads_scoped_and_unscoped_packages() {
        let parsed: serde_yaml::Value = serde_yaml::from_str(
            r#"
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
  '@scope/pkg@1.2.3':
    resolution:
      integrity: sha512-scope
  react-dom@19.0.0(react@19.0.0):
    resolution:
      integrity: sha512-dom
"#,
        )
        .unwrap();
        let deps = parse_all_from_value(&parsed).unwrap();
        let names = deps.iter().map(|dep| dep.name.as_str()).collect::<Vec<_>>();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"@scope/pkg"));
        assert!(names.contains(&"react-dom"));
    }
}
