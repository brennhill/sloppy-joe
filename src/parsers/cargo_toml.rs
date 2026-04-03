use crate::Dependency;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoSourceSpec {
    CratesIo,
    Workspace,
    Path(String),
    RegistryAlias(String),
    RegistryIndex(String),
    Git {
        url: String,
        rev: Option<String>,
        branch: Option<String>,
        tag: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDependencySpec {
    pub manifest_name: String,
    pub package_name: String,
    pub version: Option<String>,
    pub source: CargoSourceSpec,
    pub workspace_member_invalid_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoRewriteSpec {
    pub package_name: String,
    pub patch_scope: Option<CargoPatchScope>,
    pub replace_source: Option<String>,
    pub replace_version: Option<String>,
    pub dependency: CargoDependencySpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoPatchScope {
    CratesIo,
    RegistryName(String),
    SourceUrl(String),
}

#[derive(Debug, Clone)]
pub struct CargoManifest {
    pub manifest_path: PathBuf,
    pub has_workspace: bool,
    pub workspace_members: Vec<String>,
    pub workspace_exclude: Vec<String>,
    pub dependencies: Vec<CargoDependencySpec>,
    pub workspace_dependencies: HashMap<String, CargoDependencySpec>,
    pub patches: Vec<CargoRewriteSpec>,
    pub replaces: Vec<CargoRewriteSpec>,
}

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let manifest = parse_manifest_file(&project_dir.join("Cargo.toml"))?;
    let mut deps = Vec::new();
    for spec in manifest.dependencies {
        let dep = Dependency {
            name: spec.package_name,
            version: spec.version,
            ecosystem: crate::Ecosystem::Cargo,
            actual_name: None,
        };
        super::validate_dependency(&dep, &manifest.manifest_path)?;
        deps.push(dep);
    }
    Ok(deps)
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn parse_manifest(project_dir: &Path) -> Result<CargoManifest> {
    parse_manifest_file(&project_dir.join("Cargo.toml"))
}

pub(crate) fn parse_manifest_file(path: &Path) -> Result<CargoManifest> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read Cargo.toml")?;
    let parsed: toml::Value = toml::from_str(&content).context("Failed to parse Cargo.toml")?;
    parse_manifest_value(path, &parsed)
}

pub(crate) fn parse_manifest_value(path: &Path, parsed: &toml::Value) -> Result<CargoManifest> {
    Ok(CargoManifest {
        manifest_path: path.to_path_buf(),
        has_workspace: parsed.get("workspace").and_then(|v| v.as_table()).is_some(),
        workspace_members: collect_workspace_patterns(parsed, "members"),
        workspace_exclude: collect_workspace_patterns(parsed, "exclude"),
        dependencies: collect_dependency_specs(path, parsed)?,
        workspace_dependencies: collect_workspace_dependencies(path, parsed)?,
        patches: collect_rewrites(path, parsed, "patch")?,
        replaces: collect_rewrites(path, parsed, "replace")?,
    })
}

fn collect_dependency_specs(path: &Path, parsed: &toml::Value) -> Result<Vec<CargoDependencySpec>> {
    let mut specs = Vec::new();
    let mut error = None;
    collect_dependency_tables(parsed, &mut |table| {
        if error.is_some() {
            return;
        }
        for (name, value) in table {
            match parse_dependency_spec(path, name, value) {
                Ok(spec) => specs.push(spec),
                Err(err) => {
                    error = Some(err);
                    break;
                }
            }
        }
    });
    if let Some(err) = error {
        Err(err)
    } else {
        Ok(specs)
    }
}

fn collect_workspace_dependencies(
    path: &Path,
    parsed: &toml::Value,
) -> Result<HashMap<String, CargoDependencySpec>> {
    let mut deps = HashMap::new();
    let Some(table) = parsed
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(|v| v.as_table())
    else {
        return Ok(deps);
    };

    for (name, value) in table {
        let spec = parse_dependency_spec(path, name, value)?;
        deps.insert(spec.package_name.clone(), spec);
    }
    Ok(deps)
}

fn collect_workspace_patterns(parsed: &toml::Value, key: &str) -> Vec<String> {
    parsed
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|workspace| workspace.get(key))
        .and_then(|v| v.as_array())
        .into_iter()
        .flat_map(|entries| entries.iter())
        .filter_map(|entry| entry.as_str().map(str::to_string))
        .collect()
}

pub(crate) fn collect_rewrites(
    path: &Path,
    parsed: &toml::Value,
    section: &str,
) -> Result<Vec<CargoRewriteSpec>> {
    let Some(roots) = parsed.get(section).and_then(|v| v.as_table()) else {
        return Ok(Vec::new());
    };
    let mut rewrites = Vec::new();
    if section == "replace" {
        for (name, value) in roots {
            let (package_name, replace_version, replace_source) = parse_replace_key(name);
            let mut dependency = parse_dependency_spec(path, name, value)?;
            if dependency.package_name == name.as_str() {
                dependency.package_name = package_name.clone();
            }
            rewrites.push(CargoRewriteSpec {
                package_name,
                patch_scope: None,
                replace_source,
                replace_version,
                dependency,
            });
        }
        return Ok(rewrites);
    }

    for (scope_name, source_value) in roots {
        let Some(source_table) = source_value.as_table() else {
            continue;
        };
        let patch_scope = if section == "patch" {
            Some(parse_patch_scope(scope_name))
        } else {
            None
        };
        for (name, value) in source_table {
            let dependency = parse_dependency_spec(path, name, value)?;
            rewrites.push(CargoRewriteSpec {
                package_name: dependency.package_name.clone(),
                patch_scope: patch_scope.clone(),
                replace_source: None,
                replace_version: None,
                dependency,
            });
        }
    }
    Ok(rewrites)
}

fn parse_replace_key(name: &str) -> (String, Option<String>, Option<String>) {
    if let Some((source, package_id)) = name.rsplit_once('#') {
        let (package_name, replace_version, _) = parse_replace_key(package_id);
        return (package_name, replace_version, Some(source.to_string()));
    }
    if let Some((package, version)) = name.split_once(':') {
        return (package.to_string(), Some(version.to_string()), None);
    }
    if let Some((package, version)) = name.rsplit_once('@') {
        return (package.to_string(), Some(version.to_string()), None);
    }
    (name.to_string(), None, None)
}

fn parse_patch_scope(scope: &str) -> CargoPatchScope {
    if scope == "crates-io" {
        CargoPatchScope::CratesIo
    } else if scope.contains("://") {
        CargoPatchScope::SourceUrl(scope.to_string())
    } else {
        CargoPatchScope::RegistryName(scope.to_string())
    }
}

fn collect_dependency_tables(
    parsed: &toml::Value,
    visitor: &mut impl FnMut(&toml::map::Map<String, toml::Value>),
) {
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = parsed.get(key).and_then(|v| v.as_table()) {
            visitor(table);
        }
    }

    let Some(targets) = parsed.get("target").and_then(|v| v.as_table()) else {
        return;
    };
    for target in targets.values().filter_map(|v| v.as_table()) {
        for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(table) = target.get(key).and_then(|v| v.as_table()) {
                visitor(table);
            }
        }
    }
}

fn parse_dependency_spec(
    path: &Path,
    name: &str,
    value: &toml::Value,
) -> Result<CargoDependencySpec> {
    match value {
        toml::Value::String(version) => Ok(CargoDependencySpec {
            manifest_name: name.to_string(),
            package_name: name.to_string(),
            version: Some(version.clone()),
            source: CargoSourceSpec::CratesIo,
            workspace_member_invalid_keys: Vec::new(),
        }),
        toml::Value::Table(table) => {
            let workspace = parse_bool_field(path, name, table, "workspace")?.unwrap_or(false);
            let package_name = parse_string_field(path, name, table, "package")?
                .unwrap_or_else(|| name.to_string());
            let version = parse_string_field(path, name, table, "version")?;
            let path_source = parse_string_field(path, name, table, "path")?;
            let registry_alias = parse_string_field(path, name, table, "registry")?;
            let registry_index = parse_string_field(path, name, table, "registry-index")?;
            let git = parse_string_field(path, name, table, "git")?;
            let rev = parse_string_field(path, name, table, "rev")?;
            let branch = parse_string_field(path, name, table, "branch")?;
            let tag = parse_string_field(path, name, table, "tag")?;

            let mut source_kinds = Vec::new();
            if workspace {
                source_kinds.push("workspace");
            }
            if path_source.is_some() {
                source_kinds.push("path");
            }
            if registry_alias.is_some() {
                source_kinds.push("registry");
            }
            if registry_index.is_some() {
                source_kinds.push("registry-index");
            }
            if git.is_some() {
                source_kinds.push("git");
            }
            if source_kinds.len() > 1 {
                anyhow::bail!(
                    "Broken manifest '{}': dependency '{}' declared multiple Cargo source selectors ({}). sloppy-joe refuses ambiguous dependency provenance.",
                    path.display(),
                    name,
                    source_kinds.join(", ")
                );
            }

            let source = if workspace {
                CargoSourceSpec::Workspace
            } else if let Some(path) = path_source {
                CargoSourceSpec::Path(path)
            } else if let Some(name) = registry_alias {
                CargoSourceSpec::RegistryAlias(name)
            } else if let Some(source) = registry_index {
                CargoSourceSpec::RegistryIndex(normalize_registry_index_source(&source))
            } else if let Some(url) = git {
                CargoSourceSpec::Git {
                    url,
                    rev,
                    branch,
                    tag,
                }
            } else {
                CargoSourceSpec::CratesIo
            };

            let invalid_workspace_keys = if workspace {
                table
                    .keys()
                    .filter(|key| {
                        !matches!(
                            key.as_str(),
                            "workspace" | "package" | "features" | "default-features" | "optional"
                        )
                    })
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };

            Ok(CargoDependencySpec {
                manifest_name: name.to_string(),
                package_name,
                version,
                source,
                workspace_member_invalid_keys: invalid_workspace_keys,
            })
        }
        other => anyhow::bail!(
            "Broken manifest '{}': dependency '{}' has unsupported dependency value '{}'. Expected a version string or a dependency table.",
            path.display(),
            name,
            toml_type_name(other)
        ),
    }
}

fn parse_string_field(
    path: &Path,
    dependency_name: &str,
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
) -> Result<Option<String>> {
    match table.get(field) {
        None => Ok(None),
        Some(toml::Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => anyhow::bail!(
            "Broken manifest '{}': dependency '{}' field '{}' must be a string, not '{}'.",
            path.display(),
            dependency_name,
            field,
            toml_type_name(other)
        ),
    }
}

fn parse_bool_field(
    path: &Path,
    dependency_name: &str,
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
) -> Result<Option<bool>> {
    match table.get(field) {
        None => Ok(None),
        Some(toml::Value::Boolean(value)) => Ok(Some(*value)),
        Some(other) => anyhow::bail!(
            "Broken manifest '{}': dependency '{}' field '{}' must be a boolean, not '{}'.",
            path.display(),
            dependency_name,
            field,
            toml_type_name(other)
        ),
    }
}

fn toml_type_name(value: &toml::Value) -> &'static str {
    match value {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "integer",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "boolean",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

fn normalize_registry_index_source(source: &str) -> String {
    let trimmed = source.trim();
    if trimmed.starts_with("registry+") || trimmed.starts_with("sparse+") {
        trimmed.to_string()
    } else {
        format!("registry+{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_dir(content: &str) -> std::path::PathBuf {
        setup_test_dir("cargo", "Cargo.toml", content)
    }

    #[test]
    fn parse_string_style_deps() {
        let dir = setup_dir(
            r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
anyhow = "1"
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"anyhow"));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Cargo);
        cleanup(&dir);
    }

    #[test]
    fn parse_table_style_deps() {
        let dir = setup_dir(
            r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, Some("1.0".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn parse_accepts_source_bearing_dependency_tables() {
        let dir = setup_dir(
            r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
workspace_dep = { workspace = true }
path_dep = { path = "../util" }
registry_dep = { registry = "company", version = "=1.2.3" }
git_dep = { git = "https://github.com/example/repo", rev = "0123456789abcdef0123456789abcdef01234567" }
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 4);
        cleanup(&dir);
    }

    #[test]
    fn parse_manifest_captures_workspace_and_rewrites() {
        let dir = setup_dir(
            r#"
[workspace]
members = ["app"]

[workspace.dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "../patched-serde" }
"#,
        );
        let manifest = parse_manifest(&dir).unwrap();
        assert!(manifest.has_workspace);
        assert!(manifest.workspace_dependencies.contains_key("serde"));
        assert_eq!(manifest.patches.len(), 1);
        cleanup(&dir);
    }

    #[test]
    fn parse_manifest_captures_replace_package_id_specs() {
        let dir = setup_dir(
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[replace]
"serde:1.0.228" = { path = "patched-serde" }
"#,
        );
        let manifest = parse_manifest(&dir).unwrap();
        assert_eq!(manifest.replaces.len(), 1);
        assert_eq!(manifest.replaces[0].package_name, "serde");
        assert_eq!(
            manifest.replaces[0].replace_version.as_deref(),
            Some("1.0.228")
        );
        assert_eq!(
            manifest.replaces[0].dependency.source,
            CargoSourceSpec::Path("patched-serde".to_string())
        );
        cleanup(&dir);
    }

    #[test]
    fn parse_manifest_captures_replace_package_id_sources() {
        let dir = setup_dir(
            r#"
[package]
name = "app"
version = "0.1.0"

[replace]
"registry+https://cargo.company.example/index#serde@1.0.228" = { path = "patched-serde" }
"#,
        );
        let manifest = parse_manifest(&dir).unwrap();
        assert_eq!(manifest.replaces.len(), 1);
        assert_eq!(manifest.replaces[0].package_name, "serde");
        assert_eq!(
            manifest.replaces[0].replace_source.as_deref(),
            Some("registry+https://cargo.company.example/index")
        );
        assert_eq!(
            manifest.replaces[0].replace_version.as_deref(),
            Some("1.0.228")
        );
        cleanup(&dir);
    }

    #[test]
    fn parse_manifest_captures_git_replace_package_id_sources() {
        let dir = setup_dir(
            r#"
[package]
name = "app"
version = "0.1.0"

[replace]
"git+https://github.com/yourorg/shared-crate?rev=0123456789abcdef0123456789abcdef01234567#0123456789abcdef0123456789abcdef01234567#shared@0.1.0" = { path = "patched-shared" }
"#,
        );
        let manifest = parse_manifest(&dir).unwrap();
        assert_eq!(manifest.replaces.len(), 1);
        assert_eq!(manifest.replaces[0].package_name, "shared");
        assert_eq!(
            manifest.replaces[0].replace_source.as_deref(),
            Some(
                "git+https://github.com/yourorg/shared-crate?rev=0123456789abcdef0123456789abcdef01234567#0123456789abcdef0123456789abcdef01234567"
            )
        );
        assert_eq!(
            manifest.replaces[0].replace_version.as_deref(),
            Some("0.1.0")
        );
        cleanup(&dir);
    }

    #[test]
    fn parse_rejects_invalid_dependency_value_type() {
        let dir = setup_dir(
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = []
"#,
        );
        let err = parse_manifest(&dir)
            .expect_err("invalid Cargo dependency value types must fail closed");
        assert!(err.to_string().contains("unsupported dependency value"));
        cleanup(&dir);
    }
}
