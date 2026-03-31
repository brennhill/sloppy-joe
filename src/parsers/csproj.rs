use crate::Dependency;
use anyhow::{Result, bail};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let csproj = find_csproj(project_dir)?;
    let content = super::read_file_limited(&csproj, super::MAX_MANIFEST_BYTES)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", csproj.display(), e))?;

    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.contains("<PackageReference") {
            if let Some(name) = extract_include(line) {
                let version = extract_attr(line, "Version");
                if line.contains("/>") || version.is_some() {
                    let dep = Dependency {
                        name,
                        version,
                        ecosystem: crate::Ecosystem::Dotnet,
                    };
                    super::validate_dependency(&dep, &csproj)?;
                    deps.push(dep);
                } else {
                    current_name = Some(name);
                    current_version = None;
                }
            }
            continue;
        }

        if current_name.is_some() {
            if let Some(version) = extract_xml_value(line, "Version") {
                current_version = Some(version);
            }
            if line.contains("</PackageReference>") {
                let dep = Dependency {
                    name: current_name.take().unwrap(),
                    version: current_version.take(),
                    ecosystem: crate::Ecosystem::Dotnet,
                };
                super::validate_dependency(&dep, &csproj)?;
                deps.push(dep);
            }
        }
    }

    Ok(deps)
}

fn find_csproj(dir: &Path) -> Result<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if let Some(ext) = path.extension()
            && ext == "csproj"
        {
            return Ok(path);
        }
    }
    bail!("No .csproj file found in {}", dir.display())
}

fn extract_include(line: &str) -> Option<String> {
    extract_attr(line, "Include")
}

fn extract_attr(line: &str, attr: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr);
    let start = line.find(&pattern)? + pattern.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    super::extract_xml_value(line, tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_dir(content: &str) -> std::path::PathBuf {
        setup_test_dir("csproj", "test.csproj", content)
    }

    #[test]
    fn parse_self_closing_package_reference() {
        let dir = setup_dir(
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Newtonsoft.Json");
        assert_eq!(deps[0].version, Some("13.0.1".to_string()));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Dotnet);
        cleanup(&dir);
    }

    #[test]
    fn parse_multiple_package_references() {
        let dir = setup_dir(
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="3.0.0" />
    <PackageReference Include="xunit" Version="2.5.0" />
  </ItemGroup>
</Project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 3);
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Newtonsoft.Json"));
        assert!(names.contains(&"Serilog"));
        assert!(names.contains(&"xunit"));
        cleanup(&dir);
    }

    #[test]
    fn handle_no_csproj_file() {
        let dir = empty_test_dir("csproj");
        let result = parse(&dir);
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[test]
    fn extract_attr_works() {
        let line = r#"<PackageReference Include="Foo" Version="1.0" />"#;
        assert_eq!(extract_attr(line, "Include"), Some("Foo".to_string()));
        assert_eq!(extract_attr(line, "Version"), Some("1.0".to_string()));
        assert_eq!(extract_attr(line, "Missing"), None);
    }

    #[test]
    fn parse_package_reference_without_version() {
        let dir = setup_dir(
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="SomePackage" />
  </ItemGroup>
</Project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "SomePackage");
        assert_eq!(deps[0].version, None);
        cleanup(&dir);
    }

    #[test]
    fn parse_nested_version_element() {
        let dir = setup_dir(
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="SomePackage">
      <Version>1.2.3</Version>
    </PackageReference>
  </ItemGroup>
</Project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "SomePackage");
        assert_eq!(deps[0].version, Some("1.2.3".to_string()));
        cleanup(&dir);
    }
}
