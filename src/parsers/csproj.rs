use crate::Dependency;
use anyhow::{bail, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let csproj = find_csproj(project_dir)?;
    let content =
        std::fs::read_to_string(&csproj).context_msg(&csproj)?;

    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.contains("<PackageReference") {
            if let Some(name) = extract_include(line) {
                let version = extract_attr(line, "Version");
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: "dotnet".to_string(),
                });
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
        if let Some(ext) = path.extension() {
            if ext == "csproj" {
                return Ok(path);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn setup_dir(content: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-csproj-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("test.csproj"), content).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_self_closing_package_reference() {
        let dir = setup_dir(r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>
"#);
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Newtonsoft.Json");
        assert_eq!(deps[0].version, Some("13.0.1".to_string()));
        assert_eq!(deps[0].ecosystem, "dotnet");
        cleanup(&dir);
    }

    #[test]
    fn parse_multiple_package_references() {
        let dir = setup_dir(r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="3.0.0" />
    <PackageReference Include="xunit" Version="2.5.0" />
  </ItemGroup>
</Project>
"#);
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
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-csproj-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        let result = parse(&dir);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
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
        let dir = setup_dir(r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="SomePackage" />
  </ItemGroup>
</Project>
"#);
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "SomePackage");
        assert_eq!(deps[0].version, None);
        cleanup(&dir);
    }
}

trait ContextMsg {
    fn context_msg(self, path: &Path) -> Result<String>;
}

impl ContextMsg for std::io::Result<String> {
    fn context_msg(self, path: &Path) -> Result<String> {
        self.map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))
    }
}
