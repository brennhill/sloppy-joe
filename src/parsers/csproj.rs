use crate::Dependency;
use anyhow::{Result, bail};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    for csproj in find_csproj_files(project_dir)? {
        deps.extend(parse_file(&csproj)?);
    }
    Ok(deps)
}

pub(crate) fn parse_file(csproj: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(csproj, super::MAX_MANIFEST_BYTES)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", csproj.display(), e))?;
    let content = strip_xml_comments(&content);

    let mut deps = Vec::new();
    let mut search_start = 0usize;
    while let Some(open_idx) = find_package_reference_start(&content, search_start) {
        let (tag_end, self_closing) = find_tag_end(&content, open_idx)?;
        let tag_content = &content[open_idx + "<PackageReference".len()..tag_end];
        if let Some(name) = extract_attr(tag_content, "Include") {
            let version = if self_closing {
                extract_attr(tag_content, "Version")
            } else {
                let close_idx = content[tag_end + 1..]
                    .find("</PackageReference>")
                    .map(|idx| tag_end + 1 + idx)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Unterminated <PackageReference> element in {}",
                            csproj.display()
                        )
                    })?;
                let body = &content[tag_end + 1..close_idx];
                extract_attr(tag_content, "Version").or_else(|| extract_xml_value(body, "Version"))
            };
            let dep = Dependency {
                name,
                version,
                ecosystem: crate::Ecosystem::Dotnet,
                actual_name: None,
            };
            super::validate_dependency(&dep, csproj)?;
            deps.push(dep);
        }
        search_start = tag_end + 1;
    }

    Ok(deps)
}

fn strip_xml_comments(content: &str) -> String {
    let mut sanitized = String::with_capacity(content.len());
    let mut index = 0usize;

    while let Some(start) = content[index..].find("<!--") {
        let start = index + start;
        sanitized.push_str(&content[index..start]);
        if let Some(end) = content[start + 4..].find("-->") {
            index = start + 4 + end + 3;
        } else {
            break;
        }
    }

    sanitized.push_str(&content[index..]);
    sanitized
}

fn find_package_reference_start(content: &str, start: usize) -> Option<usize> {
    let mut search = start;
    while let Some(found) = content[search..].find("<PackageReference") {
        let found = search + found;
        let boundary = content[found + "<PackageReference".len()..]
            .chars()
            .next()
            .is_none_or(|ch| ch.is_whitespace() || matches!(ch, '/' | '>'));
        if boundary {
            return Some(found);
        }
        search = found + "<PackageReference".len();
    }
    None
}

fn find_csproj_files(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "csproj"))
        .collect::<Vec<_>>();
    files.sort();
    if files.is_empty() {
        bail!("No .csproj file found in {}", dir.display());
    }
    Ok(files)
}

fn find_tag_end(content: &str, start: usize) -> Result<(usize, bool)> {
    let bytes = content.as_bytes();
    let mut index = start;
    let mut in_single = false;
    let mut in_double = false;

    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'>' if !in_single && !in_double => {
                let self_closing = content[start..index].trim_end().ends_with('/');
                return Ok((index, self_closing));
            }
            _ => {}
        }
        index += 1;
    }

    bail!("Unterminated XML tag")
}

fn extract_attr(tag_content: &str, attr: &str) -> Option<String> {
    let mut chars = tag_content.char_indices().peekable();

    while let Some((start, ch)) = chars.next() {
        if ch.is_whitespace() || ch == '/' {
            continue;
        }
        let name_start = start;
        let mut name_end = start + ch.len_utf8();
        while let Some(&(idx, next)) = chars.peek() {
            if next.is_whitespace() || matches!(next, '=' | '/' | '>') {
                break;
            }
            name_end = idx + next.len_utf8();
            chars.next();
        }
        let name = &tag_content[name_start..name_end];
        while let Some(&(_, next)) = chars.peek() {
            if !next.is_whitespace() {
                break;
            }
            chars.next();
        }
        if !matches!(chars.peek(), Some((_, '='))) {
            continue;
        }
        chars.next();
        while let Some(&(_, next)) = chars.peek() {
            if !next.is_whitespace() {
                break;
            }
            chars.next();
        }
        let (_, quote) = chars.next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let value_start = chars
            .peek()
            .map(|(idx, _)| *idx)
            .unwrap_or(tag_content.len());
        while let Some(&(idx, next)) = chars.peek() {
            if next == quote {
                let value = &tag_content[value_start..idx];
                if name == attr {
                    return Some(value.to_string());
                }
                chars.next();
                break;
            }
            chars.next();
        }
    }

    None
}

fn extract_xml_value(content: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = content.find(&open)? + open.len();
    let end = content[start..].find(&close)? + start;
    Some(content[start..end].trim().to_string())
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
    fn parse_all_csproj_files_in_directory() {
        let dir = setup_dir(
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>
"#,
        );
        std::fs::write(
            dir.join("second.csproj"),
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog" Version="3.0.0" />
  </ItemGroup>
</Project>
"#,
        )
        .unwrap();

        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|dep| dep.name == "Newtonsoft.Json"));
        assert!(deps.iter().any(|dep| dep.name == "Serilog"));
        cleanup(&dir);
    }

    #[test]
    fn extract_attr_works() {
        let tag = r#" Include="Foo" Version='1.0' /"#;
        assert_eq!(extract_attr(tag, "Include"), Some("Foo".to_string()));
        assert_eq!(extract_attr(tag, "Version"), Some("1.0".to_string()));
        assert_eq!(extract_attr(tag, "Missing"), None);
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

    #[test]
    fn parse_single_quoted_attributes() {
        let dir = setup_dir(
            r#"
<Project Sdk='Microsoft.NET.Sdk'>
  <ItemGroup>
    <PackageReference Include='Newtonsoft.Json' Version='13.0.1' />
  </ItemGroup>
</Project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Newtonsoft.Json");
        assert_eq!(deps[0].version, Some("13.0.1".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn parse_multiline_package_reference_attributes() {
        let dir = setup_dir(
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference
      Include="Newtonsoft.Json"
      Version="13.0.1" />
  </ItemGroup>
</Project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Newtonsoft.Json");
        assert_eq!(deps[0].version, Some("13.0.1".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn ignore_commented_package_references() {
        let dir = setup_dir(
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <!-- <PackageReference Include="Commented" Version="9.9.9" /> -->
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Newtonsoft.Json");
        cleanup(&dir);
    }
}
