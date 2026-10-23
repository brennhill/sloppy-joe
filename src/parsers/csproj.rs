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
    let csproj = &std::fs::canonicalize(csproj)?;
    let content = super::read_file_limited(csproj, super::MAX_MANIFEST_BYTES)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", csproj.display(), e))?;
    let content = strip_xml_comments(&content);

    for ancestor in csproj.parent().into_iter().flat_map(Path::ancestors) {
        for name in [
            "Directory.Build.props",
            "Directory.Build.targets",
            "Directory.Packages.props",
        ] {
            if super::path_detected(&ancestor.join(name))? {
                bail!(
                    "Unsupported MSBuild Import '{}' in {}: implicit dependency imports are not trusted yet",
                    name,
                    csproj.display()
                );
            }
        }
        reject_global_json_msbuild_sdks(ancestor, csproj)?;
    }

    for tag in content.split('<').skip(1) {
        let name = tag
            .split(|c: char| c.is_whitespace() || matches!(c, '/' | '>'))
            .next()
            .unwrap_or_default();
        let local_name = name.rsplit(':').next().unwrap_or_default();
        if matches!(
            local_name,
            "Import" | "PackageDownload" | "DotNetCliToolReference"
        ) || (local_name == "PackageReference" && name != "PackageReference")
        {
            bail!(
                "Unsupported MSBuild {} in {}: dependency declarations cannot be verified",
                name,
                csproj.display()
            );
        }
        let attrs = tag.split('>').next().unwrap_or_default();
        let attrs = &attrs[name.len().min(attrs.len())..];
        if local_name == "Project"
            && let Some(sdks) = extract_attr(attrs, "Sdk")
        {
            for sdk in sdks.split(';').map(str::trim).filter(|sdk| !sdk.is_empty()) {
                let (sdk_name, version) = match sdk.split_once('/') {
                    Some((sdk_name, version)) => (sdk_name.trim(), Some(version)),
                    None => (sdk, None),
                };
                reject_unbundled_msbuild_sdk(sdk_name, version, csproj)?;
            }
        }
        if local_name == "Sdk" {
            if name != "Sdk" {
                bail!(
                    "Unsupported MSBuild {} in {}: SDK declarations cannot be verified",
                    name,
                    csproj.display()
                );
            }
            let sdk_name = extract_attr(attrs, "Name").unwrap_or_default();
            let version = extract_attr(attrs, "Version");
            reject_unbundled_msbuild_sdk(sdk_name.trim(), version.as_deref(), csproj)?;
        }
    }

    let mut deps = Vec::new();
    let mut search_start = 0usize;
    while let Some(open_idx) = find_package_reference_start(&content, search_start) {
        let (tag_end, self_closing) = find_tag_end(&content, open_idx)?;
        let tag_content = &content[open_idx + "<PackageReference".len()..tag_end];
        {
            let name = extract_attr(tag_content, "Include").ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported PackageReference in {}: expected an Include attribute",
                    csproj.display()
                )
            })?;
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

/// MSBuild project SDKs other than the ones bundled with the .NET SDK are
/// NuGet packages restored by the SDK resolver and imported into the build.
/// They never appear in packages.lock.json, so they cannot be verified and
/// must fail closed. A version on a bundled SDK name also routes resolution
/// through NuGet, so it fails closed too.
fn reject_unbundled_msbuild_sdk(name: &str, version: Option<&str>, csproj: &Path) -> Result<()> {
    let bundled = name == "Microsoft.NET.Sdk" || name.starts_with("Microsoft.NET.Sdk.");
    if bundled && version.is_none() {
        return Ok(());
    }
    bail!(
        "Unsupported MSBuild SDK '{}' in {}: only SDKs bundled with the .NET SDK (Microsoft.NET.Sdk*, without a version) can be trusted; NuGet-resolved project SDKs cannot be verified",
        crate::report::sanitize_for_terminal(name),
        csproj.display()
    )
}

/// `global.json` `msbuild-sdks` pins NuGet-resolved MSBuild SDKs for every
/// project below it.
fn reject_global_json_msbuild_sdks(dir: &Path, csproj: &Path) -> Result<()> {
    let global_json = dir.join("global.json");
    if !super::path_detected(&global_json)? {
        return Ok(());
    }
    let content = super::read_file_limited(&global_json, super::MAX_MANIFEST_BYTES)?;
    if content.to_ascii_lowercase().contains("msbuild-sdks") {
        bail!(
            "Unsupported global.json msbuild-sdks in {} (applies to {}): NuGet-resolved MSBuild SDKs cannot be verified",
            global_json.display(),
            csproj.display()
        );
    }
    Ok(())
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
    fn reject_unmodeled_package_declarations() {
        for declaration in [
            r#"<m:PackageReference Include="Payload" Version="1.0.0" />"#,
            r#"<PackageReference Update="Payload" Version="1.0.0" />"#,
            r#"<PackageDownload Include="Payload" Version="[1.0.0]" />"#,
        ] {
            let dir = setup_dir(&format!(
                r#"<Project xmlns:m="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>{declaration}</ItemGroup></Project>"#
            ));
            assert!(
                parse(&dir).is_err(),
                "unmodeled declaration must fail closed: {declaration}"
            );
            cleanup(&dir);
        }
    }

    #[test]
    fn reject_implicit_dependency_imports() {
        for imported in [
            "Directory.Build.props",
            "Directory.Build.targets",
            "Directory.Packages.props",
        ] {
            let dir = setup_dir("<Project />");
            std::fs::write(dir.join(imported), r#"<Project><ItemGroup><PackageReference Include="Payload" Version="1.0.0" /></ItemGroup></Project>"#).unwrap();
            let err = parse(&dir)
                .expect_err("automatically imported package references must not disappear");
            assert!(err.to_string().contains(imported));
            cleanup(&dir);
        }
    }

    #[test]
    fn reject_unmodeled_project_imports() {
        let dir = setup_dir(r#"<Project><Import Project="Dependencies.props" /></Project>"#);
        std::fs::write(dir.join("Dependencies.props"), r#"<Project><ItemGroup><PackageReference Include="Payload" Version="1.0.0" /></ItemGroup></Project>"#).unwrap();
        let err = parse(&dir).expect_err("imported package references must not disappear");
        assert!(err.to_string().contains("Import"));
        cleanup(&dir);
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

#[cfg(test)]
mod msbuild_sdk_tests {
    use super::*;
    use crate::parsers::test_utils::*;

    #[test]
    fn reject_third_party_msbuild_sdks_and_cli_tools() {
        for project in [
            r#"<Project Sdk="Evil.Sdk/1.0.0"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
            r#"<Project Sdk="Evil.Sdk"></Project>"#,
            r#"<Project Sdk="Microsoft.NET.Sdk;Evil.Sdk/1.0.0"></Project>"#,
            r#"<Project Sdk="Microsoft.NET.Sdk/99.0.0"></Project>"#,
            r#"<Project><Sdk Name="Evil.Sdk" Version="1.0.0" /></Project>"#,
            r#"<Project><Sdk Name="Microsoft.NET.Sdk" Version="1.0.0" /></Project>"#,
            r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><DotNetCliToolReference Include="Evil.Tool" Version="1.0.0" /></ItemGroup></Project>"#,
        ] {
            let dir = setup_test_dir("csproj", "app.csproj", project);
            let err = parse(&dir).expect_err(&format!("must fail closed: {project}"));
            assert!(err.to_string().contains("app.csproj"), "{err}");
            cleanup(&dir);
        }
    }

    #[test]
    fn accept_builtin_msbuild_sdks() {
        for project in [
            r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
            r#"<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
            r#"<Project><Sdk Name="Microsoft.NET.Sdk" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
        ] {
            let dir = setup_test_dir("csproj", "app.csproj", project);
            let deps = parse(&dir).unwrap_or_else(|err| panic!("{project}: {err}"));
            assert_eq!(deps.len(), 1);
            cleanup(&dir);
        }
    }

    #[test]
    fn reject_global_json_msbuild_sdks() {
        let root = empty_test_dir("csproj");
        std::fs::write(
            root.join("global.json"),
            r#"{"sdk":{"version":"8.0.100"},"msbuild-sdks":{"Evil.Sdk":"1.0.0"}}"#,
        )
        .unwrap();
        let project = root.join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("app.csproj"),
            r#"<Project Sdk="Microsoft.NET.Sdk"></Project>"#,
        )
        .unwrap();
        let err = parse(&project).expect_err("global.json msbuild-sdks must fail closed");
        assert!(err.to_string().contains("msbuild-sdks"), "{err}");

        // A global.json that only pins the .NET SDK is fine.
        std::fs::write(root.join("global.json"), r#"{"sdk":{"version":"8.0.100"}}"#).unwrap();
        assert!(parse(&project).unwrap().is_empty());
        cleanup(&root);
    }
}
