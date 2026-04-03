use crate::Dependency;
use anyhow::{Context, Result, bail};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let gradle = project_dir.join("build.gradle");
    if super::path_detected(&gradle)? {
        return parse_gradle(&gradle);
    }
    let gradle_kts = project_dir.join("build.gradle.kts");
    if super::path_detected(&gradle_kts)? {
        return parse_gradle(&gradle_kts);
    }
    let pom = project_dir.join("pom.xml");
    parse_pom(&pom)
}

pub(crate) fn parse_manifest(path: &Path) -> Result<Vec<Dependency>> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("build.gradle") | Some("build.gradle.kts") => parse_gradle(path),
        Some("pom.xml") => parse_pom(path),
        _ => bail!("Unsupported JVM manifest: {}", path.display()),
    }
}

fn parse_gradle(path: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read build.gradle")?;
    validate_gradle_source_policy(&content, path)?;
    let mut deps = Vec::new();
    let configs = [
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
    ];

    for line in content.lines() {
        let line = line.trim();
        for cfg in &configs {
            if line.starts_with(cfg)
                && let Some(dep) = extract_gradle_dep(line, path)?
            {
                super::validate_dependency(&dep, path)?;
                deps.push(dep);
            }
        }
    }
    Ok(deps)
}

fn extract_gradle_dep(line: &str, source_path: &Path) -> Result<Option<Dependency>> {
    let Some(quote) = line.find(['\'', '"']) else {
        return Ok(None);
    };
    let ch = line.as_bytes()[quote] as char;
    let rest = &line[quote + 1..];
    let Some(end) = rest.find(ch) else {
        return Ok(None);
    };
    let coord = &rest[..end];
    let parts: Vec<&str> = coord.splitn(3, ':').collect();
    if coord.matches(':').count() > 2 {
        bail!(
            "Unsupported Gradle dependency notation '{}' in {}: classifier-bearing coordinates are not supported",
            crate::report::sanitize_for_terminal(coord),
            source_path.display()
        );
    }
    if parts.len() >= 2 {
        let name = format!("{}:{}", parts[0], parts[1]);
        let version = parts.get(2).map(|v| v.to_string());
        return Ok(Some(Dependency {
            name,
            version,
            ecosystem: crate::Ecosystem::Jvm,
            actual_name: None,
        }));
    }
    Ok(None)
}

fn parse_pom(path: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read pom.xml")?;
    validate_pom_source_policy(&content, path)?;
    let mut deps = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim().contains("<dependency>") {
            let (dep, end) = parse_pom_dep(&lines, i);
            if let Some(d) = dep {
                super::validate_dependency(&d, path)?;
                deps.push(d);
            }
            i = end;
        }
        i += 1;
    }
    Ok(deps)
}

fn parse_pom_dep(lines: &[&str], start: usize) -> (Option<Dependency>, usize) {
    let mut group = None;
    let mut artifact = None;
    let mut version = None;

    for (i, line) in lines.iter().enumerate().skip(start + 1) {
        let line = line.trim();
        if line.contains("</dependency>") {
            if let (Some(g), Some(a)) = (group, artifact) {
                let name = format!("{}:{}", g, a);
                return (
                    Some(Dependency {
                        name,
                        version,
                        ecosystem: crate::Ecosystem::Jvm,
                        actual_name: None,
                    }),
                    i,
                );
            }
            return (None, i);
        }
        if let Some(v) = extract_xml_value(line, "groupId") {
            group = Some(v);
        }
        if let Some(v) = extract_xml_value(line, "artifactId") {
            artifact = Some(v);
        }
        if let Some(v) = extract_xml_value(line, "version") {
            version = Some(v);
        }
    }
    (None, lines.len())
}

fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    super::extract_xml_value(line, tag)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GradleToken {
    Ident(String),
    Symbol(char),
}

fn tokenize_gradle(content: &str) -> Vec<GradleToken> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            c if c.is_whitespace() => i += 1,
            '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                i += 2;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(chars.len());
            }
            '"' | '\'' => {
                let quote = chars[i];
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if chars[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            '{' | '}' | '(' | ')' => {
                tokens.push(GradleToken::Symbol(chars[i]));
                i += 1;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                i += 1;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric()
                        || matches!(chars[i], '_' | '.' | '-' | ':'))
                {
                    i += 1;
                }
                tokens.push(GradleToken::Ident(chars[start..i].iter().collect()));
            }
            _ => i += 1,
        }
    }
    tokens
}

fn find_gradle_block_end(tokens: &[GradleToken], open_idx: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, token) in tokens.iter().enumerate().skip(open_idx) {
        match token {
            GradleToken::Symbol('{') => depth += 1,
            GradleToken::Symbol('}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn validate_gradle_repositories_block(tokens: &[GradleToken], path: &Path) -> Result<()> {
    for window in tokens.windows(2) {
        let [GradleToken::Ident(name), GradleToken::Symbol(next)] = window else {
            continue;
        };
        if !matches!(next, '{' | '(') {
            continue;
        }
        if matches!(
            name.as_str(),
            "maven" | "mavenLocal" | "flatDir" | "ivy" | "google" | "gradlePluginPortal"
        ) {
            bail!(
                "Unsupported Gradle repository in {}: only mavenCentral() is supported for trusted registry resolution",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_gradle_dependencies_block(tokens: &[GradleToken], path: &Path) -> Result<()> {
    let dependency_configs = [
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
    ];
    let local_sources = ["project", "files", "fileTree", "includeBuild"];

    for (idx, token) in tokens.iter().enumerate() {
        let GradleToken::Ident(config) = token else {
            continue;
        };
        if !dependency_configs.contains(&config.as_str()) {
            continue;
        }

        for lookahead in tokens.iter().skip(idx + 1).take(8) {
            if let GradleToken::Ident(source) = lookahead
                && local_sources.contains(&source.as_str())
            {
                bail!(
                    "Unsupported Gradle dependency source in {}: local project or file dependencies are not supported",
                    path.display()
                );
            }
        }
    }

    Ok(())
}

fn validate_gradle_source_policy(content: &str, path: &Path) -> Result<()> {
    let tokens = tokenize_gradle(content);
    let mut idx = 0usize;
    while idx < tokens.len() {
        match &tokens[idx] {
            GradleToken::Ident(name)
                if matches!(name.as_str(), "repositories" | "dependencies")
                    && matches!(tokens.get(idx + 1), Some(GradleToken::Symbol('{'))) =>
            {
                let end = find_gradle_block_end(&tokens, idx + 1).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken Gradle manifest '{}': unclosed '{}' block.",
                        path.display(),
                        name
                    )
                })?;
                let block = &tokens[idx + 2..end];
                if name == "repositories" {
                    validate_gradle_repositories_block(block, path)?;
                } else {
                    validate_gradle_dependencies_block(block, path)?;
                }
                idx = end;
            }
            _ => {}
        }
        idx += 1;
    }

    Ok(())
}

fn xml_contains_open_tag(content: &str, target: &str) -> bool {
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '<' {
            i += 1;
            continue;
        }
        i += 1;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        if matches!(chars[i], '/' | '!' | '?') {
            while i < chars.len() && chars[i] != '>' {
                i += 1;
            }
            i += 1;
            continue;
        }

        let start = i;
        while i < chars.len() && !chars[i].is_whitespace() && !matches!(chars[i], '>' | '/') {
            i += 1;
        }
        let name: String = chars[start..i].iter().collect();
        let local_name = name.rsplit(':').next().unwrap_or(name.as_str());
        if local_name == target {
            return true;
        }
    }
    false
}

fn validate_pom_source_policy(content: &str, path: &Path) -> Result<()> {
    if [
        "repositories",
        "pluginRepositories",
        "repository",
        "pluginRepository",
    ]
    .iter()
    .any(|tag| xml_contains_open_tag(content, tag))
    {
        bail!(
            "Unsupported Maven repository declaration in {}: custom repositories are not supported",
            path.display()
        );
    }

    if xml_contains_open_tag(content, "systemPath") {
        bail!(
            "Unsupported Maven dependency source in {}: systemPath dependencies are not supported",
            path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_gradle(content: &str) -> std::path::PathBuf {
        setup_test_dir("jvm", "build.gradle", content)
    }

    fn setup_pom(content: &str) -> std::path::PathBuf {
        setup_test_dir("jvm", "pom.xml", content)
    }

    #[test]
    fn parse_gradle_implementation() {
        let dir = setup_gradle("implementation 'com.google.guava:guava:31.1-jre'");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Jvm);
        cleanup(&dir);
    }

    #[test]
    fn parse_gradle_api_double_quotes() {
        let dir = setup_gradle("api \"org.slf4j:slf4j-api:2.0.0\"");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "org.slf4j:slf4j-api");
        cleanup(&dir);
    }

    #[test]
    fn parse_gradle_multiple_configs() {
        let dir = setup_gradle(
            "implementation 'com.google.guava:guava:31.1-jre'\ntestImplementation 'junit:junit:4.13'",
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        cleanup(&dir);
    }

    #[test]
    fn parse_pom_xml_dependency() {
        let dir = setup_pom(
            r#"
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn parse_pom_multiple_dependencies() {
        let dir = setup_pom(
            r#"
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
    </dependency>
  </dependencies>
</project>
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        cleanup(&dir);
    }

    #[test]
    fn gradle_takes_priority_over_pom() {
        let dir = setup_gradle("implementation 'a:b:1.0'");
        std::fs::write(
            dir.join("pom.xml"),
            "<project><dependencies><dependency><groupId>c</groupId><artifactId>d</artifactId></dependency></dependencies></project>",
        ).unwrap();
        let deps = parse(&dir).unwrap();
        // Should parse gradle, not pom
        assert_eq!(deps[0].name, "a:b");
        cleanup(&dir);
    }

    #[test]
    fn extract_gradle_dep_no_version() {
        let dep = extract_gradle_dep(
            "implementation 'com.example:lib'",
            Path::new("build.gradle"),
        );
        assert!(dep.is_ok());
        let dep = dep.unwrap().unwrap();
        assert_eq!(dep.name, "com.example:lib");
        assert_eq!(dep.version, None);
    }

    #[test]
    fn parse_gradle_kts() {
        let dir = setup_test_dir(
            "jvm",
            "build.gradle.kts",
            "implementation(\"com.google.guava:guava:31.1-jre\")",
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn reject_gradle_classifier_coordinates() {
        let dir = setup_gradle("implementation 'org.example:foo:1.2.3:tests'");
        let err = parse(&dir).expect_err("classifier-bearing Gradle coords must fail closed");
        assert!(err.to_string().contains("classifier-bearing coordinates"));
        cleanup(&dir);
    }

    #[test]
    fn reject_multiline_gradle_custom_repository_blocks() {
        let dir = setup_gradle(
            r#"
repositories
{
    mavenCentral()
    maven
    {
        url = uri("https://repo.example.com/maven")
    }
}
"#,
        );
        let err = parse(&dir).expect_err("custom Gradle repositories must fail closed");
        assert!(err.to_string().contains("Unsupported Gradle repository"));
        cleanup(&dir);
    }

    #[test]
    fn reject_multiline_gradle_local_project_dependencies() {
        let dir = setup_gradle(
            r#"
dependencies {
    implementation(
        project(":shared")
    )
}
"#,
        );
        let err = parse(&dir).expect_err("local Gradle project deps must fail closed");
        assert!(
            err.to_string()
                .contains("Unsupported Gradle dependency source")
        );
        cleanup(&dir);
    }

    #[test]
    fn reject_namespaced_maven_repository_tags() {
        let dir = setup_pom(
            r#"
<project xmlns:m="https://maven.apache.org/POM/4.0.0">
  <m:repositories>
    <m:repository>
      <m:id>internal</m:id>
      <m:url>https://repo.example.com/maven</m:url>
    </m:repository>
  </m:repositories>
</project>
"#,
        );
        let err = parse(&dir).expect_err("namespaced Maven repositories must fail closed");
        assert!(
            err.to_string()
                .contains("Unsupported Maven repository declaration")
        );
        cleanup(&dir);
    }

    #[test]
    fn reject_namespaced_maven_system_path_dependencies() {
        let dir = setup_pom(
            r#"
<project xmlns:m="https://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>local</artifactId>
      <version>1.0.0</version>
      <m:systemPath>/tmp/local.jar</m:systemPath>
    </dependency>
  </dependencies>
</project>
"#,
        );
        let err = parse(&dir).expect_err("namespaced Maven systemPath must fail closed");
        assert!(err.to_string().contains("systemPath"));
        cleanup(&dir);
    }
}
