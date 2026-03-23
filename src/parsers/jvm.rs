use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let gradle = project_dir.join("build.gradle");
    if gradle.exists() {
        return parse_gradle(&gradle);
    }
    let gradle_kts = project_dir.join("build.gradle.kts");
    if gradle_kts.exists() {
        return parse_gradle(&gradle_kts);
    }
    let pom = project_dir.join("pom.xml");
    parse_pom(&pom)
}

fn parse_gradle(path: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read build.gradle")?;
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
                && let Some(dep) = extract_gradle_dep(line)
            {
                deps.push(dep);
            }
        }
    }
    Ok(deps)
}

fn extract_gradle_dep(line: &str) -> Option<Dependency> {
    let quote = line.find(['\'', '"'])?;
    let ch = line.as_bytes()[quote] as char;
    let rest = &line[quote + 1..];
    let end = rest.find(ch)?;
    let coord = &rest[..end];
    let parts: Vec<&str> = coord.splitn(3, ':').collect();
    if parts.len() >= 2 {
        let name = format!("{}:{}", parts[0], parts[1]);
        let version = parts.get(2).map(|v| v.to_string());
        return Some(Dependency {
            name,
            version,
            ecosystem: crate::Ecosystem::Jvm,
        });
    }
    None
}

fn parse_pom(path: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read pom.xml")?;
    let mut deps = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim().contains("<dependency>") {
            let (dep, end) = parse_pom_dep(&lines, i);
            if let Some(d) = dep {
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
        let dep = extract_gradle_dep("implementation 'com.example:lib'");
        assert!(dep.is_some());
        let dep = dep.unwrap();
        assert_eq!(dep.name, "com.example:lib");
        assert_eq!(dep.version, None);
    }

    #[test]
    fn parse_gradle_kts() {
        let dir = setup_test_dir("jvm", "build.gradle.kts", "implementation(\"com.google.guava:guava:31.1-jre\")");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
        cleanup(&dir);
    }
}
