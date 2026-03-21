use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let gradle = project_dir.join("build.gradle");
    if gradle.exists() {
        return parse_gradle(&gradle);
    }
    let pom = project_dir.join("pom.xml");
    parse_pom(&pom)
}

fn parse_gradle(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path).context("Failed to read build.gradle")?;
    let mut deps = Vec::new();
    let configs = [
        "implementation", "api", "compileOnly", "runtimeOnly", "testImplementation",
    ];

    for line in content.lines() {
        let line = line.trim();
        for cfg in &configs {
            if line.starts_with(cfg) {
                if let Some(dep) = extract_gradle_dep(line) {
                    deps.push(dep);
                }
            }
        }
    }
    Ok(deps)
}

fn extract_gradle_dep(line: &str) -> Option<Dependency> {
    let quote = line.find(|c| c == '\'' || c == '"')?;
    let ch = line.as_bytes()[quote] as char;
    let rest = &line[quote + 1..];
    let end = rest.find(ch)?;
    let coord = &rest[..end];
    let parts: Vec<&str> = coord.splitn(3, ':').collect();
    if parts.len() >= 2 {
        let name = format!("{}:{}", parts[0], parts[1]);
        let version = parts.get(2).map(|v| v.to_string());
        return Some(Dependency { name, version, ecosystem: "jvm".to_string() });
    }
    None
}

fn parse_pom(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path).context("Failed to read pom.xml")?;
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

    for i in (start + 1)..lines.len() {
        let line = lines[i].trim();
        if line.contains("</dependency>") {
            if let (Some(g), Some(a)) = (group, artifact) {
                let name = format!("{}:{}", g, a);
                return (Some(Dependency { name, version, ecosystem: "jvm".to_string() }), i);
            }
            return (None, i);
        }
        if let Some(v) = extract_xml_value(line, "groupId") { group = Some(v); }
        if let Some(v) = extract_xml_value(line, "artifactId") { artifact = Some(v); }
        if let Some(v) = extract_xml_value(line, "version") { version = Some(v); }
    }
    (None, lines.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn setup_gradle(content: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-jvm-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("build.gradle"), content).unwrap();
        dir
    }

    fn setup_pom(content: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-jvm-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pom.xml"), content).unwrap();
        dir
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_gradle_implementation() {
        let dir = setup_gradle("implementation 'com.google.guava:guava:31.1-jre'");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
        assert_eq!(deps[0].ecosystem, "jvm");
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
        let dir = setup_pom(r#"
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>
"#);
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn parse_pom_multiple_dependencies() {
        let dir = setup_pom(r#"
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
"#);
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        cleanup(&dir);
    }

    #[test]
    fn gradle_takes_priority_over_pom() {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-jvm-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("build.gradle"), "implementation 'a:b:1.0'").unwrap();
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
}

fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = line.find(&open)? + open.len();
    let end = line.find(&close)?;
    Some(line[start..end].to_string())
}
