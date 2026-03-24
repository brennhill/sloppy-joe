pub mod cargo_toml;
pub mod composer_json;
pub mod csproj;
pub mod gemfile;
pub mod go_mod;
pub mod jvm;
pub mod package_json;
pub mod requirements;

use crate::Dependency;
use anyhow::{Result, bail};
use std::path::Path;

/// Read a file with a size limit to prevent memory exhaustion on huge files.
pub(crate) fn read_file_limited(path: &std::path::Path, max_bytes: u64) -> Result<String> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max_bytes {
        anyhow::bail!(
            "File too large: {} bytes (max {})",
            meta.len(),
            max_bytes
        );
    }
    Ok(std::fs::read_to_string(path)?)
}

/// Maximum file size for manifest/lockfile parsing (100 MB).
pub(crate) const MAX_MANIFEST_BYTES: u64 = 100 * 1024 * 1024;

/// Shared XML value extractor: `<tag>value</tag>` on a single line.
/// Searches for the close tag starting AFTER the open tag to avoid
/// matching a close tag that appears before the open tag.
pub(crate) fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = line.find(&open)? + open.len();
    let end = line[start..].find(&close).map(|i| i + start)?;
    Some(line[start..end].to_string())
}

/// Auto-detect the project type and parse dependencies, or use the specified type.
pub fn parse_dependencies(
    project_dir: &Path,
    project_type: Option<&str>,
) -> Result<Vec<Dependency>> {
    match project_type {
        Some("npm") => package_json::parse(project_dir),
        Some("pypi") => requirements::parse(project_dir),
        Some("cargo") => cargo_toml::parse(project_dir),
        Some("go") => go_mod::parse(project_dir),
        Some("ruby") => gemfile::parse(project_dir),
        Some("php") => composer_json::parse(project_dir),
        Some("jvm") => jvm::parse(project_dir),
        Some("dotnet") => csproj::parse(project_dir),
        Some(other) => bail!("Unknown project type: {}", other),
        None => auto_detect(project_dir),
    }
}

/// Detect ALL ecosystems present in a project directory.
/// Returns one Vec<Dependency> per detected ecosystem.
/// Used by monorepo scanning to ensure no ecosystem is missed.
pub fn parse_all_ecosystems(project_dir: &Path) -> Vec<Vec<Dependency>> {
    type Parser = (&'static str, fn(&Path) -> Result<Vec<Dependency>>);
    let parsers: Vec<Parser> = vec![
        ("package.json", package_json::parse),
        ("requirements.txt", requirements::parse),
        ("Cargo.toml", cargo_toml::parse),
        ("go.mod", go_mod::parse),
        ("Gemfile", gemfile::parse),
        ("composer.json", composer_json::parse),
    ];

    let mut results = Vec::new();
    for (manifest, parser) in parsers {
        if project_dir.join(manifest).exists()
            && let Ok(deps) = parser(project_dir)
            && !deps.is_empty()
        {
            results.push(deps);
        }
    }

    // JVM and csproj need special detection
    let has_jvm = project_dir.join("build.gradle").exists()
        || project_dir.join("build.gradle.kts").exists()
        || project_dir.join("pom.xml").exists();
    if has_jvm
        && let Ok(deps) = jvm::parse(project_dir)
        && !deps.is_empty()
    {
        results.push(deps);
    }
    if has_csproj(project_dir)
        && let Ok(deps) = csproj::parse(project_dir)
        && !deps.is_empty()
    {
        results.push(deps);
    }

    results
}

fn auto_detect(project_dir: &Path) -> Result<Vec<Dependency>> {
    if project_dir.join("package.json").exists() {
        return package_json::parse(project_dir);
    }
    if project_dir.join("requirements.txt").exists() {
        return requirements::parse(project_dir);
    }
    if project_dir.join("Cargo.toml").exists() {
        return cargo_toml::parse(project_dir);
    }
    if project_dir.join("go.mod").exists() {
        return go_mod::parse(project_dir);
    }
    if project_dir.join("Gemfile").exists() {
        return gemfile::parse(project_dir);
    }
    if project_dir.join("composer.json").exists() {
        return composer_json::parse(project_dir);
    }
    if project_dir.join("build.gradle").exists()
        || project_dir.join("build.gradle.kts").exists()
        || project_dir.join("pom.xml").exists()
    {
        return jvm::parse(project_dir);
    }
    if has_csproj(project_dir) {
        return csproj::parse(project_dir);
    }
    bail!(
        "Could not detect project type. Use --type to specify one of: \
         npm, pypi, cargo, go, ruby, php, jvm, dotnet"
    );
}

fn has_csproj(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .any(|e| e.path().extension().is_some_and(|ext| ext == "csproj"))
        })
        .unwrap_or(false)
}

/// Shared test utilities for parser tests.
#[cfg(test)]
pub(crate) mod test_utils {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a unique temp directory and write a manifest file into it.
    pub fn setup_test_dir(prefix: &str, filename: &str, content: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-{}-{}-{}", prefix, std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(filename), content).unwrap();
        dir
    }

    /// Create a unique temp directory without writing any file.
    pub fn empty_test_dir(prefix: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-{}-{}-{}", prefix, std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Clean up a test directory.
    pub fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_utils::*;

    #[test]
    fn parse_dependencies_with_explicit_type() {
        let dir = empty_test_dir("parsers");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18"}}"#,
        )
        .unwrap();
        let deps = parse_dependencies(&dir, Some("npm")).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "react");
        cleanup(&dir);
    }

    #[test]
    fn parse_dependencies_unknown_type_errors() {
        let dir = empty_test_dir("parsers");
        let result = parse_dependencies(&dir, Some("unknown_type"));
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[test]
    fn auto_detect_package_json() {
        let dir = empty_test_dir("parsers");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"express": "^4"}}"#,
        )
        .unwrap();
        let deps = parse_dependencies(&dir, None).unwrap();
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Npm);
        cleanup(&dir);
    }

    #[test]
    fn auto_detect_requirements_txt() {
        let dir = empty_test_dir("parsers");
        std::fs::write(dir.join("requirements.txt"), "flask==2.0\n").unwrap();
        let deps = parse_dependencies(&dir, None).unwrap();
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::PyPI);
        cleanup(&dir);
    }

    #[test]
    fn auto_detect_cargo_toml() {
        let dir = empty_test_dir("parsers");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n\n[dependencies]\nserde = \"1\"",
        )
        .unwrap();
        let deps = parse_dependencies(&dir, None).unwrap();
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Cargo);
        cleanup(&dir);
    }

    #[test]
    fn auto_detect_go_mod() {
        let dir = empty_test_dir("parsers");
        std::fs::write(
            dir.join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9\n)\n",
        )
        .unwrap();
        let deps = parse_dependencies(&dir, None).unwrap();
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Go);
        cleanup(&dir);
    }

    #[test]
    fn auto_detect_gemfile() {
        let dir = empty_test_dir("parsers");
        std::fs::write(dir.join("Gemfile"), "gem 'rails'\n").unwrap();
        let deps = parse_dependencies(&dir, None).unwrap();
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Ruby);
        cleanup(&dir);
    }

    #[test]
    fn auto_detect_composer_json() {
        let dir = empty_test_dir("parsers");
        std::fs::write(
            dir.join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        let deps = parse_dependencies(&dir, None).unwrap();
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Php);
        cleanup(&dir);
    }

    #[test]
    fn auto_detect_no_project_files_errors() {
        let dir = empty_test_dir("parsers");
        let result = parse_dependencies(&dir, None);
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[test]
    fn auto_detect_build_gradle_kts() {
        let dir = empty_test_dir("parsers");
        std::fs::write(
            dir.join("build.gradle.kts"),
            "implementation(\"com.google.guava:guava:31.1-jre\")",
        )
        .unwrap();
        let deps = parse_dependencies(&dir, None).unwrap();
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Jvm);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        cleanup(&dir);
    }

    #[test]
    fn has_csproj_finds_file() {
        let dir = empty_test_dir("parsers");
        std::fs::write(dir.join("app.csproj"), "<Project></Project>").unwrap();
        assert!(has_csproj(&dir));
        cleanup(&dir);
    }

    #[test]
    fn has_csproj_no_file() {
        let dir = empty_test_dir("parsers");
        assert!(!has_csproj(&dir));
        cleanup(&dir);
    }

    // ── extract_xml_value tests ──

    #[test]
    fn extract_xml_value_basic() {
        assert_eq!(
            extract_xml_value("  <Version>1.2.3</Version>", "Version"),
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn extract_xml_value_handles_close_before_open() {
        // P0-3: "</Version><Version>1.2.3</Version>" should return Some("1.2.3"), not panic
        assert_eq!(
            extract_xml_value("</Version><Version>1.2.3</Version>", "Version"),
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn extract_xml_value_no_open_tag() {
        assert_eq!(extract_xml_value("just text", "Version"), None);
    }

    #[test]
    fn extract_xml_value_no_close_tag() {
        assert_eq!(
            extract_xml_value("<Version>1.2.3", "Version"),
            None
        );
    }

    // ── read_file_limited tests ──

    #[test]
    fn read_file_limited_rejects_oversized() {
        let dir = empty_test_dir("parsers");
        let path = dir.join("big.txt");
        std::fs::write(&path, "hello world").unwrap();
        // Set limit to 5 bytes - "hello world" is 11
        let result = read_file_limited(&path, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
        cleanup(&dir);
    }

    #[test]
    fn read_file_limited_allows_small() {
        let dir = empty_test_dir("parsers");
        let path = dir.join("small.txt");
        std::fs::write(&path, "ok").unwrap();
        let result = read_file_limited(&path, 100);
        assert_eq!(result.unwrap(), "ok");
        cleanup(&dir);
    }

    // ── parse_all_ecosystems tests ──

    #[test]
    fn parse_all_ecosystems_empty_dir() {
        let dir = empty_test_dir("parsers-all");
        let results = parse_all_ecosystems(&dir);
        assert!(results.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_single_npm() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18"}}"#,
        )
        .unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Npm);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_multiple_ecosystems() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18"}}"#,
        )
        .unwrap();
        std::fs::write(dir.join("requirements.txt"), "flask==2.0\n").unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 2);
        let ecosystems: Vec<crate::Ecosystem> = results.iter().map(|r| r[0].ecosystem).collect();
        assert!(ecosystems.contains(&crate::Ecosystem::Npm));
        assert!(ecosystems.contains(&crate::Ecosystem::PyPI));
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_detects_cargo() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n\n[dependencies]\nserde = \"1\"",
        )
        .unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Cargo);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_detects_go_mod() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9\n)\n",
        )
        .unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Go);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_detects_gemfile() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(dir.join("Gemfile"), "gem 'rails'\n").unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Ruby);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_detects_composer() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Php);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_detects_jvm_gradle() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("build.gradle"),
            "implementation 'com.google.guava:guava:31.1-jre'",
        )
        .unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Jvm);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_detects_jvm_gradle_kts() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("build.gradle.kts"),
            "implementation(\"com.google.guava:guava:31.1-jre\")",
        )
        .unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Jvm);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_detects_jvm_pom() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("pom.xml"),
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.google.guava</groupId>\n      <artifactId>guava</artifactId>\n      <version>31.1-jre</version>\n    </dependency>\n  </dependencies>\n</project>",
        )
        .unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Jvm);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_detects_csproj() {
        let dir = empty_test_dir("parsers-all");
        std::fs::write(
            dir.join("app.csproj"),
            r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
        )
        .unwrap();
        let results = parse_all_ecosystems(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Dotnet);
        cleanup(&dir);
    }

    #[test]
    fn parse_all_ecosystems_skips_empty_manifests() {
        let dir = empty_test_dir("parsers-all");
        // An empty package.json with no deps should not produce a result
        std::fs::write(dir.join("package.json"), r#"{}"#).unwrap();
        let results = parse_all_ecosystems(&dir);
        assert!(results.is_empty());
        cleanup(&dir);
    }
}
