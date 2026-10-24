use super::test_utils::*;
use super::*;

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
fn auto_detect_prefers_requirements_txt_over_alternates() {
    let dir = empty_test_dir("parsers");
    std::fs::write(dir.join("requirements.txt"), "flask==2.0\n").unwrap();
    std::fs::write(dir.join("requirements-dev.txt"), "pytest==8.1.1\n").unwrap();

    let deps = parse_dependencies(&dir, None).unwrap();
    assert_eq!(deps[0].name, "flask");
    cleanup(&dir);
}

#[test]
fn auto_detect_errors_on_ambiguous_requirements_without_primary() {
    let dir = empty_test_dir("parsers");
    std::fs::write(dir.join("requirements-dev.txt"), "pytest==8.1.1\n").unwrap();
    std::fs::write(dir.join("requirements-prod.txt"), "flask==2.0\n").unwrap();

    let err = parse_dependencies(&dir, None)
        .expect_err("multiple alternate requirements files without requirements.txt must fail");
    assert!(
        err.to_string()
            .contains("Ambiguous Python requirements manifests")
    );
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
    assert!(first_csproj(&dir).unwrap().is_some());
    cleanup(&dir);
}

#[test]
fn has_csproj_no_file() {
    let dir = empty_test_dir("parsers");
    assert!(first_csproj(&dir).unwrap().is_none());
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
    assert_eq!(extract_xml_value("<Version>1.2.3", "Version"), None);
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

#[cfg(unix)]
#[test]
fn read_file_limited_rejects_symlinked_file() {
    let dir = empty_test_dir("parsers");
    let real = dir.join("real.txt");
    let link = dir.join("link.txt");
    std::fs::write(&real, "ok").unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let result = read_file_limited(&link, 100);
    let err = result.expect_err("symlinked manifests should be rejected");
    assert!(err.to_string().contains("symlink"));

    cleanup(&dir);
}

#[test]
fn read_file_limited_rejects_non_regular_file() {
    let dir = empty_test_dir("parsers");
    let result = read_file_limited(&dir, 100);
    let err = result.expect_err("non-regular files should be rejected");
    assert!(err.to_string().contains("regular file"));
    cleanup(&dir);
}

// ── parse_all_ecosystems tests ──

#[test]
fn parse_all_ecosystems_empty_dir() {
    let dir = empty_test_dir("parsers-all");
    let results = parse_all_ecosystems(&dir).unwrap();
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
    let results = parse_all_ecosystems(&dir).unwrap();
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
    let results = parse_all_ecosystems(&dir).unwrap();
    assert_eq!(results.len(), 2);
    let ecosystems: Vec<crate::Ecosystem> = results.iter().map(|r| r[0].ecosystem).collect();
    assert!(ecosystems.contains(&crate::Ecosystem::Npm));
    assert!(ecosystems.contains(&crate::Ecosystem::PyPI));
    cleanup(&dir);
}

#[test]
fn parse_all_ecosystems_detects_projects_inside_common_directory_names() {
    let dir = empty_test_dir("parsers-all-common-dir");
    std::fs::create_dir_all(dir.join("fixtures/demo")).unwrap();
    std::fs::write(
        dir.join("fixtures/demo/package.json"),
        r#"{"dependencies": {"react": "^18"}}"#,
    )
    .unwrap();

    let results = parse_all_ecosystems(&dir).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Npm);
    cleanup(&dir);
}

#[cfg(unix)]
#[test]
fn parse_all_ecosystems_follows_symlink_into_internal_directory() {
    use std::os::unix::fs::symlink;

    let dir = empty_test_dir("parsers-all-symlink");
    std::fs::create_dir_all(dir.join("vendor/demo")).unwrap();
    std::fs::write(
        dir.join("vendor/demo/package.json"),
        r#"{"dependencies": {"react": "^18"}}"#,
    )
    .unwrap();
    symlink(dir.join("vendor"), dir.join("alias")).unwrap();

    let results = parse_all_ecosystems(&dir).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Npm);
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
    let results = parse_all_ecosystems(&dir).unwrap();
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
    let results = parse_all_ecosystems(&dir).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Go);
    cleanup(&dir);
}

#[test]
fn parse_all_ecosystems_detects_gemfile() {
    let dir = empty_test_dir("parsers-all");
    std::fs::write(dir.join("Gemfile"), "gem 'rails'\n").unwrap();
    let results = parse_all_ecosystems(&dir).unwrap();
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
    let results = parse_all_ecosystems(&dir).unwrap();
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
    let results = parse_all_ecosystems(&dir).unwrap();
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
    let results = parse_all_ecosystems(&dir).unwrap();
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
    let results = parse_all_ecosystems(&dir).unwrap();
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
    let results = parse_all_ecosystems(&dir).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0][0].ecosystem, crate::Ecosystem::Dotnet);
    cleanup(&dir);
}

#[test]
fn parse_all_ecosystems_skips_empty_manifests() {
    let dir = empty_test_dir("parsers-all");
    // An empty package.json with no deps should not produce a result
    std::fs::write(dir.join("package.json"), r#"{}"#).unwrap();
    let results = parse_all_ecosystems(&dir).unwrap();
    assert!(results.is_empty());
    cleanup(&dir);
}

#[test]
fn parse_all_ecosystems_recurses_into_nested_projects() {
    let dir = empty_test_dir("parsers-all");
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("services/api")).unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"dependencies": {"react": "^18"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("services/api/requirements.txt"), "flask==2.0\n").unwrap();

    let results = parse_all_ecosystems(&dir).unwrap();

    assert_eq!(results.len(), 2);
    let ecosystems: Vec<crate::Ecosystem> = results.iter().map(|r| r[0].ecosystem).collect();
    assert!(ecosystems.contains(&crate::Ecosystem::Npm));
    assert!(ecosystems.contains(&crate::Ecosystem::PyPI));
    cleanup(&dir);
}

fn setup_csproj(content: &str) -> std::path::PathBuf {
    setup_test_dir("csproj-hardening", "test.csproj", content)
}

#[test]
fn dependencies_the_parser_could_miss_block() {
    let project = |body: &str| {
        format!(r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>{body}</ItemGroup></Project>"#)
    };
    for body in [
        r#"<packagereference Include="Evil.Pkg" Version="1.0.0" />"#,
        r#"<PACKAGEREFERENCE Include="Evil.Pkg" Version="1.0.0" />"#,
    ] {
        let dir = setup_csproj(&project(body));
        assert!(crate::parsers::csproj::parse(&dir).is_err(), "{body}");
        cleanup(&dir);
    }
    for property in [
        "<RestorePackagesWithLockFile>false</RestorePackagesWithLockFile>",
        "<NuGetLockFilePath>locks/other.json</NuGetLockFilePath>",
    ] {
        let dir = setup_csproj(&format!(
            r#"<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>{property}</PropertyGroup></Project>"#
        ));
        assert!(crate::parsers::csproj::parse(&dir).is_err(), "{property}");
        cleanup(&dir);
    }
    let dir = setup_csproj(
        r#"<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup></Project>"#,
    );
    assert!(crate::parsers::csproj::parse(&dir).is_ok());
    cleanup(&dir);
}

#[test]
fn a_csproj_user_file_blocks() {
    let dir = setup_csproj(r#"<Project Sdk="Microsoft.NET.Sdk"></Project>"#);
    let manifest = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .next()
        .unwrap();
    let mut user = manifest.clone().into_os_string();
    user.push(".user");
    std::fs::write(
        &user,
        r#"<Project><ItemGroup><PackageReference Include="X" Version="1"/></ItemGroup></Project>"#,
    )
    .unwrap();
    assert!(crate::parsers::csproj::parse(&dir).is_err());
    cleanup(&dir);
}

#[test]
fn hidden_line_breaks_in_python_config_block() {
    let dir = empty_test_dir("linebreaks");
    for (name, content) in [
        (
            "requirements.txt",
            "six==1.16.0\n# pinned\revil @ https://e.example/e.tgz\n",
        ),
        ("requirements.txt", "six==1.16.0\n# pinned\x0cevil==1\n"),
    ] {
        std::fs::write(dir.join(name), content).unwrap();
        assert!(requirements::parse(&dir).is_err(), "{content:?}");
    }
    std::fs::write(
        dir.join("setup.cfg"),
        "[options]\n# c\rinstall_requires = evil\n",
    )
    .unwrap();
    assert!(setup_cfg::parse(&dir).is_err());
    cleanup(&dir);
}

#[test]
fn msbuild_response_and_solution_files_in_a_parent_block() {
    for name in [
        "Directory.Build.rsp",
        "Directory.Solution.props",
        "Directory.Solution.targets",
    ] {
        let dir = setup_csproj(r#"<Project Sdk="Microsoft.NET.Sdk"></Project>"#);
        assert!(csproj::parse(&dir).is_ok(), "{name} baseline");
        std::fs::write(
            dir.join(name),
            "-p:RestoreSources=https://evil.example/v3/index.json",
        )
        .unwrap();
        assert!(csproj::parse(&dir).is_err(), "{name}");
        cleanup(&dir);
    }
}

#[test]
fn nuget_restore_location_properties_block() {
    for property in [
        "<RestoreConfigFile>build/feeds.xml</RestoreConfigFile>",
        "<RestorePackagesPath>pkgs</RestorePackagesPath>",
        "<RestoreRootConfigDirectory>cfg</RestoreRootConfigDirectory>",
        "<restorepackagespath>pkgs</restorepackagespath>",
    ] {
        let dir = setup_csproj(&format!(
            r#"<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>{property}</PropertyGroup></Project>"#
        ));
        assert!(crate::parsers::csproj::parse(&dir).is_err(), "{property}");
        cleanup(&dir);
    }
}
