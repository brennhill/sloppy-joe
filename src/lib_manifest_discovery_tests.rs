use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("sj-dotnet-discovery-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn monorepo_discovery_includes_fsharp_and_visual_basic_projects() {
    let root = unique_dir();
    for (dir, file, package) in [
        ("fs", "app.fsproj", "Evil.FSharp"),
        ("vb", "app.vbproj", "Evil.VisualBasic"),
    ] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
        std::fs::write(
            root.join(dir).join(file),
            format!(
                r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="{package}" Version="1.0.0" /></ItemGroup></Project>"#
            ),
        )
        .unwrap();
    }

    let specs = discover_project_inputs(&root, &[]).unwrap();
    let kinds: Vec<(String, ProjectInputKind)> = specs
        .iter()
        .map(|spec| {
            (
                spec.manifest_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                spec.kind,
            )
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            ("app.fsproj".to_string(), ProjectInputKind::Dotnet),
            ("app.vbproj".to_string(), ProjectInputKind::Dotnet),
        ]
    );
    let names: Vec<String> = specs
        .iter()
        .flat_map(|spec| parse_project_input(&root, spec).unwrap())
        .map(|dep| dep.name)
        .collect();
    assert_eq!(names, vec!["Evil.FSharp", "Evil.VisualBasic"]);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn monorepo_discovery_fails_closed_on_legacy_packages_config() {
    let root = unique_dir();
    let legacy = root.join("legacy");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(
        legacy.join("packages.config"),
        r#"<?xml version="1.0" encoding="utf-8"?><packages><package id="Evil.Legacy" version="1.0.0" targetFramework="net472" /></packages>"#,
    )
    .unwrap();

    let err = discover_project_inputs(&root, &[])
        .expect_err("packages.config must not vanish from discovery");
    assert!(err.to_string().contains("packages.config"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn npm_manifest_with_utf8_bom_is_read() {
    let root = unique_dir();
    let manifest = root.join("package.json");
    std::fs::write(
        &manifest,
        "\u{feff}{\"name\":\"t0\",\"dependencies\":{\"left-pad\":\"^1.3.0\"}}",
    )
    .unwrap();
    let value = read_npm_manifest_value(&manifest).unwrap();
    assert_eq!(value["name"], "t0");
    let deps = parsers::package_json::parse(&root).unwrap();
    assert_eq!(deps[0].name, "left-pad");
    let _ = std::fs::remove_dir_all(&root);
}
