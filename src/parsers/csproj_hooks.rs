//! Code that runs while `dotnet restore` installs packages, and tools CI runs afterwards:
//! restore-hooked MSBuild targets, inline task factories, `InitialTargets`, unmodeled
//! `obj/<project>.*.props` extension imports and `.config/dotnet-tools.json` local tools.

use anyhow::{Result, bail};
use std::path::Path;

/// Names that tie a `<Target>` to the restore.
const RESTORE_MARKERS: &[&str] = &["restore", "collectpackagereferences"];

/// The opening tag up to its `>`, lowercased (MSBuild matches item and property names loosely and
/// the check must not depend on capitalisation).
fn lowered_open_tag(tag: &str) -> String {
    tag.split('>').next().unwrap_or_default().to_lowercase()
}

/// Reject `<Target>` hooked to or named after the restore, `<UsingTask TaskFactory=..>`, inline
/// `<TaskBody>` code and `InitialTargets` on `<Project>`. `folded_name` is the lowercase local
/// element name, `tag` the text after `<`.
pub(super) fn reject_install_hooks(folded_name: &str, tag: &str, csproj: &Path) -> Result<()> {
    let open = lowered_open_tag(tag);
    let reason = match folded_name {
        "target" if RESTORE_MARKERS.iter().any(|marker| open.contains(marker)) => {
            "a Target tied to the restore runs code while packages are installed"
        }
        "usingtask" if open.contains("taskfactory") => {
            "an inline task factory compiles and runs code from the repository"
        }
        "taskbody" => "an inline task body runs code from the repository",
        "project" if open.contains("initialtargets") => {
            "InitialTargets run before every build and restore"
        }
        _ => return Ok(()),
    };
    bail!(
        "Unsupported MSBuild {} in {}: {}",
        folded_name,
        csproj.display(),
        reason
    )
}

/// MSBuild imports `obj/<project file>.*.props` and `.targets` automatically. NuGet's own
/// `.nuget.g.*` files are expected; any other name is an unscanned import.
pub(super) fn reject_obj_extension_imports(csproj: &Path) -> Result<()> {
    let (Some(dir), Some(file)) = (csproj.parent(), csproj.file_name().and_then(|n| n.to_str()))
    else {
        return Ok(());
    };
    let obj = dir.join("obj");
    let Ok(entries) = std::fs::read_dir(&obj) else {
        return Ok(());
    };
    let prefix = format!("{}.", file.to_lowercase());
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        let imported = name.ends_with(".props") || name.ends_with(".targets");
        let generated = name.ends_with(".nuget.g.props") || name.ends_with(".nuget.g.targets");
        if name.starts_with(&prefix) && imported && !generated {
            bail!(
                "Unsupported MSBuild extension import {} for {}: MSBuild imports it automatically and its contents cannot be verified",
                entry.path().display(),
                csproj.display()
            );
        }
    }
    Ok(())
}

/// `.config/dotnet-tools.json` declares local tools that `dotnet tool restore` installs and CI
/// then runs; they are never part of `packages.lock.json`.
pub(super) fn reject_local_tools(dir: &Path, csproj: &Path) -> Result<()> {
    let manifest = dir.join(".config").join("dotnet-tools.json");
    if !super::path_detected(&manifest)? {
        return Ok(());
    }
    let content = super::read_file_limited(&manifest, super::MAX_MANIFEST_BYTES)?;
    let parsed: serde_json::Value = serde_json::from_str(content.trim_start_matches('\u{feff}'))
        .map_err(|err| {
            anyhow::anyhow!(
                "Unreadable dotnet tool manifest {}: {err}",
                manifest.display()
            )
        })?;
    let tools = parsed.as_object().and_then(|object| {
        object
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("tools"))
            .map(|(_, value)| value)
    });
    let declared = match tools {
        None => false,
        Some(value) => value.as_object().is_none_or(|map| !map.is_empty()),
    };
    if declared {
        bail!(
            "Unsupported dotnet tool manifest {} (applies to {}): local tools are restored and run outside packages.lock.json and cannot be verified",
            manifest.display(),
            csproj.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::parsers::csproj::parse;
    use crate::parsers::test_utils::*;

    fn project(body: &str) -> std::path::PathBuf {
        setup_test_dir("csproj-hooks", "app.csproj", body)
    }

    fn blocked(body: &str, needle: &str) {
        let dir = project(body);
        let err = parse(&dir).expect_err(body).to_string();
        assert!(err.contains(needle), "{body}: {err}");
        cleanup(&dir);
    }

    #[test]
    fn targets_tied_to_the_restore_block() {
        for target in [
            r#"<Target Name="Marker" BeforeTargets="Restore"><Touch Files="m" /></Target>"#,
            r#"<Target Name="Marker" AfterTargets="_GenerateRestoreGraph"><Exec Command="x" /></Target>"#,
            r#"<Target Name="m" DependsOnTargets="CollectPackageReferences" />"#,
            r#"<target name="Restore"><Exec Command="x" /></target>"#,
            r#"<Target Name="m" BeforeTargets="restore;Build" />"#,
        ] {
            blocked(
                &format!("<Project Sdk=\"Microsoft.NET.Sdk\">{target}</Project>"),
                "Target",
            );
        }
    }

    #[test]
    fn build_time_targets_and_plain_projects_pass() {
        let dir = project(
            r#"<Project Sdk="Microsoft.NET.Sdk"><Target Name="Copy" AfterTargets="Build"><Copy SourceFiles="a" DestinationFolder="b" /></Target><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#,
        );
        assert_eq!(parse(&dir).unwrap().len(), 1);
        cleanup(&dir);
    }

    #[test]
    fn inline_tasks_and_initial_targets_block() {
        blocked(
            r#"<Project><UsingTask TaskName="T" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll"><Task><Code Type="Fragment" Language="cs">x</Code></Task></UsingTask></Project>"#,
            "usingtask",
        );
        blocked(
            r#"<Project><UsingTask TaskName="T"><TaskBody>x</TaskBody></UsingTask></Project>"#,
            "taskbody",
        );
        blocked(
            r#"<Project InitialTargets="Pwn"><Target Name="Pwn" /></Project>"#,
            "project",
        );
    }

    #[test]
    fn unmodeled_obj_extension_imports_block_but_nuget_generated_files_pass() {
        let dir = project(r#"<Project Sdk="Microsoft.NET.Sdk" />"#);
        let obj = dir.join("obj");
        std::fs::create_dir_all(&obj).unwrap();
        std::fs::write(obj.join("app.csproj.nuget.g.props"), "<Project />").unwrap();
        std::fs::write(obj.join("app.csproj.nuget.g.targets"), "<Project />").unwrap();
        std::fs::write(obj.join("project.assets.json"), "{}").unwrap();
        assert!(parse(&dir).is_ok());
        std::fs::write(obj.join("app.csproj.evil.props"), "<Project />").unwrap();
        let err = parse(&dir).unwrap_err().to_string();
        assert!(err.contains("extension import"), "{err}");
        cleanup(&dir);
    }

    #[test]
    fn local_dotnet_tools_block() {
        for tools in [
            r#"{"version":1,"isRoot":true,"tools":{"dotnet-ef":{"version":"9.0.0","commands":["dotnet-ef"]}}}"#,
            r#"{"version":1,"Tools":{"x":{}}}"#,
            r#"{"tools": 5}"#,
            "not json",
        ] {
            let dir = project(r#"<Project Sdk="Microsoft.NET.Sdk" />"#);
            std::fs::create_dir_all(dir.join(".config")).unwrap();
            std::fs::write(dir.join(".config/dotnet-tools.json"), tools).unwrap();
            assert!(parse(&dir).is_err(), "{tools}");
            cleanup(&dir);
        }
        let dir = project(r#"<Project Sdk="Microsoft.NET.Sdk" />"#);
        std::fs::create_dir_all(dir.join(".config")).unwrap();
        std::fs::write(
            dir.join(".config/dotnet-tools.json"),
            r#"{"version":1,"isRoot":true,"tools":{}}"#,
        )
        .unwrap();
        assert!(
            parse(&dir).is_ok(),
            "an empty tool manifest declares nothing"
        );
        cleanup(&dir);
    }
}
