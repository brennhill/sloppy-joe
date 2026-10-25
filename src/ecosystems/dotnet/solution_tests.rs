use super::*;
use crate::parsers::test_utils::{cleanup, setup_test_dir};

fn check(name: &str, content: &str) -> Result<()> {
    let dir = setup_test_dir("dotnet-solution", name, content);
    let result = check_unparsed_msbuild_input(&dir.join(name));
    cleanup(&dir);
    result
}

const HEADER: &str = "\u{feff}\nMicrosoft Visual Studio Solution File, Format Version 12.00\n";

fn sln(entries: &[(&str, &str)]) -> String {
    let mut text = HEADER.to_string();
    for (kind, path) in entries {
        text.push_str(&format!(
            "Project(\"{{{kind}}}\") = \"x\", \"{path}\", \"{{11111111-1111-1111-1111-111111111111}}\"\nEndProject\n"
        ));
    }
    text
}

const CSHARP: &str = "9A19103F-16F7-4668-BE54-9A1E7A4F7556";

#[test]
fn a_solution_of_supported_projects_and_folders_passes() {
    let text = sln(&[
        (CSHARP, "app\\demo.csproj"),
        ("F2A71F9B-5D33-465A-A702-920D77279786", "lib\\lib.fsproj"),
        (SOLUTION_FOLDER_TYPE, "src"),
    ]);
    check("demo.sln", &text).unwrap();
}

#[test]
fn a_solution_listing_another_project_type_is_rejected() {
    for member in ["tools\\tools.proj", "db\\build.sqlproj", "web\\site.esproj"] {
        let err = check(
            "demo.sln",
            &sln(&[(CSHARP, "app\\demo.csproj"), (CSHARP, member)]),
        )
        .expect_err(member)
        .to_string();
        assert!(err.contains("Unsupported project"), "{member}: {err}");
    }
}

#[test]
fn an_unreadable_solution_entry_is_rejected() {
    let text = format!("{HEADER}Project(\"{{{CSHARP}}}\") = \"x\"\nEndProject\n");
    assert!(check("demo.sln", &text).is_err());
}

#[test]
fn an_xml_solution_listing_another_project_type_is_rejected() {
    check(
        "demo.slnx",
        "<Solution><Project Path=\"app/demo.csproj\" /></Solution>",
    )
    .unwrap();
    assert!(
        check(
            "demo.slnx",
            "<Solution><Project Path=\"app/demo.csproj\" /><Project Path='tools/tools.proj' /></Solution>",
        )
        .is_err()
    );
}

#[test]
fn other_msbuild_projects_may_not_declare_nuget_input() {
    for content in [
        "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><PackageReference Include=\"Evil\" Version=\"1.0.0\" /></ItemGroup></Project>",
        "<Project Sdk=\"Microsoft.Build.NoTargets/3.7.0\" />",
        "<Project><Sdk Name=\"Microsoft.Build.Sql\" Version=\"0.1.12\" /></Project>",
        "<Project><ItemGroup><PackageDownload Include=\"Evil\" Version=\"[1.0.0]\" /></ItemGroup></Project>",
    ] {
        assert!(check("build.sqlproj", content).is_err(), "{content}");
    }
    check(
        "native.vcxproj",
        "<Project DefaultTargets=\"Build\"><ItemGroup><ClCompile Include=\"a.cpp\" /></ItemGroup></Project>",
    )
    .unwrap();
}

#[test]
fn files_that_are_not_msbuild_inputs_are_ignored() {
    check("README.md", "PackageReference").unwrap();
    check("app.csproj", "<Project />").unwrap();
}
