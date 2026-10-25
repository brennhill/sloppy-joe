//! Solutions and MSBuild project files the scan does not parse.
//!
//! `dotnet restore` on a solution restores every project it lists, and any MSBuild project
//! (`.proj`, `.sqlproj`, ...) can declare NuGet packages. Only `.csproj`, `.fsproj` and
//! `.vbproj` are parsed, so a solution listing another project type, or another project type
//! that declares packages, would restore dependencies nothing checked.

use super::*;

/// Visual Studio's "solution folder" project type: a folder in the IDE, not a project.
const SOLUTION_FOLDER_TYPE: &str = "2150E333-8FDC-42A3-9474-1A3956D46DE8";

/// Markers of NuGet input in an MSBuild project: package items, central versions, and an SDK
/// pinned to a version (`Name/Version`), which MSBuild downloads from NuGet.
const NUGET_MARKERS: &[&str] = &[
    "PackageReference",
    "PackageDownload",
    "GlobalPackageReference",
    "PackageVersion",
];

fn extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
}

/// What `detect` should do with `path` beyond the supported project files.
pub(super) fn check_unparsed_msbuild_input(path: &Path) -> Result<()> {
    let Some(ext) = extension(path) else {
        return Ok(());
    };
    if parsers::csproj::is_project_file(path) {
        return Ok(());
    }
    match ext.as_str() {
        "sln" if parsers::path_detected(path)? => check_solution(path),
        "slnx" if parsers::path_detected(path)? => check_xml_solution(path),
        _ if ext.ends_with("proj") && parsers::path_detected(path)? => check_other_project(path),
        _ => Ok(()),
    }
}

fn read(path: &Path, format: crate::untrusted::Format) -> Result<String> {
    let text =
        crate::untrusted::read_validated_bom_tolerant(path, format, parsers::MAX_MANIFEST_BYTES)?;
    Ok(text.trim_start_matches('\u{feff}').to_string())
}

fn unsupported_member(solution: &Path, member: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Unsupported project '{}' in solution {}: restoring the solution restores it, but only .csproj, .fsproj and .vbproj projects are scanned, so its NuGet dependencies would go unchecked. Fix: remove it from the solution or convert it to a supported project type.",
        crate::report::sanitize_for_terminal(member),
        solution.display()
    )
}

fn check_member(solution: &Path, member: &str) -> Result<()> {
    let normalized = member.replace('\\', "/");
    if parsers::csproj::is_project_file(Path::new(&normalized)) {
        return Ok(());
    }
    Err(unsupported_member(solution, member))
}

/// `Project("{type}") = "name", "path", "{guid}"` lines of a classic `.sln`.
fn check_solution(path: &Path) -> Result<()> {
    let text = read(path, crate::untrusted::Format::Line)?;
    for row in crate::untrusted::rows(&text) {
        let Some(rest) = row.trim_start().strip_prefix("Project(") else {
            continue;
        };
        let fields: Vec<&str> = rest.split('"').collect();
        // [ "", "{type}", ") = ", "name", ", ", "path", ", ", "{guid}", "" ]
        let (Some(kind), Some(member)) = (fields.get(1), fields.get(5)) else {
            return Err(anyhow::anyhow!(
                "Unsupported solution entry in {}: '{}' is not a Project(\"{{type}}\") = \"name\", \"path\" line",
                path.display(),
                crate::report::sanitize_for_terminal(row.trim())
            ));
        };
        if kind
            .trim_matches(['{', '}'])
            .eq_ignore_ascii_case(SOLUTION_FOLDER_TYPE)
        {
            continue;
        }
        check_member(path, member)?;
    }
    Ok(())
}

/// `<Project Path="..."/>` elements of an XML `.slnx` solution.
fn check_xml_solution(path: &Path) -> Result<()> {
    let text = read(path, crate::untrusted::Format::Xml)?;
    for element in text.split("<Project").skip(1) {
        if !element.starts_with(|ch: char| ch.is_whitespace() || ch == '/' || ch == '>') {
            continue;
        }
        let attrs = element.split('>').next().unwrap_or_default();
        let member = attrs
            .split("Path=")
            .nth(1)
            .and_then(|value| {
                let quote = value.chars().next()?;
                value[1..].split(quote).next()
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported solution entry in {}: a <Project> element has no Path",
                    path.display()
                )
            })?;
        check_member(path, member)?;
    }
    Ok(())
}

/// Any other MSBuild project is allowed only while it declares no NuGet input.
fn check_other_project(path: &Path) -> Result<()> {
    let text = read(path, crate::untrusted::Format::Xml)?;
    let pinned_sdk = text.split("Sdk=").skip(1).any(|value| {
        let value = value.trim_start_matches(['"', '\'']);
        value
            .split(['"', '\''])
            .next()
            .is_some_and(|sdk| sdk.contains('/'))
    }) || text.split("<Sdk").skip(1).any(|element| {
        element
            .split('>')
            .next()
            .is_some_and(|attrs| attrs.contains("Version="))
    });
    if pinned_sdk || NUGET_MARKERS.iter().any(|marker| text.contains(marker)) {
        anyhow::bail!(
            "Unsupported MSBuild project {}: it declares NuGet packages or a versioned SDK, but only .csproj, .fsproj and .vbproj projects are scanned, so those dependencies would go unchecked.",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "solution_tests.rs"]
mod tests;
