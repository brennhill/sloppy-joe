//! `nuget.config` policy for .NET projects.
use super::csproj::{extract_attr, strip_xml_comments};
use anyhow::{Result, bail};
use std::path::Path;

const NUGET_ORG_FEED: &str = "https://api.nuget.org/v3/index.json";

/// `<add key=..>` settings that move where restore reads or writes packages: a repo-committed
/// folder then supplies packages with their recorded hash metadata.
const FOLDER_KEYS: &[&str] = &["globalpackagesfolder", "repositorypath"];

/// `dotnet restore` honors a `nuget.config` in the project directory or any parent, so a
/// feed other than nuget.org there redirects every package to an unverified source.
pub(super) fn reject_untrusted_nuget_config(dir: &Path, csproj: &Path) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case("nuget.config")
        {
            continue;
        }
        let path = entry.path();
        let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)?;
        let content = strip_xml_comments(&content);
        let lowered = content.to_ascii_lowercase();
        if lowered.contains("<fallbackpackagefolders") {
            bail!(
                "Unsupported {} (applies to {}): <fallbackPackageFolders> changes where restore reads packages from",
                path.display(),
                csproj.display()
            );
        }
        for tag in content.split('<').skip(1) {
            if !tag.to_ascii_lowercase().starts_with("add") {
                continue;
            }
            let attrs = tag.split('>').next().unwrap_or_default();
            let key = extract_attr(attrs, "key")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if FOLDER_KEYS.contains(&key.trim()) {
                bail!(
                    "Unsupported {} setting in {} (applies to {}): it changes where restore reads packages from",
                    key.trim(),
                    path.display(),
                    csproj.display()
                );
            }
        }
        let mut rest = lowered.as_str();
        let original = content.as_str();
        let mut offset = 0;
        while let Some(start) = rest.find("<packagesources") {
            let section_start = offset + start;
            let section_end = lowered[section_start..]
                .find("</packagesources")
                .map(|end| section_start + end)
                .unwrap_or(lowered.len());
            for tag in original[section_start..section_end].split('<').skip(1) {
                if !tag.to_ascii_lowercase().starts_with("add") {
                    continue;
                }
                let attrs = tag.split('>').next().unwrap_or_default();
                let value = extract_attr(attrs, "value").unwrap_or_default();
                if value.trim() != NUGET_ORG_FEED {
                    bail!(
                        "Unsupported package source '{}' in {} (applies to {}): only {NUGET_ORG_FEED} is trusted",
                        value.trim(),
                        path.display(),
                        csproj.display()
                    );
                }
            }
            offset = section_end;
            rest = &lowered[offset..];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_folder_settings_block() {
        let dir = std::env::temp_dir().join(format!("sj-nuget-folder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = dir.join("a.csproj");
        for key in [
            "globalPackagesFolder",
            "repositoryPath",
            "GLOBALPACKAGESFOLDER",
        ] {
            std::fs::write(
                dir.join("nuget.config"),
                format!(
                    r#"<configuration><config><add key="{key}" value="pkgs"/></config></configuration>"#
                ),
            )
            .unwrap();
            assert!(
                reject_untrusted_nuget_config(&dir, &manifest).is_err(),
                "{key}"
            );
        }
        std::fs::write(
            dir.join("nuget.config"),
            r#"<configuration><config><add key="signatureValidationMode" value="require"/></config></configuration>"#,
        )
        .unwrap();
        assert!(reject_untrusted_nuget_config(&dir, &manifest).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
