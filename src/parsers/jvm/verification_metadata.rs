//! `gradle/verification-metadata.xml` and `gradle/*.versions.toml`: files Gradle reads beside a
//! project that weaken or extend what it trusts.

use crate::untrusted::{self, Format};
use anyhow::{Result, bail};
use std::path::Path;

/// Gradle's dependency verification is the only integrity check on `gradle.lockfile` builds, so a
/// file that switches it off, trusts by pattern or ignores keys is a weakened install.
pub(crate) fn reject_weakened_verification_metadata(path: &Path) -> Result<()> {
    let text = untrusted::read_text(path, Format::Xml, crate::parsers::MAX_MANIFEST_BYTES)?;
    let lowered = text.to_ascii_lowercase();
    let compact: String = lowered.split_whitespace().collect();
    let weakened = if compact.contains("<verify-metadata>false") {
        Some("<verify-metadata> is false, so checksums are not verified")
    } else if compact.contains("<ignored-key") {
        Some("<ignored-keys> lets artifacts signed by those keys through unchecked")
    } else if tags(&lowered)
        .filter(|tag| tag.starts_with("trust ") || tag.starts_with("trust/"))
        .any(|tag| tag.replace(' ', "").contains("regex=\"true\""))
    {
        Some("a <trust> element matches by regular expression, so unlisted artifacts are trusted")
    } else {
        None
    };
    match weakened {
        Some(why) => bail!(
            "Unsupported Gradle dependency verification file {}: {why}",
            path.display()
        ),
        None => Ok(()),
    }
}

/// The text of every `<...>` tag, without the angle brackets.
fn tags(text: &str) -> impl Iterator<Item = &str> {
    text.split('<')
        .skip(1)
        .filter_map(|part| part.split_once('>').map(|(tag, _)| tag.trim_start()))
}

/// A version catalog only names coordinates (the resolved versions come from `gradle.lockfile`),
/// and its sources are set in `settings.gradle`, which the script scanner covers. It is still
/// read through the gateway so a BOM, NUL byte or duplicate key blocks instead of being parsed
/// differently by Gradle.
pub(crate) fn reject_unreadable_version_catalog(path: &Path) -> Result<()> {
    untrusted::read(path, Format::Toml, crate::parsers::MAX_MANIFEST_BYTES)
        .map(|_| ())
        .map_err(|err| {
            anyhow::anyhow!(
                "Unsupported Gradle version catalog {}: {err:#}",
                path.display()
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, content: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sj-verif-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn weakened_verification_metadata_blocks() {
        for body in [
            "<verification-metadata><configuration><verify-metadata>false</verify-metadata></configuration></verification-metadata>",
            "<verification-metadata><configuration><verify-metadata> false </verify-metadata></configuration></verification-metadata>",
            "<verification-metadata><configuration><trusted-artifacts><trust group=\".*\" regex=\"true\"/></trusted-artifacts></configuration></verification-metadata>",
            "<verification-metadata><configuration><verification-metadata><ignored-keys><ignored-key id=\"ABCD\"/></ignored-keys></verification-metadata></configuration></verification-metadata>",
        ] {
            let path = write("verification-metadata.xml", body);
            assert!(
                reject_weakened_verification_metadata(&path).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn ordinary_verification_metadata_passes() {
        let body = "<verification-metadata><configuration><verify-metadata>true</verify-metadata><trusted-artifacts><trust group=\"com.google.guava\"/></trusted-artifacts></configuration><components/></verification-metadata>";
        let path = write("verification-metadata.xml", body);
        reject_weakened_verification_metadata(&path).unwrap();
    }

    #[test]
    fn a_catalog_with_a_duplicate_key_or_bom_blocks() {
        let dup = write("libs.versions.toml", "[versions]\na = \"1\"\na = \"2\"\n");
        assert!(reject_unreadable_version_catalog(&dup).is_err());
        let bom = write("libs.versions.toml", "\u{feff}[versions]\na = \"1\"\n");
        assert!(reject_unreadable_version_catalog(&bom).is_err());
        let ok = write("libs.versions.toml", "[versions]\na = \"1\"\n");
        reject_unreadable_version_catalog(&ok).unwrap();
    }
}
