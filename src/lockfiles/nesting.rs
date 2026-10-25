use super::*;

/// Parse a JSON5 lockfile (bun.lock) after rejecting pathological nesting
/// that would overflow the recursive-descent parser's stack.
pub(crate) fn parse_json5_guarded(content: &str) -> Result<serde_json::Value> {
    ensure_nesting_depth(content, NestingSyntax::Json5)?;
    Ok(json5::from_str(content)?)
}

/// Parse a YAML lockfile or workspace file after rejecting pathological flow
/// nesting that makes the YAML scanner burn minutes of CPU.
/// Key under which the packages of pnpm's own (earlier) lockfile documents ride
/// along with the project document. Not a pnpm key.
pub(crate) const PNPM_ENV_PACKAGES_KEY: &str = "x-sloppy-joe-env-packages";

/// A pnpm lockfile has one project document; pnpm that manages its own version
/// writes earlier "environment" documents locking pnpm itself. Allow a handful.
pub(crate) const MAX_PNPM_LOCK_DOCUMENTS: usize = 4;

/// Parse a `pnpm-lock.yaml`. The last YAML document is the project lockfile and
/// is returned as before. The packages of any earlier environment documents
/// (pnpm and its config dependencies, which are installed and run too) are
/// checked to be plain registry packages and carried along under
/// [`PNPM_ENV_PACKAGES_KEY`] so they are scanned with the root importer.
pub(crate) fn parse_pnpm_lock_guarded(content: &str) -> Result<serde_yaml::Value> {
    use serde::Deserialize;

    ensure_nesting_depth(content, NestingSyntax::Yaml)?;
    let mut documents = serde_yaml::Deserializer::from_str(content)
        .map(serde_yaml::Value::deserialize)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if documents.len() <= 1 {
        let project: serde_yaml::Value = serde_yaml::from_str(content)?;
        ensure_pnpm_lockfile_version(&project)?;
        return Ok(project);
    }
    if documents.len() > MAX_PNPM_LOCK_DOCUMENTS {
        anyhow::bail!(
            "pnpm-lock.yaml has {} YAML documents; at most {} are supported",
            documents.len(),
            MAX_PNPM_LOCK_DOCUMENTS
        );
    }
    documents
        .iter()
        .try_for_each(ensure_pnpm_lockfile_version)?;

    let mut project = documents.pop().expect("more than one document");
    let has_importers = project
        .get("importers")
        .is_some_and(serde_yaml::Value::is_mapping);
    if !has_importers {
        anyhow::bail!(
            "the last YAML document of pnpm-lock.yaml is the project lockfile and must have an importers table"
        );
    }

    let mut env_packages = std::collections::BTreeSet::new();
    for document in &documents {
        if !document.is_mapping() || document.get("lockfileVersion").is_none() {
            anyhow::bail!(
                "an earlier YAML document of pnpm-lock.yaml is not a pnpm lockfile (it needs a lockfileVersion)"
            );
        }
        let Some(packages) = document
            .get("packages")
            .and_then(|value| value.as_mapping())
        else {
            continue;
        };
        for (key, value) in packages {
            let key = key.as_str().ok_or_else(|| {
                anyhow::anyhow!("an environment package key in pnpm-lock.yaml is not a string")
            })?;
            let Some((name, version)) = pnpm::pnpm_package_key_parts(key) else {
                anyhow::bail!(
                    "environment package '{}' in pnpm-lock.yaml has an unrecognized key",
                    crate::report::sanitize_for_terminal(key)
                );
            };
            if !crate::ecosystem::validate_package_name_for_ecosystem(name, Ecosystem::Npm) {
                anyhow::bail!(
                    "environment package '{}' in pnpm-lock.yaml has an invalid package name",
                    crate::report::sanitize_for_terminal(key)
                );
            }
            // Only plain registry packages can be vetted: an integrity hash and
            // no tarball, directory or git override.
            let registry_only = value
                .get("resolution")
                .and_then(|resolution| resolution.as_mapping())
                .is_some_and(|resolution| {
                    resolution.len() == 1
                        && resolution
                            .get("integrity")
                            .is_some_and(serde_yaml::Value::is_string)
                });
            if !registry_only {
                anyhow::bail!(
                    "environment package '{}' in pnpm-lock.yaml does not resolve to a plain registry package with an integrity hash",
                    crate::report::sanitize_for_terminal(key)
                );
            }
            env_packages.insert(format!("{name}@{version}"));
        }
    }

    if !env_packages.is_empty()
        && let Some(mapping) = project.as_mapping_mut()
    {
        mapping.insert(
            serde_yaml::Value::String(PNPM_ENV_PACKAGES_KEY.to_string()),
            serde_yaml::Value::Sequence(
                env_packages
                    .into_iter()
                    .map(serde_yaml::Value::String)
                    .collect(),
            ),
        );
    }
    Ok(project)
}

/// The one pnpm lockfile format the key and graph parsers model (pnpm 9 and later). Older
/// formats key packages differently (`/name/1.0.0`, `/name@1.0.0`), and pnpm ignores or
/// rewrites a lockfile whose version it does not know, so anything else would be read wrong.
pub(crate) const PNPM_LOCKFILE_VERSION: &str = "9.0";

fn ensure_pnpm_lockfile_version(document: &serde_yaml::Value) -> Result<()> {
    match document.get("lockfileVersion") {
        Some(serde_yaml::Value::String(version)) if version == PNPM_LOCKFILE_VERSION => Ok(()),
        Some(other) => anyhow::bail!(
            "pnpm-lock.yaml lockfileVersion {} is not supported: only '{}' (pnpm 9 and later) is modeled. Fix: regenerate the lockfile with pnpm 9 or later and commit it.",
            crate::report::sanitize_for_terminal(
                serde_yaml::to_string(other).unwrap_or_default().trim()
            ),
            PNPM_LOCKFILE_VERSION
        ),
        None => anyhow::bail!(
            "pnpm-lock.yaml has no lockfileVersion, so its format is unknown. Fix: regenerate the lockfile with pnpm 9 or later and commit it."
        ),
    }
}

pub(crate) fn parse_yaml_guarded(content: &str) -> Result<serde_yaml::Value> {
    ensure_nesting_depth(content, NestingSyntax::Yaml)?;
    Ok(serde_yaml::from_str(content)?)
}

/// Real lockfiles nest well under 10 levels. This cap stays far below the
/// depth at which json5's recursive parser overflows a 2 MiB thread stack.
pub(crate) const MAX_LOCKFILE_NESTING_DEPTH: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NestingSyntax {
    Json5,
    Yaml,
}

/// Cheap linear pre-scan of `[`/`{` nesting depth that skips string literals
/// and comments, so brackets inside strings neither trip nor hide the limit.
pub(crate) fn ensure_nesting_depth(content: &str, syntax: NestingSyntax) -> Result<()> {
    let bytes = content.as_bytes();
    let mut depth = 0usize;
    let mut index = 0usize;
    // Last significant byte on the current line outside strings/comments;
    // `None` at the start of a line. YAML quotes only open a string at a token
    // start, so `it's` stays a plain scalar.
    let mut previous: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if opens_string(byte, previous, syntax) {
            index = skip_string(bytes, index, syntax);
            previous = Some(b'"');
            continue;
        }
        if let Some(after_comment) = skip_comment(bytes, index, syntax) {
            index = after_comment;
            continue;
        }
        match byte {
            b'[' | b'{' => {
                depth += 1;
                if depth > MAX_LOCKFILE_NESTING_DEPTH {
                    anyhow::bail!(
                        "lockfile nests deeper than {} levels; refusing to parse a pathologically nested file",
                        MAX_LOCKFILE_NESTING_DEPTH
                    );
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            b'\n' => {
                previous = None;
                index += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' => {
                index += 1;
                continue;
            }
            _ => {}
        }
        previous = Some(byte);
        index += 1;
    }
    Ok(())
}

fn opens_string(byte: u8, previous: Option<u8>, syntax: NestingSyntax) -> bool {
    matches!(byte, b'"' | b'\'')
        && (syntax == NestingSyntax::Json5
            || matches!(
                previous,
                None | Some(b':' | b',' | b'[' | b'{' | b'-' | b'?')
            ))
}

/// Index just past a comment starting at `index`, or `None` when no comment starts there.
fn skip_comment(bytes: &[u8], index: usize, syntax: NestingSyntax) -> Option<usize> {
    let next = bytes.get(index + 1);
    match bytes[index] {
        b'/' if syntax == NestingSyntax::Json5 && next == Some(&b'/') => {
            Some(skip_until(bytes, index + 2, b"\n"))
        }
        b'/' if syntax == NestingSyntax::Json5 && next == Some(&b'*') => {
            Some(skip_until(bytes, index + 2, b"*/") + 2)
        }
        b'#' if syntax == NestingSyntax::Yaml
            && (index == 0 || bytes[index - 1].is_ascii_whitespace()) =>
        {
            Some(skip_until(bytes, index + 1, b"\n"))
        }
        _ => None,
    }
}

/// Index just past the string literal opening at `start`.
pub(crate) fn skip_string(bytes: &[u8], start: usize, syntax: NestingSyntax) -> usize {
    let quote = bytes[start];
    let backslash_escapes = syntax == NestingSyntax::Json5 || quote == b'"';
    let mut index = start + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' && backslash_escapes {
            index += 2;
            continue;
        }
        if byte == quote {
            // YAML single-quoted strings escape a quote by doubling it.
            if syntax == NestingSyntax::Yaml
                && quote == b'\''
                && bytes.get(index + 1) == Some(&b'\'')
            {
                index += 2;
                continue;
            }
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

/// Index of the first occurrence of `needle` at or after `start` (or the end).
pub(crate) fn skip_until(bytes: &[u8], start: usize, needle: &[u8]) -> usize {
    bytes
        .get(start..)
        .and_then(|rest| {
            rest.windows(needle.len())
                .position(|window| window == needle)
        })
        .map(|position| start + position)
        .unwrap_or(bytes.len())
}

// -- Shared helpers used by npm.rs and cargo.rs --
