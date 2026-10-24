//! Modules that go.sum proves were downloaded but go.mod does not list.
//!
//! From go 1.17 go.mod lists every module that provides a package for the build (`// indirect`
//! ones included), so each is scanned as a requirement. Before that, go.mod lists direct
//! requirements only, and a transitive module that is downloaded would never be scanned.

use super::*;

/// The `go` directive's `(major, minor)`, if there is a parseable one.
pub(super) fn go_version(go_mod: &str) -> Option<(u32, u32)> {
    let version = parse_directive(go_mod, "go")
        .into_iter()
        .next()
        .and_then(|tokens| tokens.into_iter().next())?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts
        .next()?
        .trim_end_matches(|c: char| !c.is_ascii_digit())
        .parse::<u32>()
        .ok()?;
    Some((major, minor))
}

/// Block when go.sum records downloaded modules (entries with a content hash) that a pre-1.17
/// go.mod does not require, since they would reach the build without being scanned.
pub(super) fn check_unlisted_modules(go_mod: &str, go_sum: &str) -> Result<()> {
    if go_version(go_mod).is_some_and(|version| version >= (1, 17)) {
        return Ok(());
    }
    let listed: HashSet<String> = parse_requirements(go_mod)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let local = parse_local_replace_targets(go_mod);
    let mut unlisted: Vec<String> = go_sum
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [module, version, _hash] = fields[..] else {
                return None;
            };
            (!version.ends_with("/go.mod") && !listed.contains(module) && !local.contains(module))
                .then(|| format!("{module} {version}"))
        })
        .collect();
    unlisted.sort();
    unlisted.dedup();
    if unlisted.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "go.sum records downloaded module(s) that go.mod does not list: {}. With a go directive before 1.17 go.mod omits indirect requirements, so these would not be scanned. Fix: raise the go directive to 1.17 or later and run `go mod tidy` so go.mod lists every module.",
        unlisted.join(", ")
    )
}

/// The vendored counterpart of [`check_unlisted_modules`]: `vendor/modules.txt` lists every vendored
/// module, and a pre-1.17 go.mod does not require the indirect ones.
pub(super) fn check_unlisted_vendored(
    go_mod: &str,
    vendored: &HashSet<(String, String)>,
) -> Result<()> {
    if go_version(go_mod).is_some_and(|version| version >= (1, 17)) {
        return Ok(());
    }
    let listed: HashSet<String> = parse_requirements(go_mod)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let local = parse_local_replace_targets(go_mod);
    let mut unlisted: Vec<String> = vendored
        .iter()
        .filter(|(name, _)| !listed.contains(name) && !local.contains(name.as_str()))
        .map(|(name, version)| format!("{name} {version}"))
        .collect();
    unlisted.sort();
    if unlisted.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "vendor/modules.txt lists module(s) that go.mod does not require: {}. With a go directive before 1.17 go.mod omits indirect requirements, so these would not be scanned. Fix: raise the go directive to 1.17 or later and run `go mod tidy && go mod vendor`.",
        unlisted.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=";

    fn sum(entries: &[&str]) -> String {
        entries
            .iter()
            .map(|entry| format!("{entry} {HASH}\n"))
            .collect()
    }

    #[test]
    fn old_go_mod_without_indirect_requirements_blocks_unlisted_downloads() {
        let go_sum = sum(&[
            "golang.org/x/text v0.3.0",
            "golang.org/x/text v0.3.0/go.mod",
            "example.com/hidden v1.0.0",
            "example.com/hidden v1.0.0/go.mod",
        ]);
        for header in ["module m\n\ngo 1.16\n", "module m\n\n"] {
            let go_mod = format!("{header}\nrequire golang.org/x/text v0.3.0\n");
            let err = check_unlisted_modules(&go_mod, &go_sum).unwrap_err();
            assert!(
                err.to_string().contains("example.com/hidden v1.0.0"),
                "{err}"
            );
        }
    }

    #[test]
    fn go_1_17_or_listing_every_module_passes() {
        let go_sum = sum(&[
            "example.com/hidden v1.0.0",
            "example.com/hidden v1.0.0/go.mod",
        ]);
        let new = "module m\n\ngo 1.17\n\nrequire example.com/a v1.0.0\n";
        assert!(check_unlisted_modules(new, &go_sum).is_ok());
        let listed = "module m\n\ngo 1.16\n\nrequire example.com/hidden v1.0.0\n";
        assert!(check_unlisted_modules(listed, &go_sum).is_ok());
        // go.mod-only entries (the module graph) were never downloaded.
        let graph_only = sum(&["example.com/graph v1.0.0/go.mod"]);
        let old = "module m\n\ngo 1.16\n\nrequire example.com/a v1.0.0\n";
        assert!(check_unlisted_modules(old, &graph_only).is_ok());
    }

    #[test]
    fn old_go_mod_with_unrequired_vendored_modules_blocks() {
        let vendored: HashSet<(String, String)> = [
            ("golang.org/x/text".to_string(), "v0.3.0".to_string()),
            ("example.com/hidden".to_string(), "v1.0.0".to_string()),
        ]
        .into();
        let old = "module m\n\ngo 1.16\n\nrequire golang.org/x/text v0.3.0\n";
        let err = check_unlisted_vendored(old, &vendored).unwrap_err();
        assert!(err.to_string().contains("example.com/hidden"), "{err}");
        let new = "module m\n\ngo 1.18\n\nrequire golang.org/x/text v0.3.0\n";
        assert!(check_unlisted_vendored(new, &vendored).is_ok());
    }
}
