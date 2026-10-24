//! The registry and source-policy claims, checked against the conformance fixtures.

use super::*;

#[test]
fn every_ecosystem_with_a_kind_resolves_to_its_plugin() {
    for kind in ProjectInputKind::ALL {
        let plugin =
            for_ecosystem(kind.ecosystem()).unwrap_or_else(|err| panic!("{kind:?}: {err}"));
        assert!(plugin.kinds().contains(&kind), "{kind:?}");
    }
}

#[test]
fn only_npm_checks_transitive_similarity_without_deep() {
    for plugin in all() {
        let ecosystem = plugin.kinds()[0].ecosystem();
        assert_eq!(
            plugin.similarity_on_transitives(),
            ecosystem == Ecosystem::Npm,
            "{}",
            ecosystem.as_str()
        );
    }
}

/// A plugin's source policy is a claim about where unsupported sources are rejected. Each
/// unsupported-source fixture holds the claim to account: `EnforcedEarlier` must mean the parse
/// stage rejected it, a lockfile-backed policy must itself reject it, and a policy that accepts a
/// fixture neither parse nor itself rejected is a hole.
#[test]
fn source_policy_claims_match_where_unsupported_sources_are_rejected() {
    let config = config::SloppyJoeConfig::default();
    let opts = ScanOptions::default();
    let mut wrong = Vec::new();
    for row in registered(UNSUPPORTED, LockfilePolicy::Required, |row| row.kind) {
        let fixture = Fixture {
            kind: row.kind,
            manifest: row.manifest,
            content: row.content,
            lockfile: FIXTURES
                .iter()
                .find(|fixture| fixture.kind == row.kind)
                .map_or("", |fixture| fixture.lockfile),
        };
        let dir = fixture_dir(&fixture, row.lockfile);
        let scan = ScanCtx {
            scan_root: &dir,
            config: &config,
            opts: &opts,
        };
        let spec = ProjectInputSpec {
            kind: row.kind,
            manifest_path: dir.join(row.manifest),
            lockfile_path_override: None,
            js_binding: None,
        };
        let plugin = for_kind(row.kind);
        let parse_blocked = match plugin.parse(&scan, &spec) {
            Err(_) => true,
            Ok(parsed) => parsed
                .warnings
                .iter()
                .any(|w| w.severity == Severity::Error),
        };
        let policy = PreflightCtx::new(
            scan,
            std::slice::from_ref(&spec),
            std::slice::from_ref(&spec),
        )
        .and_then(|pre| plugin.source_policy(&pre, &spec));
        let verdict = match policy {
            Err(_) => None,
            Ok(SourcePolicy::EnforcedEarlier(_)) if parse_blocked => None,
            Ok(SourcePolicy::EnforcedEarlier(stage)) => {
                Some(format!("claims {stage} rejects it, but parse accepted it"))
            }
            Ok(_) => Some("accepted an unsupported source".to_string()),
        };
        if let Some(verdict) = verdict {
            wrong.push(format!("{:?}: {verdict}", row.kind));
        }
        let _ = std::fs::remove_dir_all(dir);
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn only_cargo_checks_sources_in_its_own_policy_stage() {
    // Every other lockfile-backed kind states where it enforces sources instead of returning an
    // empty lockfile-backed policy, so "required" cannot hide a no-op.
    let config = config::SloppyJoeConfig::default();
    let opts = ScanOptions::default();
    let root = std::env::temp_dir();
    for kind in ProjectInputKind::ALL {
        if kind.descriptor().lockfile != LockfilePolicy::Required || kind == ProjectInputKind::Cargo
        {
            continue;
        }
        let scan = ScanCtx {
            scan_root: &root,
            config: &config,
            opts: &opts,
        };
        let ctx = PreflightCtx::new(scan, &[], &[]).unwrap();
        let outcome = for_kind(kind).source_policy(&ctx, &spec(kind, "manifest"));
        assert!(
            matches!(outcome, Ok(SourcePolicy::EnforcedEarlier(_))),
            "{kind:?} must state where sources are enforced"
        );
    }
}

/// How many plugins claim `name` (a detected kind or a blocking lookalike error).
fn claimants(name: &str) -> Vec<String> {
    let path = Path::new("/proj").join(name);
    all()
        .iter()
        .filter(|plugin| !matches!(plugin.detect(&path), Ok(None)))
        .map(|plugin| format!("{:?}", plugin.kinds()[0].ecosystem()))
        .collect()
}

#[test]
fn no_file_is_claimed_by_two_plugins() {
    // `detect()` answers with the first plugin that claims a file, so an overlap would make the
    // result depend on registry order.
    let mut names: Vec<&str> = ProjectInputKind::ALL
        .iter()
        .flat_map(|kind| kind.descriptor().manifest_file_names.iter().copied())
        .collect();
    // Pattern-matched names that no descriptor lists, and lookalikes the scan must not skip.
    names.extend([
        "app.csproj",
        "App.Web.csproj",
        "requirements.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "gems.rb",
        "gems.locked",
        "packages.config",
    ]);
    for name in names {
        let owners = claimants(name);
        assert!(owners.len() <= 1, "{name} is claimed by {owners:?}");
    }
    for kind in ProjectInputKind::ALL {
        for name in kind.descriptor().manifest_file_names {
            assert_eq!(claimants(name).len(), 1, "{name}");
        }
    }
}

#[test]
fn manifests_the_scan_does_not_read_block_instead_of_being_skipped() {
    let dir = std::env::temp_dir().join(format!("sj-unscanned-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, content: &str| {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    };
    // pnpm's package.yaml and package.json5 declare npm dependencies the scan would never read.
    let pnpm = write(
        "package.yaml",
        "name: web\ndependencies:\n  left-pad: 1.3.0\n",
    );
    assert!(detect(&pnpm).is_err());
    let dev = write(
        "package.yaml",
        "name: web\ndevDependencies:\n  left-pad: 1.3.0\n",
    );
    assert!(detect(&dev).is_err());
    let json5 = write(
        "package.json5",
        "{name: 'web', dependencies: {'left-pad': '1.3.0'}}",
    );
    assert!(detect(&json5).is_err());
    // Haskell's hpack uses the same file name with a list of dependencies: not a JS project.
    let hpack = write(
        "package.yaml",
        "name: lib\ndependencies:\n  - base\n  - text\n",
    );
    assert_eq!(detect(&hpack).unwrap(), None);
    // Unreadable or malformed candidates fail closed.
    let broken = write("package.yaml", "dependencies: [unclosed");
    assert!(detect(&broken).is_err());
    let _ = std::fs::remove_dir_all(dir);
}
