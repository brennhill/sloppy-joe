use super::*;

fn spec(kind: ProjectInputKind, manifest: &str) -> ProjectInputSpec {
    ProjectInputSpec {
        kind,
        manifest_path: PathBuf::from("/proj").join(manifest),
        lockfile_path_override: None,
        js_binding: None,
    }
}

#[test]
fn every_kind_is_owned_by_exactly_one_plugin() {
    for kind in ProjectInputKind::ALL {
        let owners = all()
            .iter()
            .filter(|plugin| plugin.kinds().contains(&kind))
            .count();
        assert_eq!(owners, 1, "{kind:?} must be owned by exactly one plugin");
    }
}

#[test]
fn plugins_own_kinds_of_their_own_ecosystem_only() {
    for plugin in all() {
        let kinds = plugin.kinds();
        assert!(!kinds.is_empty());
        let ecosystem = kinds[0].ecosystem();
        for kind in kinds {
            assert_eq!(kind.ecosystem(), ecosystem, "{kind:?}");
        }
    }
}

#[test]
fn default_lockfile_paths_agree_with_the_descriptor() {
    for kind in ProjectInputKind::ALL {
        let manifest = kind.descriptor().manifest_file_names.first().copied();
        let spec = spec(kind, manifest.unwrap_or("manifest"));
        let path = for_kind(kind).default_lockfile_path(&spec);
        if let Some(name) = kind.descriptor().lockfile_name {
            assert_eq!(path, Some(PathBuf::from("/proj").join(name)), "{kind:?}");
        }
        if kind.descriptor().lockfile == LockfilePolicy::Unsupported {
            assert!(
                path.is_none() || kind == ProjectInputKind::PyRequirementsTrusted,
                "{kind:?} declares no lockfile support"
            );
        }
    }
}

#[test]
fn plugins_detect_exactly_the_manifest_names_their_descriptors_list() {
    for kind in ProjectInputKind::ALL {
        for name in kind.descriptor().manifest_file_names {
            // pyproject.toml is classified by content, so it is not in the name table.
            let detected = detect(Path::new("/proj").join(name).as_path())
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(detected, Some(kind), "{name}");
        }
    }
}

#[test]
fn unrelated_files_are_not_projects() {
    for name in ["README.md", "main.rs", "Makefile", "lock.json"] {
        assert_eq!(
            detect(&Path::new("/proj").join(name)).unwrap(),
            None,
            "{name}"
        );
    }
}

#[test]
fn unsupported_bundler_files_block_instead_of_being_skipped() {
    for name in ["gems.rb", "gems.locked"] {
        assert!(detect(&Path::new("/proj").join(name)).is_err(), "{name}");
    }
}

// Shared conformance suite: every kind that requires a lockfile must block when the lockfile is
// missing or unreadable, and Maven must state its reduced-confidence policy instead of passing
// silently.

/// The fixture rows for every kind the registry exposes with `policy`, found by walking `all()`.
/// A registered kind without a row fails the test, so a new ecosystem cannot join the registry
/// without a fixture.
fn registered<T>(
    rows: &'static [T],
    policy: LockfilePolicy,
    kind_of: impl Fn(&T) -> ProjectInputKind,
) -> Vec<&'static T> {
    all()
        .iter()
        .flat_map(|plugin| plugin.kinds().iter().copied())
        .filter(|kind| kind.descriptor().lockfile == policy)
        .map(|kind| {
            rows.iter()
                .find(|row| kind_of(row) == kind)
                .unwrap_or_else(|| panic!("registered kind {kind:?} has no conformance fixture"))
        })
        .collect()
}

struct Fixture {
    kind: ProjectInputKind,
    manifest: &'static str,
    content: &'static str,
    /// File name the lockfile is written under; empty for kinds without one.
    lockfile: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        kind: ProjectInputKind::Npm,
        manifest: "package.json",
        content: r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
        lockfile: "package-lock.json",
    },
    Fixture {
        kind: ProjectInputKind::Cargo,
        manifest: "Cargo.toml",
        content: "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.200\"\n",
        lockfile: "Cargo.lock",
    },
    Fixture {
        kind: ProjectInputKind::Go,
        manifest: "go.mod",
        content: "module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
        lockfile: "go.sum",
    },
    Fixture {
        kind: ProjectInputKind::Ruby,
        manifest: "Gemfile",
        content: "source 'https://rubygems.org'\ngem 'rake', '13.0.6'\n",
        lockfile: "Gemfile.lock",
    },
    Fixture {
        kind: ProjectInputKind::Php,
        manifest: "composer.json",
        content: r#"{"require":{"monolog/monolog":"3.5.0"}}"#,
        lockfile: "composer.lock",
    },
    Fixture {
        kind: ProjectInputKind::Gradle,
        manifest: "build.gradle",
        content: "dependencies {\n    implementation 'com.google.guava:guava:33.0.0-jre'\n}\n",
        lockfile: "gradle.lockfile",
    },
    Fixture {
        kind: ProjectInputKind::Dotnet,
        manifest: "app.csproj",
        content: r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
        lockfile: "packages.lock.json",
    },
    Fixture {
        kind: ProjectInputKind::PyProjectPoetry,
        manifest: "pyproject.toml",
        content: "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\n\n[tool.poetry.dependencies]\npython = \"3.11.0\"\nrequests = \"2.31.0\"\n",
        lockfile: "poetry.lock",
    },
    Fixture {
        kind: ProjectInputKind::PyProjectUv,
        manifest: "pyproject.toml",
        content: "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n\n[tool.uv]\n",
        lockfile: "uv.lock",
    },
];

fn fixture_dir(fixture: &Fixture, lockfile: Option<&str>) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-conformance-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(fixture.manifest), fixture.content).unwrap();
    if let Some(content) = lockfile {
        assert!(
            !fixture.lockfile.is_empty(),
            "{:?} has no lockfile",
            fixture.kind
        );
        std::fs::write(dir.join(fixture.lockfile), content).unwrap();
    }
    dir
}

/// Why a preflight of `dir` blocks, `None` when it does not.
fn block_reason(dir: &Path) -> Option<String> {
    match crate::preflight_scan_inputs(dir, None) {
        Err(err) => Some(err.to_string()),
        Ok(issues) => issues
            .iter()
            .find(|issue| issue.severity == Severity::Error)
            .map(|issue| issue.message.clone()),
    }
}

#[test]
fn fixtures_cover_every_kind_that_requires_a_lockfile() {
    for kind in ProjectInputKind::ALL {
        if kind.descriptor().lockfile == LockfilePolicy::Required {
            assert!(
                FIXTURES.iter().any(|fixture| fixture.kind == kind),
                "add a conformance fixture for {kind:?}"
            );
        }
    }
}

#[test]
fn a_missing_required_lockfile_blocks() {
    for fixture in registered(FIXTURES, LockfilePolicy::Required, |f| f.kind) {
        let dir = fixture_dir(fixture, None);
        let reason = block_reason(&dir);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("is missing")),
            "{:?} must block because the lockfile is missing, got {reason:?}",
            fixture.kind
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn a_malformed_lockfile_blocks() {
    for fixture in registered(FIXTURES, LockfilePolicy::Required, |f| f.kind) {
        let dir = fixture_dir(fixture, Some("\u{1}{ not a lockfile ]["));
        // The lockfile exists, so the block must be about its content, not its absence.
        let reason = block_reason(&dir);
        assert!(
            reason.as_deref().is_some_and(|r| {
                !r.contains("is missing")
                    && (r.contains("Broken lockfile") || r.contains("malformed or stale"))
            }),
            "{:?} must block because the lockfile is malformed, got {reason:?}",
            fixture.kind
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn maven_states_its_reduced_confidence_policy() {
    let dir = std::env::temp_dir().join(format!("sj-conformance-maven-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("pom.xml"),
        "<project><dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version></dependency></dependencies></project>",
    )
    .unwrap();
    let issues = crate::preflight_scan_inputs(&dir, None).unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE),
        "{issues:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

// Constructs the scan cannot verify must block, and for the stated reason: a fixture that blocks
// for another reason (a missing lockfile) proves nothing about the construct. Rows carry a valid
// lockfile when the plugin only sees the construct there.
struct Unsupported {
    kind: ProjectInputKind,
    manifest: &'static str,
    content: &'static str,
    lockfile: Option<&'static str>,
    reason: &'static str,
}

const UNSUPPORTED: &[Unsupported] = &[
    Unsupported {
        kind: ProjectInputKind::Npm,
        manifest: "package.json",
        content: r#"{"name":"app","version":"1.0.0","dependencies":{"x":"git+https://example.com/x.git"}}"#,
        lockfile: None,
        reason: "Unsupported non-registry npm dependency",
    },
    // The Cargo parse stage drops git dependencies; the lockfile-backed source policy blocks them.
    Unsupported {
        kind: ProjectInputKind::Cargo,
        manifest: "Cargo.toml",
        content: "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nx = { git = \"https://example.com/x\" }\n",
        lockfile: Some(
            "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"x\"]\n\n[[package]]\nname = \"x\"\nversion = \"0.1.0\"\nsource = \"git+https://example.com/x#0000000000000000000000000000000000000000\"\n",
        ),
        reason: "cargo_git_policy blocks git dependencies",
    },
    Unsupported {
        kind: ProjectInputKind::Go,
        manifest: "go.mod",
        content: "module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\nreplace github.com/pkg/errors => ../errors\n",
        lockfile: None,
        reason: "local replace directives are not trusted",
    },
    Unsupported {
        kind: ProjectInputKind::Ruby,
        manifest: "Gemfile",
        content: "source 'https://rubygems.org'\ngem 'x', git: 'https://example.com/x.git'\n",
        lockfile: None,
        reason: "Unsupported non-registry Gemfile dependency source",
    },
    Unsupported {
        kind: ProjectInputKind::Php,
        manifest: "composer.json",
        content: r#"{"require":{"a/b":"dev-main"},"repositories":[{"type":"vcs","url":"https://example.com/b.git"}]}"#,
        lockfile: None,
        reason: "custom package sources are not supported",
    },
    Unsupported {
        kind: ProjectInputKind::Gradle,
        manifest: "build.gradle",
        content: "dependencies {\n    implementation files('libs/x.jar')\n    implementation 'a:b:+'\n}\n",
        lockfile: None,
        reason: "local project or file dependencies are not supported",
    },
    Unsupported {
        kind: ProjectInputKind::Dotnet,
        manifest: "app.csproj",
        content: r#"<Project Sdk="Some.Custom.Sdk/1.0.0"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
        lockfile: None,
        reason: "NuGet-resolved project SDKs cannot be verified",
    },
    Unsupported {
        kind: ProjectInputKind::PyProjectPoetry,
        manifest: "pyproject.toml",
        content: "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\n\n[tool.poetry.dependencies]\npython = \"3.11.0\"\nx = { git = \"https://example.com/x.git\" }\n",
        lockfile: None,
        reason: "git sources are not supported",
    },
    Unsupported {
        kind: ProjectInputKind::PyProjectUv,
        manifest: "pyproject.toml",
        content: "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"x @ git+https://example.com/x.git\"]\n\n[tool.uv]\n",
        lockfile: None,
        reason: "Unsupported direct requirement",
    },
];

/// The first error the parse or source-policy stage raises for `row`, `None` when both pass.
fn unsupported_block(row: &Unsupported) -> (Option<String>, PathBuf) {
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
    let config = config::SloppyJoeConfig::default();
    let opts = ScanOptions::default();
    let ctx = ScanCtx {
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
    let reason = match plugin.parse(&ctx, &spec) {
        Err(err) => Some(err.to_string()),
        Ok(parsed) => match parsed
            .warnings
            .iter()
            .find(|w| w.severity == Severity::Error)
        {
            Some(issue) => Some(issue.message.clone()),
            None => PreflightCtx::new(
                ctx,
                std::slice::from_ref(&spec),
                std::slice::from_ref(&spec),
            )
            .and_then(|pre| plugin.source_policy(&pre, &spec))
            .err()
            .map(|err| err.to_string()),
        },
    };
    (reason, dir)
}

#[test]
fn unsupported_constructs_block_for_the_construct() {
    for row in registered(UNSUPPORTED, LockfilePolicy::Required, |row| row.kind) {
        let (reason, dir) = unsupported_block(row);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains(row.reason)),
            "{:?}: expected a block naming {:?}, got {reason:?}",
            row.kind,
            row.reason
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn unsupported_fixtures_cover_every_conformance_fixture() {
    for fixture in FIXTURES {
        assert!(
            UNSUPPORTED.iter().any(|row| row.kind == fixture.kind),
            "add an unsupported-construct fixture for {:?}",
            fixture.kind
        );
    }
}

#[test]
fn poetry_only_refusals_are_descriptor_facts_that_source_policy_enforces() {
    let mut config = config::SloppyJoeConfig::default();
    config.python_enforcement = config::PythonEnforcement::PoetryOnly;
    let opts = ScanOptions::default();
    let root = std::env::temp_dir();
    for kind in ProjectInputKind::ALL {
        let refusal = kind.descriptor().poetry_only_refusal;
        assert!(
            kind.is_python() || refusal.is_none(),
            "{kind:?}: only Python kinds can be refused by poetry_only"
        );
        if let Some(text) = refusal {
            assert!(
                text.contains("{}"),
                "{kind:?} refusal must name the manifest"
            );
        }
        if !kind.is_python() {
            continue;
        }
        let spec = spec(kind, "manifest");
        let scan = ScanCtx {
            scan_root: &root,
            config: &config,
            opts: &opts,
        };
        let ctx = PreflightCtx::new(scan, &[], &[]).unwrap();
        let outcome = for_kind(kind).source_policy(&ctx, &spec);
        assert_eq!(outcome.is_err(), refusal.is_some(), "{kind:?}");
    }
}

// Kinds with no lockfile of their own must say so: preflight passes with a stated warning
// (legacy format or reduced confidence), never silently clean and never as a lockfile-backed
// scan.
const LOCKFILE_LESS: &[(ProjectInputKind, &str, &str)] = &[
    (
        ProjectInputKind::PyRequirements,
        "requirements.txt",
        "requests==2.31.0\n",
    ),
    (
        ProjectInputKind::PyRequirementsTrusted,
        "requirements.txt",
        "requests==2.31.0 \\\n    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
    ),
    (
        ProjectInputKind::PyProjectLegacy,
        "pyproject.toml",
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n",
    ),
    (
        ProjectInputKind::PyPipfile,
        "Pipfile",
        "[packages]\nrequests = \"==2.31.0\"\n",
    ),
    (
        ProjectInputKind::PySetupPy,
        "setup.py",
        "from setuptools import setup\nsetup(name='app', install_requires=['requests==2.31.0'])\n",
    ),
    (
        ProjectInputKind::PySetupCfg,
        "setup.cfg",
        "[options]\ninstall_requires =\n    requests==2.31.0\n",
    ),
    (
        ProjectInputKind::Maven,
        "pom.xml",
        "<project><dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version></dependency></dependencies></project>",
    ),
];

#[test]
fn every_kind_has_a_conformance_fixture() {
    for kind in ProjectInputKind::ALL {
        let covered = FIXTURES.iter().any(|fixture| fixture.kind == kind)
            || LOCKFILE_LESS.iter().any(|(k, ..)| *k == kind);
        assert!(covered, "add a conformance fixture for {kind:?}");
    }
}

#[test]
fn lockfile_less_kinds_state_their_policy() {
    let config = config::SloppyJoeConfig::default();
    let opts = ScanOptions::default();
    for (kind, manifest, content) in
        registered(LOCKFILE_LESS, LockfilePolicy::Unsupported, |row| row.0)
    {
        assert_eq!(
            kind.descriptor().lockfile,
            LockfilePolicy::Unsupported,
            "{kind:?}"
        );
        let fixture = Fixture {
            kind: *kind,
            manifest,
            content,
            lockfile: "",
        };
        let dir = fixture_dir(&fixture, None);
        let scan = ScanCtx {
            scan_root: &dir,
            config: &config,
            opts: &opts,
        };
        let spec = ProjectInputSpec {
            kind: *kind,
            manifest_path: dir.join(manifest),
            lockfile_path_override: None,
            js_binding: None,
        };
        let ctx = PreflightCtx::new(
            scan,
            std::slice::from_ref(&spec),
            std::slice::from_ref(&spec),
        )
        .unwrap();
        let issues = preflight(&ctx, &spec)
            .unwrap_or_else(|err| panic!("{kind:?} should preflight with a warning: {err}"));
        assert!(
            issues
                .iter()
                .any(|issue| issue.severity == Severity::Warning),
            "{kind:?} must state its reduced-confidence policy, got {issues:?}"
        );
        assert!(
            issues.iter().all(|issue| issue.severity != Severity::Error),
            "{kind:?}: {issues:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

// Unsupported constructs for the kinds with no lockfile: with nothing else to fail on, the whole
// preflight must block.
const UNSUPPORTED_LOCKFILE_LESS: &[(ProjectInputKind, &str, &str, &str)] = &[
    (
        ProjectInputKind::PyRequirements,
        "requirements.txt",
        "x @ git+https://example.com/x.git\n",
        "Unsupported direct requirement 'x @ git+",
    ),
    (
        ProjectInputKind::PyRequirementsTrusted,
        "requirements.txt",
        "x @ git+https://example.com/x.git \\\n    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
        "Unsupported direct requirement 'x @ git+",
    ),
    (
        ProjectInputKind::PyProjectLegacy,
        "pyproject.toml",
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"x @ git+https://example.com/x.git\"]\n",
        "Unsupported direct requirement 'x @ git+",
    ),
    (
        ProjectInputKind::PyPipfile,
        "Pipfile",
        "[packages]\nx = {git = \"https://example.com/x.git\"}\n",
        "git sources are not supported",
    ),
    (
        ProjectInputKind::PySetupPy,
        "setup.py",
        "from setuptools import setup\nsetup(name='app', install_requires=['x @ git+https://example.com/x.git'])\n",
        "Unsupported direct requirement 'x @ git+",
    ),
    (
        ProjectInputKind::PySetupCfg,
        "setup.cfg",
        "[options]\ninstall_requires =\n    x @ git+https://example.com/x.git\n",
        "Unsupported direct requirement 'x @ git+",
    ),
    (
        ProjectInputKind::Maven,
        "pom.xml",
        "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0</version><scope>system</scope><systemPath>/opt/b.jar</systemPath></dependency></dependencies></project>",
        "systemPath dependencies are not supported",
    ),
];

#[test]
fn lockfile_less_kinds_block_unsupported_constructs() {
    let config = config::SloppyJoeConfig::default();
    let opts = ScanOptions::default();
    let mut mismatches = Vec::new();
    for (kind, manifest, content, reason) in registered(
        UNSUPPORTED_LOCKFILE_LESS,
        LockfilePolicy::Unsupported,
        |row| row.0,
    ) {
        let fixture = Fixture {
            kind: *kind,
            manifest,
            content,
            lockfile: "",
        };
        let dir = fixture_dir(&fixture, None);
        let scan = ScanCtx {
            scan_root: &dir,
            config: &config,
            opts: &opts,
        };
        let spec = ProjectInputSpec {
            kind: *kind,
            manifest_path: dir.join(manifest),
            lockfile_path_override: None,
            js_binding: None,
        };
        let ctx = PreflightCtx::new(
            scan,
            std::slice::from_ref(&spec),
            std::slice::from_ref(&spec),
        )
        .unwrap();
        let blocked = match preflight(&ctx, &spec) {
            Err(err) => Some(err.to_string()),
            Ok(issues) => issues
                .iter()
                .find(|i| i.severity == Severity::Error)
                .map(|i| i.message.clone()),
        };
        if !blocked.as_deref().is_some_and(|text| text.contains(reason)) {
            mismatches.push(format!("{kind:?}: expected {reason:?}, got {blocked:?}"));
        }
        let _ = std::fs::remove_dir_all(dir);
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn every_kind_has_an_unsupported_construct_fixture() {
    for kind in ProjectInputKind::ALL {
        let covered = UNSUPPORTED.iter().any(|row| row.kind == kind)
            || UNSUPPORTED_LOCKFILE_LESS.iter().any(|(k, ..)| *k == kind);
        assert!(covered, "add an unsupported-construct fixture for {kind:?}");
    }
}

#[path = "tests/registry.rs"]
mod registry;
