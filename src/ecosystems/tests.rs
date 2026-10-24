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

struct Fixture {
    kind: ProjectInputKind,
    manifest: &'static str,
    content: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        kind: ProjectInputKind::Npm,
        manifest: "package.json",
        content: r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    },
    Fixture {
        kind: ProjectInputKind::Cargo,
        manifest: "Cargo.toml",
        content: "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.200\"\n",
    },
    Fixture {
        kind: ProjectInputKind::Go,
        manifest: "go.mod",
        content: "module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
    },
    Fixture {
        kind: ProjectInputKind::Ruby,
        manifest: "Gemfile",
        content: "source 'https://rubygems.org'\ngem 'rake', '13.0.6'\n",
    },
    Fixture {
        kind: ProjectInputKind::Php,
        manifest: "composer.json",
        content: r#"{"require":{"monolog/monolog":"3.5.0"}}"#,
    },
    Fixture {
        kind: ProjectInputKind::Gradle,
        manifest: "build.gradle",
        content: "dependencies {\n    implementation 'com.google.guava:guava:33.0.0-jre'\n}\n",
    },
    Fixture {
        kind: ProjectInputKind::Dotnet,
        manifest: "app.csproj",
        content: r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
    },
    Fixture {
        kind: ProjectInputKind::PyProjectPoetry,
        manifest: "pyproject.toml",
        content: "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\n\n[tool.poetry.dependencies]\npython = \"3.11.0\"\nrequests = \"2.31.0\"\n",
    },
    Fixture {
        kind: ProjectInputKind::PyProjectUv,
        manifest: "pyproject.toml",
        content: "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n\n[tool.uv]\n",
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
    if let (Some(name), Some(content)) = (fixture.kind.descriptor().lockfile_name, lockfile) {
        std::fs::write(dir.join(name), content).unwrap();
    }
    dir
}

fn blocks(dir: &Path) -> bool {
    match crate::preflight_scan_inputs(dir, None) {
        Err(_) => true,
        Ok(issues) => issues.iter().any(|issue| issue.severity == Severity::Error),
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
    for fixture in FIXTURES {
        let dir = fixture_dir(fixture, None);
        assert!(
            blocks(&dir),
            "{:?} must block without a lockfile",
            fixture.kind
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn a_malformed_lockfile_blocks() {
    for fixture in FIXTURES {
        let dir = fixture_dir(fixture, Some("\u{1}{ not a lockfile ]["));
        assert!(
            blocks(&dir),
            "{:?} must block on a malformed lockfile",
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
