//! The `lockfile_data` stage must read the project's lockfile: a valid lockfile that pins a package
//! the manifest does not declare has to surface that package as a transitive dependency. A plugin
//! that fell back to manifest-only data would silently scan the direct dependencies alone.

use super::*;

struct LockedProject {
    kind: ProjectInputKind,
    manifest: &'static str,
    manifest_content: &'static str,
    lockfile: &'static str,
    lockfile_content: &'static str,
    /// Pinned by the lockfile, declared nowhere in the manifest. `None` when the lockfile format
    /// records no dependency graph (go.sum is checksums only).
    transitive: Option<&'static str>,
}

const LOCKED: &[LockedProject] = &[
    LockedProject {
        kind: ProjectInputKind::Npm,
        manifest: "package.json",
        manifest_content: r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
        lockfile: "package-lock.json",
        lockfile_content: r#"{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0","dependencies":{"deep-transitive":"2.0.0"}},"node_modules/deep-transitive":{"version":"2.0.0"}}}"#,
        transitive: Some("deep-transitive"),
    },
    LockedProject {
        kind: ProjectInputKind::Cargo,
        manifest: "Cargo.toml",
        manifest_content: "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.200\"\n",
        lockfile: "Cargo.lock",
        lockfile_content: "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"serde\"]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"0000000000000000000000000000000000000000000000000000000000000000\"\ndependencies = [\"deep-transitive\"]\n\n[[package]]\nname = \"deep-transitive\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"1111111111111111111111111111111111111111111111111111111111111111\"\n",
        transitive: Some("deep-transitive"),
    },
    LockedProject {
        kind: ProjectInputKind::Go,
        manifest: "go.mod",
        manifest_content: "module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
        lockfile: "go.sum",
        lockfile_content: "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\ngithub.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\ngithub.com/deep/transitive v2.0.0 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\ngithub.com/deep/transitive v2.0.0/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n",
        transitive: None,
    },
    LockedProject {
        kind: ProjectInputKind::Ruby,
        manifest: "Gemfile",
        manifest_content: "source 'https://rubygems.org'\ngem 'rake', '13.0.6'\n",
        lockfile: "Gemfile.lock",
        lockfile_content: "GEM\n  remote: https://rubygems.org/\n  specs:\n    deep-transitive (2.0.0)\n    rake (13.0.6)\n      deep-transitive\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake (= 13.0.6)\n",
        transitive: Some("deep-transitive"),
    },
    LockedProject {
        kind: ProjectInputKind::Php,
        manifest: "composer.json",
        manifest_content: r#"{"require":{"monolog/monolog":"3.5.0"}}"#,
        lockfile: "composer.lock",
        lockfile_content: r#"{"packages":[{"name":"monolog/monolog","version":"3.5.0","source":{"type":"git","url":"https://github.com/Seldaek/monolog.git","reference":"abc"},"dist":{"type":"zip","url":"https://api.github.com/repos/Seldaek/monolog/zipball/abc","reference":"abc"}},{"name":"deep/transitive","version":"2.0.0","source":{"type":"git","url":"https://github.com/deep/transitive.git","reference":"def"},"dist":{"type":"zip","url":"https://api.github.com/repos/deep/transitive/zipball/def","reference":"def"}}],"packages-dev":[]}"#,
        transitive: Some("deep/transitive"),
    },
    LockedProject {
        kind: ProjectInputKind::Gradle,
        manifest: "build.gradle",
        manifest_content: "dependencies {\n    implementation 'com.google.guava:guava:33.0.0-jre'\n}\n",
        lockfile: "gradle.lockfile",
        lockfile_content: "com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath\ncom.deep:transitive:2.0.0=compileClasspath,runtimeClasspath\nempty=\n",
        transitive: Some("com.deep:transitive"),
    },
    LockedProject {
        kind: ProjectInputKind::Dotnet,
        manifest: "app.csproj",
        manifest_content: r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
        lockfile: "packages.lock.json",
        lockfile_content: r#"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1","contentHash":"abc"},"Deep.Transitive":{"type":"Transitive","resolved":"2.0.0","contentHash":"def"}}}}"#,
        transitive: Some("Deep.Transitive"),
    },
    LockedProject {
        kind: ProjectInputKind::PyProjectPoetry,
        manifest: "pyproject.toml",
        manifest_content: "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\n\n[tool.poetry.dependencies]\npython = \"3.11.0\"\nrequests = \"2.31.0\"\n",
        lockfile: "poetry.lock",
        lockfile_content: "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ndescription = \"x\"\noptional = false\npython-versions = \">=3.7\"\nfiles = [\n    {file = \"requests-2.31.0-py3-none-any.whl\", hash = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"},\n]\n\n[package.dependencies]\ndeep-transitive = \">=2.0\"\n\n[[package]]\nname = \"deep-transitive\"\nversion = \"2.0.0\"\ndescription = \"x\"\noptional = false\npython-versions = \">=3.7\"\nfiles = [\n    {file = \"deep_transitive-2.0.0-py3-none-any.whl\", hash = \"sha256:1111111111111111111111111111111111111111111111111111111111111111\"},\n]\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.11\"\ncontent-hash = \"__CONTENT_HASH__\"\n",
        transitive: Some("deep-transitive"),
    },
    LockedProject {
        kind: ProjectInputKind::PyProjectUv,
        manifest: "pyproject.toml",
        manifest_content: "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n\n[tool.uv]\n",
        lockfile: "uv.lock",
        lockfile_content: "version = 1\nrequires-python = \">=3.11\"\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\ndependencies = [\n    { name = \"requests\" },\n]\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n    { name = \"deep-transitive\" },\n]\n\n[[package]]\nname = \"deep-transitive\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
        transitive: Some("deep-transitive"),
    },
];

#[test]
fn every_lockfile_backed_kind_has_a_locked_project_fixture() {
    for kind in ProjectInputKind::ALL {
        if kind.descriptor().lockfile == LockfilePolicy::Required {
            assert!(
                LOCKED.iter().any(|row| row.kind == kind),
                "add a lockfile_data fixture for {kind:?}"
            );
        }
    }
}

/// Parse the row's project with `mutate` applied to its lockfile text and return the sorted names
/// of the direct and the lockfile-reported transitive dependencies.
fn locked_names(row: &LockedProject, mutate: &dyn Fn(&str) -> String) -> Result<Vec<String>> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let config = config::SloppyJoeConfig::default();
    let opts = ScanOptions::default();
    let dir = std::env::temp_dir().join(format!(
        "sj-lockdata-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let outcome = (|| {
        std::fs::write(dir.join(row.manifest), row.manifest_content)?;
        // A Poetry lockfile must carry the hash of its pyproject.
        let lockfile = if row.lockfile_content.contains("__CONTENT_HASH__") {
            let hash = crate::lockfiles::python::poetry_content_hash_for_test(row.manifest_content)
                .expect("fixture pyproject hashes");
            row.lockfile_content.replace("__CONTENT_HASH__", &hash)
        } else {
            row.lockfile_content.to_string()
        };
        std::fs::write(dir.join(row.lockfile), mutate(&lockfile))?;
        let spec = ProjectInputSpec {
            kind: row.kind,
            manifest_path: dir.join(row.manifest),
            lockfile_path_override: None,
            js_binding: None,
        };
        let plugin = for_kind(row.kind);
        let scan = ScanCtx {
            scan_root: &dir,
            config: &config,
            opts: &opts,
        };
        let parsed = plugin.parse(&scan, &spec)?;
        let project = ParsedProject {
            spec,
            deps: parsed.deps.clone(),
            python_root_extras: parsed.python_root_extras.clone(),
            unlocked_tooling: false,
        };
        let data = plugin.lockfile_data(&config, &opts, &project, &parsed.deps)?;
        let mut names: Vec<String> = parsed
            .deps
            .iter()
            .chain(data.transitive_deps.iter())
            .map(|dep| dep.package_name().to_string())
            .collect();
        names.sort();
        Ok(names)
    })();
    let _ = std::fs::remove_dir_all(dir);
    outcome
}

#[test]
fn lockfile_data_surfaces_packages_only_the_lockfile_pins() {
    for row in LOCKED {
        let names = locked_names(row, &|text| text.to_string())
            .unwrap_or_else(|err| panic!("{:?}: {err}", row.kind));
        let Some(transitive) = row.transitive else {
            continue;
        };
        assert!(
            names.iter().any(|name| name == transitive),
            "{:?}: lockfile_data must report the lockfile-only package {}, got {names:?}",
            row.kind,
            transitive
        );
    }
}

/// Formatting-only mutations of a lockfile. The scanner may reject a mutation it cannot model, but
/// if it accepts one it must read exactly the same packages: a different reading is a parser
/// differential, the bug class behind most red-team findings.
type Mutation = (&'static str, fn(&str) -> String);

const MUTATIONS: &[Mutation] = &[
    ("crlf", |text| text.replace('\n', "\r\n")),
    ("trailing blank lines", |text| format!("{text}\n\n")),
    ("leading blank line", |text| format!("\n{text}")),
    ("bom", |text| format!("\u{feff}{text}")),
    ("nul", |text| format!("{text}\0")),
    ("lone cr", |text| text.replacen('\n', "\r", 1)),
    ("line separator", |text| text.replacen('\n', "\u{2028}", 1)),
    ("next line", |text| text.replacen('\n', "\u{85}", 1)),
    ("vertical tab", |text| text.replacen('\n', "\u{b}", 1)),
    ("form feed", |text| text.replacen('\n', "\u{c}", 1)),
    ("tab indent", |text| text.replace("  ", "\t")),
];

#[test]
fn formatting_mutations_never_change_what_the_scanner_reads() {
    let mut accepted = 0;
    for row in LOCKED {
        let baseline = locked_names(row, &|text| text.to_string())
            .unwrap_or_else(|err| panic!("{:?}: {err}", row.kind));
        for (name, mutate) in MUTATIONS {
            if let Ok(names) = locked_names(row, mutate) {
                assert_eq!(
                    names, baseline,
                    "{:?}: the '{name}' mutation was accepted but changed the packages read",
                    row.kind
                );
                accepted += 1;
            }
        }
    }
    // Some mutations are harmless (CRLF in JSON); if none were accepted the comparison is vacuous.
    assert!(
        accepted > 0,
        "no mutation was accepted, so nothing was compared"
    );
}

#[test]
fn nul_and_bom_are_never_silently_accepted_in_line_oriented_locks() {
    for row in LOCKED {
        // go.sum is read in the preflight stage (`check_go_sum`), not by this one.
        let line_oriented = matches!(row.kind, ProjectInputKind::Ruby | ProjectInputKind::Gradle);
        if !line_oriented {
            continue;
        }
        for (name, mutate) in MUTATIONS
            .iter()
            .filter(|(n, _)| matches!(*n, "nul" | "bom"))
        {
            assert!(
                locked_names(row, mutate).is_err(),
                "{:?}: a lockfile with a {name} must be refused",
                row.kind
            );
        }
    }
}
