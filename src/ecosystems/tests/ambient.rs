//! Conformance for the ambient-input tables: every plugin states its surface, and every row that
//! is not `Irrelevant` has a fixture proving what the scan does with a matching file.

use super::*;
use crate::ecosystems::ambient::{Disposition, Scope};

/// One fixture per table row, keyed by plugin kind and pattern.
struct Probe {
    kind: ProjectInputKind,
    pattern: &'static str,
    /// Files created next to the manifest (or at the repository root when `at_root`).
    files: &'static [(&'static str, &'static str)],
    /// Text the block message contains. For `ModeledElsewhere` rows it must come from the check
    /// the row names, so a block for another reason (a missing lockfile) cannot satisfy it.
    expect: &'static str,
    at_root: bool,
}

const fn probe(
    kind: ProjectInputKind,
    pattern: &'static str,
    files: &'static [(&'static str, &'static str)],
    expect: &'static str,
) -> Probe {
    Probe {
        kind,
        pattern,
        files,
        expect,
        at_root: false,
    }
}

const fn at_root(mut p: Probe) -> Probe {
    p.at_root = true;
    p
}

use ProjectInputKind as K;

const GO_SUM: &str = "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\ngithub.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n";

const NPM_LOCK: &str = r#"{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx4HLj7TpdiZhIYNVMe9OcVZ8Ag=="}}}"#;

const UV_BAD: &str = "index-url = \"https://evil.example/simple\"\n";

#[rustfmt::skip]
const PROBES: &[Probe] = &[
    // Python
    probe(K::PyProjectUv, ".python-version", &[(".python-version", "./tools/python3\n")], "Unsupported interpreter request"),
    probe(K::PyProjectUv, ".venv/pyvenv.cfg", &[(".venv/pyvenv.cfg", "home = /usr\n")], ""),
    probe(K::PyProjectUv, ".venv/bin/python", &[(".venv/bin/python", "#!/bin/sh\n")], ""),
    probe(K::PyPipfile, ".env", &[(".env", "PYTHONPATH=./x\n")], "Unsupported variable"),
    probe(K::PyProjectUv, "poetry.toml", &[("poetry.toml", "cache-dir = \".pcache\"\n")], "Unsupported Poetry setting"),
    probe(K::PyProjectUv, "uv.toml", &[("uv.toml", UV_BAD)], "Unsupported uv setting"),
    at_root(probe(K::PyProjectUv, "pyproject.toml", &[("pyproject.toml", "[tool.uv]\nindex-url = \"https://evil.example/simple\"\n")], "Unsupported uv setting")),
    probe(K::PyProjectUv, "pdm.toml", &[("pdm.toml", "[pypi]\nurl = \"https://evil.example/simple\"\n")], "Unsupported PDM configuration"),
    probe(K::PyProjectUv, ".pdm.toml", &[(".pdm.toml", "[pypi]\nurl = \"https://evil.example/simple\"\n")], "Unsupported PDM configuration"),
    probe(K::PyProjectUv, "hatch.toml", &[("hatch.toml", "[envs.default]\ndependencies = [\"evil\"]\n")], "hatch"),
    probe(K::PyRequirements, "tox.ini", &[("tox.ini", "[testenv]\ndeps = evil\n")], "tox"),
    probe(K::PyRequirements, "tox.toml", &[("tox.toml", "env_run_base = { deps = [\"evil\"] }\n")], "tox"),
    probe(K::PySetupCfg, "setup.cfg", &[("setup.cfg", "[options]\rinstall_requires = evil\n")], "line"),
    probe(K::PySetupPy, "setup.py", &[("setup.py", "from setuptools import setup\rsetup(name='a')\n")], "line"),
    // Cargo
    probe(K::Cargo, ".cargo/config.toml", &[(".cargo/config.toml", "[build]\nrustc-wrapper = \"tools/wrap.sh\"\n")], "rustc-wrapper"),
    probe(K::Cargo, ".cargo/config", &[(".cargo/config", "[build]\nrustc-wrapper = \"tools/wrap.sh\"\n")], "rustc-wrapper"),
    probe(K::Cargo, "rust-toolchain.toml", &[("rust-toolchain.toml", "[toolchain]\npath = \"tools/rust\"\n")], "rustup toolchain path"),
    probe(K::Cargo, "rust-toolchain", &[("rust-toolchain", "[toolchain]\npath = \"tools/rust\"\n")], "rustup toolchain path"),
    // Go
    probe(K::Go, "go.work", &[("go.work", "go 1.21\nuse .\n")], "workspace dependency sources"),
    probe(K::Go, "go.sum", &[("go.sum", "not a checksum line\n")], "Broken lockfile"),
    probe(K::Go, "vendor/modules.txt", &[("go.sum", GO_SUM), ("vendor/modules.txt", "# example.com/unrelated v1.0.0\n")], "vendor"),
    // Ruby
    probe(K::Ruby, ".bundle/config", &[(".bundle/config", "---\nBUNDLE_MIRROR__ALL: \"https://evil.example\"\n")], "registry mirrors"),
    probe(K::Ruby, "*.gemspec", &[("app.gemspec", "Gem::Specification.new { |s| s.send(:dependency_x) }\n"), ("Gemfile", "source 'https://rubygems.org'\ngemspec\n")], "gemspec"),
    probe(K::Ruby, "gems.rb", &[("gems.rb", "source 'https://rubygems.org'\n")], "Unsupported Bundler file"),
    probe(K::Ruby, "gems.locked", &[("gems.locked", "GEM\n")], "Unsupported Bundler file"),
    probe(K::Ruby, "vendor/cache", &[("vendor/cache/rake-13.0.6.gem", "x")], ""),
    // PHP
    probe(K::Php, "vendor/composer/installed.json", &[("vendor/composer/installed.json", "{\"packages\":[]}")], ""),
    // JVM
    probe(K::Gradle, "gradle.properties", &[("gradle.properties", "systemProp.javax.net.ssl.trustStore=certs/store.jks\n")], "trustStore"),
    probe(K::Gradle, "gradle/wrapper/gradle-wrapper.properties", &[("gradle/wrapper/gradle-wrapper.properties", "distributionUrl=https\\://evil.example/gradle.zip\n")], "Untrusted Gradle wrapper"),
    probe(K::Gradle, "gradle/gradle-daemon-jvm.properties", &[("gradle/gradle-daemon-jvm.properties", "toolchainUrl.MAC_OS.AARCH64=https\\://evil.example/jdk.tgz\n")], "toolchainUrl"),
    probe(K::Gradle, "settings.gradle", &[("settings.gradle", "buildCache { local { directory = file('bc') } }\n")], "Unsupported Gradle build cache"),
    probe(K::Gradle, "settings.gradle.kts", &[("settings.gradle.kts", "buildCache { local { directory = file(\"bc\") } }\n")], "Unsupported Gradle build cache"),
    probe(K::Gradle, "buildSrc", &[("buildSrc/src/main/java/A.java", "class A {}\n")], "buildSrc"),
    probe(K::Maven, ".mvn/extensions.xml", &[(".mvn/extensions.xml", "<extensions/>")], "extensions.xml"),
    probe(K::Maven, ".mvn/settings.xml", &[(".mvn/settings.xml", "<settings/>")], "settings.xml"),
    probe(K::Maven, ".mvn/toolchains.xml", &[(".mvn/toolchains.xml", "<toolchains/>")], "toolchains.xml"),
    probe(K::Maven, ".mvn/maven-build-cache-config.xml", &[(".mvn/maven-build-cache-config.xml", "<cache/>")], "build cache"),
    probe(K::Maven, ".mvn/maven.config", &[(".mvn/maven.config", "-Dmaven.repo.local=.m2\n")], "maven.repo.local"),
    probe(K::Maven, ".mvn/jvm.config", &[(".mvn/jvm.config", "-Duser.home=.\n")], "user.home"),
    probe(K::Maven, ".mvn/wrapper/maven-wrapper.properties", &[(".mvn/wrapper/maven-wrapper.properties", "distributionUrl=https://evil.example/maven.zip\n")], "Untrusted Maven wrapper"),
    probe(K::Gradle, "gradle/verification-metadata.xml", &[("gradle/verification-metadata.xml", "<verification-metadata><configuration><verify-metadata>false</verify-metadata></configuration></verification-metadata>")], "dependency verification"),
    probe(K::Gradle, "gradle/*.versions.toml", &[("gradle/libs.versions.toml", "[versions]\na = \"1\"\na = \"2\"\n")], "version catalog"),
    probe(K::Gradle, "init.gradle", &[("init.gradle", "allprojects { }\n")], ""),
    probe(K::Gradle, "init.gradle.kts", &[("init.gradle.kts", "allprojects { }\n")], ""),
    probe(K::Gradle, "init.d/*", &[("init.d/a.gradle", "allprojects { }\n")], ""),
    // JavaScript
    probe(K::Npm, ".pnp.cjs", &[(".pnp.cjs", "module.exports = {};\n")], ""),
    probe(K::Npm, ".pnp.loader.mjs", &[(".pnp.loader.mjs", "export {};\n")], ""),
    probe(K::Npm, ".npmrc", &[(".npmrc", "strict-ssl=false\n"), ("package-lock.json", NPM_LOCK)], "strict-ssl"),
    probe(K::Npm, ".yarnrc.yml", &[(".yarnrc.yml", "yarnPath: .yarn/releases/evil.cjs\n"), ("yarn.lock", "__metadata:\n  version: 8\n  cacheKey: 10c0\n")], "yarnPath"),
    probe(K::Npm, ".yarnrc", &[(".yarnrc", "registry \"https://evil.example\"\n"), ("package-lock.json", NPM_LOCK)], ".yarnrc"),
    probe(K::Npm, ".pnpmfile.*", &[(".pnpmfile.cjs", "module.exports = {}\n"), ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")], "pnpmfile"),
    probe(K::Npm, "pnpm-workspace.yaml", &[("pnpm-workspace.yaml", "overrides:\n  left-pad: 1.0.0\n"), ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")], "pnpm workspace"),
    probe(K::Npm, "bunfig.toml", &[("bunfig.toml", "[install]\nregistry = \"https://evil.example\"\n"), ("bun.lock", "{}")], "registry"),
    // .NET
    probe(K::Dotnet, "Directory.Build.props", &[("Directory.Build.props", "<Project/>")], "Directory.Build.props"),
    probe(K::Dotnet, "Directory.Build.targets", &[("Directory.Build.targets", "<Project/>")], "Directory.Build.targets"),
    probe(K::Dotnet, "Directory.Build.rsp", &[("Directory.Build.rsp", "-p:X=1\n")], "Directory.Build.rsp"),
    probe(K::Dotnet, "Directory.Packages.props", &[("Directory.Packages.props", "<Project/>")], "Directory.Packages.props"),
    probe(K::Dotnet, "Directory.Solution.props", &[("Directory.Solution.props", "<Project/>")], "Directory.Solution.props"),
    probe(K::Dotnet, "Directory.Solution.targets", &[("Directory.Solution.targets", "<Project/>")], "Directory.Solution.targets"),
    probe(K::Dotnet, "nuget.config", &[("nuget.config", "<configuration><packageSources><add key=\"x\" value=\"https://evil.example/v3/index.json\"/></packageSources></configuration>")], "nuget.org v3 feed"),
    probe(K::Dotnet, "global.json", &[("global.json", "{\"msbuild-sdks\":{\"X.Sdk\":\"1.0.0\"}}")], "msbuild-sdks"),
    probe(K::Dotnet, ".config/dotnet-tools.json", &[(".config/dotnet-tools.json", "{\"version\":1,\"tools\":{\"dotnet-ef\":{\"version\":\"9.0.0\",\"commands\":[\"dotnet-ef\"]}}}")], "dotnet tool manifest"),
    probe(K::Dotnet, "*.csproj.user", &[("app.csproj.user", "<Project/>")], "MSBuild user file"),
    probe(K::Dotnet, "obj/*.nuget.g.props", &[("obj/app.csproj.nuget.g.props", "<Project/>")], ""),
    probe(K::Dotnet, "obj/*.nuget.g.targets", &[("obj/app.csproj.nuget.g.targets", "<Project/>")], ""),
    probe(K::Dotnet, "obj/*.props", &[("obj/app.csproj.evil.props", "<Project/>")], "obj"),
    probe(K::Dotnet, "obj/*.targets", &[("obj/app.csproj.evil.targets", "<Project/>")], "obj"),
];

const MANIFESTS: &[(ProjectInputKind, &str, &str)] = &[
    (
        K::PySetupPy,
        "setup.py",
        "from setuptools import setup\nsetup(name='a', install_requires=['requests==2.31.0'])\n",
    ),
    (
        K::PySetupCfg,
        "setup.cfg",
        "[options]\ninstall_requires =\n    requests==2.31.0\n",
    ),
    (K::PyRequirements, "requirements.txt", "requests==2.31.0\n"),
    (
        K::Npm,
        "package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    ),
    (
        K::Cargo,
        "Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.200\"\n",
    ),
    (
        K::Go,
        "go.mod",
        "module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
    ),
    (
        K::Ruby,
        "Gemfile",
        "source 'https://rubygems.org'\ngem 'rake', '13.0.6'\n",
    ),
    (
        K::Php,
        "composer.json",
        r#"{"require":{"monolog/monolog":"3.5.0"}}"#,
    ),
    (
        K::Gradle,
        "build.gradle",
        "dependencyLocking { lockAllConfigurations() }\ndependencies {\n    implementation 'com.google.guava:guava:33.0.0-jre'\n}\n",
    ),
    (
        K::Maven,
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>33.0.0-jre</version></dependency></dependencies></project>",
    ),
    (
        K::Dotnet,
        "app.csproj",
        r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
    ),
    (
        K::PyProjectUv,
        "pyproject.toml",
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n\n[tool.uv]\n",
    ),
    (
        K::PyPipfile,
        "Pipfile",
        "[packages]\nrequests = \"==2.31.0\"\n",
    ),
];

struct Fixture {
    repo: PathBuf,
    project: PathBuf,
    spec: ProjectInputSpec,
}

fn fixture(kind: ProjectInputKind) -> Fixture {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let repo = std::env::temp_dir().join(format!(
        "sj-ambient-conf-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let project = repo.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let (_, name, content) = MANIFESTS
        .iter()
        .find(|(k, _, _)| *k == kind)
        .unwrap_or_else(|| panic!("no manifest for {kind:?}"));
    std::fs::write(project.join(name), content).unwrap();
    let repo = std::fs::canonicalize(repo).unwrap();
    let project = repo.join("app");
    let spec = ProjectInputSpec {
        kind,
        manifest_path: project.join(name),
        lockfile_path_override: None,
        js_binding: None,
    };
    Fixture {
        repo,
        project,
        spec,
    }
}

fn place(base: &Path, relative: &str, content: &str) {
    let path = base.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn plugin_rows() -> Vec<(
    &'static dyn EcosystemSupport,
    &'static ambient::AmbientInput,
)> {
    all()
        .iter()
        .flat_map(|plugin| {
            plugin
                .ambient_inputs()
                .iter()
                .map(move |row| (*plugin, row))
        })
        .collect()
}

/// The kind a fixture for `row` uses: the row's own, else the plugin's first.
fn kind_of(plugin: &dyn EcosystemSupport, row: &ambient::AmbientInput) -> ProjectInputKind {
    row.kinds.first().copied().unwrap_or(plugin.kinds()[0])
}

fn probe_for(plugin: &dyn EcosystemSupport, row: &ambient::AmbientInput) -> &'static Probe {
    // Python's rows apply to every Python kind; its fixtures use the uv project.
    let wanted = kind_of(plugin, row);
    PROBES
        .iter()
        .find(|p| p.pattern == row.pattern && plugin.kinds().contains(&p.kind))
        .filter(|p| row.kinds.is_empty() || row.kinds.contains(&p.kind) || p.kind == wanted)
        .unwrap_or_else(|| {
            panic!(
                "add a conformance probe for {:?} row '{}'",
                wanted, row.pattern
            )
        })
}

fn ci_options() -> ScanOptions<'static> {
    ScanOptions {
        scan_mode: ScanMode::Ci,
        ..ScanOptions::default()
    }
}

/// Why the full preflight of `project` blocks (an error, or an Error-severity issue).
fn preflight_block(project: &Path) -> Option<String> {
    let config = config::SloppyJoeConfig::default();
    let specs = match crate::detected_project_inputs_with_config(project, None, &config) {
        Ok(specs) => specs,
        Err(err) => return Some(format!("{err:#}")),
    };
    match crate::preflight_project_inputs_with_options(project, &specs, &config, &ci_options()) {
        Err(err) => Some(format!("{err:#}")),
        Ok(issues) => issues
            .iter()
            .find(|issue| issue.severity == Severity::Error)
            .map(|issue| issue.message.clone()),
    }
}

fn walker_block(plugin: &dyn EcosystemSupport, spec: &ProjectInputSpec) -> Option<String> {
    match ambient::check(plugin.ambient_inputs(), spec, true) {
        Err(err) => Some(format!("{err:#}")),
        Ok(issues) => issues
            .iter()
            .find(|issue| issue.severity == Severity::Error)
            .map(|issue| issue.message.clone()),
    }
}

fn index_listing(paths: &[&str]) -> Vec<u8> {
    let mut bytes = b"DIRC\0\0\0\x02".to_vec();
    for path in paths {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
    }
    bytes
}

fn lay_out(fx: &Fixture, probe: &Probe) {
    let base = if probe.at_root { &fx.repo } else { &fx.project };
    for (relative, content) in probe.files {
        place(base, relative, content);
    }
}

#[test]
fn every_plugin_states_a_non_empty_surface_with_reasons() {
    for plugin in all() {
        let rows = plugin.ambient_inputs();
        assert!(
            !rows.is_empty(),
            "{:?} has no ambient inputs",
            plugin.kinds()
        );
        for row in rows {
            assert!(!row.pattern.is_empty() && !row.pattern.starts_with('/'));
            match row.disposition {
                Disposition::Irrelevant(reason) | Disposition::ModeledElsewhere(reason) => {
                    assert!(reason.len() > 12, "'{}' needs a real reason", row.pattern);
                }
                Disposition::Blocked(reason) | Disposition::BlockedIfTracked(reason) => {
                    assert!(reason.len() > 12, "'{}' needs a real reason", row.pattern);
                }
                Disposition::Modeled(_) => {}
            }
            for kind in row.kinds {
                assert!(
                    plugin.kinds().contains(kind),
                    "'{}' names a foreign kind",
                    row.pattern
                );
            }
        }
    }
}

#[test]
fn every_row_that_is_not_irrelevant_has_a_probe_and_probes_have_rows() {
    for (plugin, row) in plugin_rows() {
        if !matches!(row.disposition, Disposition::Irrelevant(_)) {
            probe_for(plugin, row);
        }
    }
    for p in PROBES {
        assert!(
            plugin_rows()
                .iter()
                .any(|(plugin, row)| row.pattern == p.pattern && plugin.kinds().contains(&p.kind)),
            "probe '{}' matches no row",
            p.pattern
        );
    }
}

#[test]
fn matching_files_get_the_declared_verdict() {
    let mut failures = Vec::new();
    for (plugin, row) in plugin_rows() {
        let probe = match row.disposition {
            Disposition::Irrelevant(_) => continue,
            _ => probe_for(plugin, row),
        };
        let fx = fixture(probe.kind);
        let contains =
            |reason: &Option<String>| reason.as_deref().is_some_and(|r| r.contains(probe.expect));
        match row.disposition {
            Disposition::Blocked(_) | Disposition::Modeled(_) => {
                lay_out(&fx, probe);
                let reason = walker_block(plugin, &fx.spec);
                if !contains(&reason) {
                    failures.push(format!(
                        "{}: want {:?}, got {reason:?}",
                        row.pattern, probe.expect
                    ));
                }
            }
            Disposition::BlockedIfTracked(_) => {
                lay_out(&fx, probe);
                let listed: Vec<String> = probe
                    .files
                    .iter()
                    .map(|(f, _)| {
                        if probe.at_root {
                            f.to_string()
                        } else {
                            format!("app/{f}")
                        }
                    })
                    .collect();
                let listed: Vec<&str> = listed.iter().map(String::as_str).collect();
                std::fs::write(fx.repo.join(".git/index"), index_listing(&listed)).unwrap();
                if walker_block(plugin, &fx.spec).is_none() {
                    failures.push(format!("{}: tracked file did not block", row.pattern));
                }
                std::fs::write(fx.repo.join(".git/index"), index_listing(&["unrelated"])).unwrap();
                if walker_block(plugin, &fx.spec).is_some() {
                    failures.push(format!("{}: untracked file blocked", row.pattern));
                }
                std::fs::remove_file(fx.repo.join(".git/index")).unwrap();
                if walker_block(plugin, &fx.spec).is_none() {
                    failures.push(format!(
                        "{}: undecidable did not block under --ci",
                        row.pattern
                    ));
                }
            }
            Disposition::ModeledElsewhere(_) => {
                let before = preflight_block(&fx.project);
                if contains(&before) {
                    failures.push(format!(
                        "{}: the baseline already says {:?}",
                        row.pattern, probe.expect
                    ));
                }
                lay_out(&fx, probe);
                let reason = preflight_block(&fx.project);
                if !contains(&reason) {
                    failures.push(format!(
                        "{}: want {:?}, got {reason:?}",
                        row.pattern, probe.expect
                    ));
                }
            }
            Disposition::Irrelevant(_) => unreachable!(),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Rows the walker itself enforces (`Blocked`, `Modeled`) behave the same for a case variant, a
/// copy in a parent directory (when the scope reaches it) and a symlink to a matching file.
#[test]
fn case_ancestor_and_symlink_variants_are_treated_alike() {
    for (plugin, row) in plugin_rows() {
        if !matches!(
            row.disposition,
            Disposition::Blocked(_) | Disposition::Modeled(_)
        ) || row.pattern.contains('*')
        {
            continue;
        }
        let probe = probe_for(plugin, row);
        // Case variant.
        let fx = fixture(probe.kind);
        let upper: Vec<(String, &str)> = probe
            .files
            .iter()
            .map(|(f, c)| (f.to_uppercase(), *c))
            .collect();
        let base = if probe.at_root { &fx.repo } else { &fx.project };
        for (f, c) in &upper {
            place(base, f, c);
        }
        assert!(
            walker_block(plugin, &fx.spec).is_some(),
            "{}: case variant",
            row.pattern
        );

        // Ancestor copy.
        if row.scope == Scope::AncestorsToRepoRoot && !probe.at_root {
            let fx = fixture(probe.kind);
            for (f, c) in probe.files {
                place(&fx.repo, f, c);
            }
            assert!(
                walker_block(plugin, &fx.spec).is_some(),
                "{}: ancestor",
                row.pattern
            );
        }

        // Symlink to a matching file under another name.
        #[cfg(unix)]
        if !row.pattern.contains('/') {
            let fx = fixture(probe.kind);
            let (name, content) = probe.files[0];
            place(&fx.project, &format!("real/{name}"), content);
            std::os::unix::fs::symlink(
                fx.project.join("real").join(name),
                fx.project.join("innocent-link"),
            )
            .unwrap();
            assert!(
                walker_block(plugin, &fx.spec).is_some(),
                "{}: symlink",
                row.pattern
            );
        }
    }
}
