//! The Cargo, Go, Composer and Python rows of the fixability catalog, end to end through the real
//! plugins with a fake package manager (docs/specs/fix-lockfile.md).

use super::report::Outcome;
use super::runner::ToolCommand;
use super::tests::*;

fn first(report: &super::report::FixReport) -> &super::report::ProjectFix {
    &report.projects[0]
}

#[test]
fn cargo_workspace_members_are_copied_with_placeholder_targets() {
    let root = "[workspace]\nmembers = [\"crates/a\"]\nresolver = \"2\"\n";
    let member = "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"=1.0.10\"\n";
    let dir = project(&[("Cargo.toml", root), ("crates/a/Cargo.toml", member)]);
    let lock: &'static str = CARGO_LOCK.replace("name = \"app\"", "name = \"a\"").leak();
    let runner = FakeRunner::default().with(
        "cargo",
        Some("cargo 1.96.0"),
        Box::new(move |command: &ToolCommand| {
            assert!(command.cwd.join("crates/a/Cargo.toml").is_file());
            let placeholder = command.cwd.join("crates/a/src/lib.rs");
            assert_eq!(std::fs::read_to_string(placeholder).unwrap(), "");
            assert!(!command.cwd.join("src/lib.rs").exists(), "a virtual root has no target");
            std::fs::write(command.cwd.join("Cargo.lock"), lock).unwrap();
            ok()
        }),
    );
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    assert!(run.report.success(), "{:#?}", run.report.projects);
    assert_eq!(std::fs::read_to_string(dir.join("Cargo.lock")).unwrap(), lock);
    assert!(!dir.join("crates/a/src").exists(), "placeholders never reach the working tree");
}

#[test]
fn cargo_configuration_that_runs_code_is_refused() {
    let dir = project(&[
        ("Cargo.toml", CARGO_TOML),
        (".cargo/config.toml", "[build]\nrustc-wrapper = \"./wrap.sh\"\n"),
    ]);
    let runner = FakeRunner::default().with("cargo", Some("cargo 1.96.0"), writes(&[("Cargo.lock", CARGO_LOCK)]));
    // The scan itself refuses this configuration while discovering the project, as `check` does.
    let (report, _) = try_fix(&dir, true, &runner, &FakeRescan::default());
    let error = format!("{:#}", report.unwrap_err());
    assert!(error.contains("build.rustc-wrapper"), "{error}");
    assert!(runner.runs().is_empty(), "cargo never runs beside a wrapper setting");
    assert!(!dir.join("Cargo.lock").exists());
}

#[test]
fn reviewed_cargo_configuration_is_copied() {
    let config = "[net]\nretry = 3\n";
    let dir = project(&[("Cargo.toml", CARGO_TOML), (".cargo/config.toml", config)]);
    let runner = FakeRunner::default().with(
        "cargo",
        Some("cargo 1.96.0"),
        Box::new(move |command: &ToolCommand| {
            assert_eq!(
                std::fs::read_to_string(command.cwd.join(".cargo/config.toml")).unwrap(),
                config
            );
            std::fs::write(command.cwd.join("Cargo.lock"), CARGO_LOCK).unwrap();
            ok()
        }),
    );
    let run = fix(&dir, false, &runner, &FakeRescan::default());
    assert_eq!(first(&run.report).result, Outcome::Verified, "{:#?}", run.report.projects);
}

const GO_MOD: &str = "module example.com/app\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n";
const GO_SUM_PARTIAL: &str = "github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=\n";
const GO_SUM_FULL: &str = "github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=\ngithub.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=\n";

#[test]
fn missing_go_sum_entries_are_downloaded_with_the_checksum_database_on() {
    let dir = project(&[("go.mod", GO_MOD), ("go.sum", GO_SUM_PARTIAL)]);
    let runner = FakeRunner::default().with("go", Some("go version go1.27.3 darwin/arm64"), writes(&[("go.sum", GO_SUM_FULL)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.problems[0].name, "go-sum");
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    let command = &runner.runs()[0];
    assert_eq!(command.args, ["mod", "download", "all"]);
    let env: std::collections::HashMap<_, _> = command.env.iter().cloned().collect();
    assert_eq!(env["GOTOOLCHAIN"], "local");
    assert_eq!(env["GOSUMDB"], "sum.golang.org");
    assert_eq!(project.diff.as_ref().unwrap().added, vec!["github.com/google/uuid@v1.6.0".to_string()]);
    assert_eq!(std::fs::read_to_string(dir.join("go.sum")).unwrap(), GO_SUM_FULL);
}

#[test]
fn a_go_toolchain_directive_is_never_run() {
    let go_mod = "module example.com/app\n\ngo 1.22\n\ntoolchain go1.23.1\n\nrequire github.com/google/uuid v1.6.0\n";
    let dir = project(&[("go.mod", go_mod), ("go.sum", GO_SUM_PARTIAL)]);
    let runner = FakeRunner::default().with("go", Some("go version go1.27.3"), writes(&[("go.sum", GO_SUM_FULL)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert!(!project.result.is_success(), "{project:#?}");
    assert!(runner.runs().is_empty());
}

const COMPOSER_JSON: &str = r#"{"name":"fixture/app","require":{"monolog/monolog":"3.6.0"}}"#;
const COMPOSER_LOCK: &str = r#"{"_readme":["fixture"],"content-hash":"x","packages":[{"name":"monolog/monolog","version":"3.6.0"}],"packages-dev":[]}"#;

#[test]
fn a_missing_composer_lockfile_is_resolved_without_scripts_plugins_or_install() {
    let dir = project(&[("composer.json", COMPOSER_JSON)]);
    let runner = FakeRunner::default().with("composer", Some("Composer version 2.10.3"), writes(&[("composer.lock", COMPOSER_LOCK)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    let args = &runner.runs()[0].args;
    for flag in ["--no-install", "--no-scripts", "--no-plugins"] {
        assert!(args.contains(&flag.to_string()), "{args:?}");
    }
    assert!(!args.contains(&"--lock".to_string()), "nothing is locked yet");
}

const UV_PYPROJECT: &str = "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.11\"\ndependencies = [\"six==1.16.0\"]\n\n[tool.uv]\n";

fn uv_lock(wheels: bool) -> String {
    let wheels = if wheels {
        "wheels = [\n    { url = \"https://files.pythonhosted.org/packages/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:2222222222222222222222222222222222222222222222222222222222222222\", size = 1 },\n]\n"
    } else {
        ""
    };
    format!(
        "version = 1\nrequires-python = \">=3.11\"\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = {{ virtual = \".\" }}\ndependencies = [{{ name = \"six\" }}]\n\n[package.metadata]\nrequires-dist = [{{ name = \"six\", specifier = \"==1.16.0\" }}]\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nsdist = {{ url = \"https://files.pythonhosted.org/packages/six-1.16.0.tar.gz\", hash = \"sha256:1111111111111111111111111111111111111111111111111111111111111111\", size = 1 }}\n{wheels}"
    )
}

#[test]
fn a_missing_uv_lockfile_is_locked_without_building() {
    let dir = project(&[("pyproject.toml", UV_PYPROJECT)]);
    let lock: &'static str = uv_lock(true).leak();
    let runner = FakeRunner::default().with("uv", Some("uv 0.11.19"), writes(&[("uv.lock", lock)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    let command = &runner.runs()[0];
    assert!(command.args.contains(&"--no-build".to_string()));
    let env: std::collections::HashMap<_, _> = command.env.iter().cloned().collect();
    assert_eq!(env["UV_NO_BUILD"], "1");
    assert_eq!(env["UV_PYTHON_DOWNLOADS"], "never");
}

#[test]
fn a_locked_package_without_a_wheel_is_never_resolved() {
    let stale = UV_PYPROJECT.replace("[\"six==1.16.0\"]", "[\"six==1.16.0\", \"idna==3.7\"]");
    let dir = project(&[("pyproject.toml", stale.as_str()), ("uv.lock", uv_lock(false).as_str())]);
    let runner = FakeRunner::default().with("uv", Some("uv 0.11.19"), writes(&[]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert!(!project.result.is_success(), "{project:#?}");
    assert!(runner.runs().is_empty());
    if project.problems.iter().any(|p| p.class == "guided") {
        let reason = project.problems[0].reason.as_deref().unwrap_or_default();
        assert!(reason.contains("no wheel"), "{reason}");
    }
}

fn assert_guided(files: &[(&str, &str)], command: &str, why: &str) {
    let dir = project(files);
    let runner = FakeRunner::default();
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Guided, "{project:#?}");
    assert_eq!(project.problems[0].command.as_deref(), Some(command), "{project:#?}");
    assert!(project.problems[0].reason.as_deref().unwrap().contains(why), "{project:#?}");
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[test]
fn gradle_and_dotnet_lockfiles_are_guided_because_their_tools_run_repository_code() {
    assert_guided(
        &[(
            "build.gradle",
            "plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencyLocking { lockAllConfigurations() }\ndependencies { implementation 'com.google.guava:guava:33.0.0-jre' }\n",
        )],
        "gradle dependencies --write-locks",
        "build scripts",
    );
    assert_guided(
        &[(
            "app.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n  </PropertyGroup>\n  <ItemGroup>\n    <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />\n  </ItemGroup>\n</Project>\n",
        )],
        "dotnet restore --use-lock-file",
        "MSBuild",
    );
}

const POETRY_PYPROJECT: &str = "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = []\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nsix = \"1.16.0\"\n\n[build-system]\nrequires = [\"poetry-core\"]\nbuild-backend = \"poetry.core.masonry.api\"\n";

#[test]
fn poetry_without_a_lockfile_is_guided_because_it_may_build_sdists() {
    let dir = project(&[("pyproject.toml", POETRY_PYPROJECT)]);
    let runner = FakeRunner::default().with("poetry", Some("Poetry (version 2.4.1)"), writes(&[]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Guided, "{project:#?}");
    assert_eq!(project.problems[0].command.as_deref(), Some("poetry lock --no-plugins"));
    assert!(project.problems[0].reason.as_deref().unwrap().contains("source distribution"));
    assert!(runner.runs().is_empty());
}
