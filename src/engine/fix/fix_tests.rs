//! The whole `fix-lockfile` flow against real project trees, with a fake package manager and a
//! fake rescan (no network, no installed tools).

use super::runner::{ToolCommand, ToolOutput};
use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) fn unique_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sj-fix-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

pub(super) fn project(files: &[(&str, &str)]) -> PathBuf {
    let dir = unique_dir("project");
    for (name, content) in files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    dir
}

type Action = Box<dyn Fn(&ToolCommand) -> ToolOutput + Send + Sync>;

pub(super) struct FakeTool {
    pub(super) version: Option<&'static str>,
    pub(super) action: Action,
}

/// A package manager that writes files into its working directory instead of resolving.
#[derive(Default)]
pub(super) struct FakeRunner {
    pub(super) tools: HashMap<&'static str, FakeTool>,
    pub(super) calls: Mutex<Vec<ToolCommand>>,
}

pub(super) fn ok() -> ToolOutput {
    ToolOutput {
        status: Some(0),
        ..Default::default()
    }
}

/// A tool action that writes `files` (relative to its working directory) and succeeds.
pub(super) fn writes(files: &[(&'static str, &'static str)]) -> Action {
    let files = files.to_vec();
    Box::new(move |command: &ToolCommand| {
        for (name, content) in &files {
            std::fs::write(command.cwd.join(name), content).unwrap();
        }
        ok()
    })
}

impl FakeRunner {
    pub(super) fn with(
        mut self,
        program: &'static str,
        version: Option<&'static str>,
        action: Action,
    ) -> Self {
        self.tools.insert(program, FakeTool { version, action });
        self
    }

    /// The non-`--version` runs.
    pub(super) fn runs(&self) -> Vec<ToolCommand> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.args != ["--version"] && call.args != ["version"])
            .cloned()
            .collect()
    }
}

impl ProcessRunner for FakeRunner {
    fn locate(&self, program: &str) -> Option<PathBuf> {
        (self.tools.contains_key(program) || program == "rustc")
            .then(|| PathBuf::from("/fake/bin").join(program))
    }

    fn search_path(&self) -> String {
        "/fake/bin".to_string()
    }

    fn run(&self, command: &ToolCommand) -> anyhow::Result<ToolOutput> {
        self.calls.lock().unwrap().push(command.clone());
        let name = command
            .program
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let tool = self
            .tools
            .get(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("no fake {name}"))?;
        if command.args == ["--version"] || command.args == ["version"] {
            return Ok(match tool.version {
                Some(version) => ToolOutput {
                    status: Some(0),
                    stdout: version.to_string(),
                    ..Default::default()
                },
                None => ToolOutput {
                    status: Some(1),
                    ..Default::default()
                },
            });
        }
        Ok((tool.action)(command))
    }
}

/// A rescan that returns a fixed report and records the trees it scanned.
#[derive(Default)]
pub(super) struct FakeRescan {
    pub(super) blocking: Option<&'static str>,
    pub(super) scanned: Mutex<Vec<PathBuf>>,
}

#[async_trait::async_trait]
impl CandidateScanner for FakeRescan {
    async fn scan(
        &self,
        root: &std::path::Path,
        _project_type: Option<&str>,
        _config: &config::SloppyJoeConfig,
        cache_dir: &std::path::Path,
    ) -> Result<ScanReport> {
        assert!(cache_dir.is_dir(), "the rescan gets a cache of its own");
        assert!(!root.starts_with(cache_dir));
        self.scanned.lock().unwrap().push(root.to_path_buf());
        let issues = self
            .blocking
            .map(|check| {
                vec![
                    Issue::new("left-pad", check, Severity::Error)
                        .message("known malicious version"),
                ]
            })
            .unwrap_or_default();
        Ok(ScanReport::from_issues_with_review_candidates(
            1,
            issues,
            Vec::new(),
        ))
    }
}

pub(super) struct Run {
    pub(super) report: FixReport,
    pub(super) scratch_parent: PathBuf,
}

pub(super) fn try_fix(
    dir: &std::path::Path,
    write: bool,
    runner: &FakeRunner,
    rescan: &FakeRescan,
) -> (Result<FixReport>, PathBuf) {
    let scratch_parent = unique_dir("scratch");
    let request = FixRequest {
        dir: dir.to_path_buf(),
        project_type: None,
        config: config::SloppyJoeConfig::default(),
        write,
        scratch_parent: scratch_parent.clone(),
        timeout: Duration::from_secs(5),
    };
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(fix_lockfiles(&request, runner, rescan));
    let left: Vec<_> = std::fs::read_dir(&scratch_parent)
        .unwrap()
        .flatten()
        .collect();
    assert!(
        left.is_empty(),
        "the scratch directory is removed on every path: {left:?}"
    );
    (report, scratch_parent)
}

pub(super) fn fix(
    dir: &std::path::Path,
    write: bool,
    runner: &FakeRunner,
    rescan: &FakeRescan,
) -> Run {
    let (report, scratch_parent) = try_fix(dir, write, runner, rescan);
    Run {
        report: report.unwrap(),
        scratch_parent,
    }
}

pub(super) const CARGO_TOML: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"=1.0.10\"\n";
pub(super) const CARGO_LOCK: &str = "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"itoa\",\n]\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.10\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"b1a46d1a171d865aa5f83f92695765caa047a9b4cbae2cbf37dbd613a793fd4c\"\n";

fn cargo_runner(action: Action) -> FakeRunner {
    FakeRunner::default().with("cargo", Some("cargo 1.96.0 (30a34c682 2026-05-25)"), action)
}

fn only(report: &FixReport) -> &ProjectFix {
    assert_eq!(report.projects.len(), 1, "{:#?}", report.projects);
    &report.projects[0]
}

#[test]
fn a_missing_cargo_lockfile_is_generated_verified_and_not_written_without_write() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK)]));
    let rescan = FakeRescan::default();
    let run = fix(&dir, false, &runner, &rescan);
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Verified, "{project:#?}");
    assert_eq!(project.problems[0].class, "fixable");
    assert_eq!(project.problems[0].name, "cargo-generate-lockfile");
    let diff = project.diff.as_ref().unwrap();
    assert!(diff.added.contains(&"itoa@1.0.10".to_string()), "{diff:?}");
    assert!(
        !dir.join("Cargo.lock").exists(),
        "nothing is written without --write"
    );
    assert!(run.report.success());

    let runs = runner.runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].args, ["generate-lockfile"]);
    assert!(
        runs[0].cwd.starts_with(&run.scratch_parent),
        "the tool runs in the scratch copy"
    );
    let scratch_files: Vec<_> = rescan.scanned.lock().unwrap().clone();
    assert_eq!(scratch_files.len(), 1);
    assert!(scratch_files[0].starts_with(&run.scratch_parent));
}

#[test]
fn the_tool_gets_a_scrubbed_environment_pointed_at_the_scratch_directory() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK)]));
    let run = fix(&dir, false, &runner, &FakeRescan::default());
    let command = &runner.runs()[0];
    let env: HashMap<&str, &str> = command
        .env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(env["PATH"], "/fake/bin");
    for key in [
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "CARGO_HOME",
    ] {
        assert!(
            std::path::Path::new(env[key]).starts_with(&run.scratch_parent),
            "{key} = {}",
            env[key]
        );
    }
    assert_eq!(env["RUSTC_WRAPPER"], "");
    assert_eq!(env["RUSTC"], "/fake/bin/rustc");
    for (key, _) in std::env::vars() {
        if !env.contains_key(key.as_str()) {
            continue;
        }
        assert!(
            [
                "PATH",
                "HOME",
                "TMPDIR",
                "LANG",
                "TERM",
                "NO_COLOR",
                "RUSTUP_HOME",
                "CARGO_HOME"
            ]
            .contains(&key.as_str())
                || key.starts_with("XDG_")
                || key.starts_with("CARGO_")
                || key.starts_with("RUSTC"),
            "{key} looks inherited"
        );
    }
    assert_eq!(command.timeout, Duration::from_secs(5));
}

#[test]
fn with_write_the_lockfile_is_written() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.lock")).unwrap(),
        CARGO_LOCK
    );
    assert!(project.backups.is_empty(), "there was no previous lockfile");
}

const CARGO_TOML_TWO: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"=1.0.10\"\nryu = \"=1.0.17\"\n";
const CARGO_LOCK_TWO: &str = "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"itoa\",\n \"ryu\",\n]\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.10\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"b1a46d1a171d865aa5f83f92695765caa047a9b4cbae2cbf37dbd613a793fd4c\"\n\n[[package]]\nname = \"ryu\"\nversion = \"1.0.17\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e86697c916019a8588c99b5fac3cead74ec0b4b819707a682fd4d23fa0ce1ba1\"\n";

#[test]
fn a_stale_cargo_lockfile_is_updated_and_the_old_one_kept_as_backup() {
    let dir = project(&[("Cargo.toml", CARGO_TOML_TWO), ("Cargo.lock", CARGO_LOCK)]);
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK_TWO)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    assert_eq!(runner.runs()[0].args, ["update", "--workspace"]);
    let diff = project.diff.as_ref().unwrap();
    assert_eq!(diff.added, vec!["ryu@1.0.17".to_string()]);
    assert_eq!(diff.unchanged, 2);
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.lock.sloppy-joe.bak")).unwrap(),
        CARGO_LOCK
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.lock")).unwrap(),
        CARGO_LOCK_TWO
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_temporary_directory_inside_the_project_is_refused() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    let link = unique_dir("tmplink").join("tmp");
    std::os::unix::fs::symlink(dir.join("tmp"), &link).unwrap();
    let request = FixRequest {
        dir: dir.clone(),
        project_type: None,
        config: config::SloppyJoeConfig::default(),
        write: true,
        scratch_parent: link,
        timeout: Duration::from_secs(5),
    };
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK)]));
    let error = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(fix_lockfiles(&request, &runner, &FakeRescan::default()))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("inside the project"),
        "{error:#}"
    );
    assert!(runner.calls.lock().unwrap().is_empty());
    assert!(!dir.join("Cargo.lock").exists());
}

#[test]
fn an_unresolvable_temporary_directory_is_refused() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let request = FixRequest {
        dir: dir.clone(),
        project_type: None,
        config: config::SloppyJoeConfig::default(),
        write: true,
        scratch_parent: unique_dir("gone").join("missing"),
        timeout: Duration::from_secs(5),
    };
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK)]));
    let error = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(fix_lockfiles(&request, &runner, &FakeRescan::default()))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("temporary directory"),
        "{error:#}"
    );
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[test]
fn a_candidate_that_changes_a_locked_version_is_never_written() {
    let bumped: &'static str =
        Box::leak(CARGO_LOCK_TWO.replace("1.0.10", "1.0.11").into_boxed_str());
    let dir = project(&[
        (
            "Cargo.toml",
            CARGO_TOML_TWO.replace("=1.0.10", "^1.0").leak(),
        ),
        ("Cargo.lock", CARGO_LOCK),
    ]);
    let runner = cargo_runner(writes(&[("Cargo.lock", bumped)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Refused, "{project:#?}");
    assert!(
        project
            .reason
            .as_deref()
            .unwrap()
            .contains("itoa@1.0.10 changed version"),
        "{project:#?}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.lock")).unwrap(),
        CARGO_LOCK
    );
    assert!(!dir.join("Cargo.lock.sloppy-joe.bak").exists());
    assert!(!run.report.success());
}

#[test]
fn a_candidate_that_changes_a_checksum_is_never_written() {
    let tampered: &'static str = CARGO_LOCK_TWO
        .replace(
            "b1a46d1a171d865aa5f83f92695765caa047a9b4cbae2cbf37dbd613a793fd4c",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .leak();
    let dir = project(&[("Cargo.toml", CARGO_TOML_TWO), ("Cargo.lock", CARGO_LOCK)]);
    let runner = cargo_runner(writes(&[("Cargo.lock", tampered)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Refused, "{project:#?}");
    assert!(
        project
            .reason
            .as_deref()
            .unwrap()
            .contains("itoa@1.0.10 changed")
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.lock")).unwrap(),
        CARGO_LOCK
    );
}

#[test]
fn a_candidate_the_full_rescan_blocks_is_never_written() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK)]));
    let rescan = FakeRescan {
        blocking: Some(crate::names::MALICIOUS_KNOWN_VULNERABILITY),
        ..Default::default()
    };
    let run = fix(&dir, true, &runner, &rescan);
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Refused, "{project:#?}");
    assert!(project.reason.as_deref().unwrap().contains("check --full"));
    assert!(!dir.join("Cargo.lock").exists());
}

#[test]
fn a_tool_that_rewrites_the_manifest_is_refused() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let runner = cargo_runner(writes(&[
        ("Cargo.lock", CARGO_LOCK),
        ("Cargo.toml", CARGO_TOML_TWO),
    ]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Refused, "{project:#?}");
    assert!(project.reason.as_deref().unwrap().contains("changed"));
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.toml")).unwrap(),
        CARGO_TOML
    );
    assert!(!dir.join("Cargo.lock").exists());
}

#[test]
fn a_candidate_that_still_fails_preflight_is_refused() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let runner = cargo_runner(writes(&[("Cargo.lock", "version = 4\n")]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Refused, "{project:#?}");
    assert!(
        project
            .reason
            .as_deref()
            .unwrap()
            .contains("still has lockfile problems"),
        "{project:#?}"
    );
}

#[test]
fn a_missing_tool_is_a_refusal_naming_the_minimum_version() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let run = fix(&dir, true, &FakeRunner::default(), &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Refused);
    let reason = project.reason.as_deref().unwrap();
    assert!(
        reason.contains("cargo is not installed") && reason.contains("cargo 1.50"),
        "{reason}"
    );
}

#[test]
fn an_old_or_unreadable_tool_version_is_a_refusal() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let old = FakeRunner::default().with("cargo", Some("cargo 1.49.0"), writes(&[]));
    let run = fix(&dir, false, &old, &FakeRescan::default());
    assert!(
        only(&run.report)
            .reason
            .as_deref()
            .unwrap()
            .contains("too old")
    );
    assert!(old.runs().is_empty(), "an old tool is never run");

    let unreadable = FakeRunner::default().with("cargo", None, writes(&[]));
    let run = fix(&dir, false, &unreadable, &FakeRescan::default());
    assert!(
        only(&run.report)
            .reason
            .as_deref()
            .unwrap()
            .contains("could not read the version")
    );
    assert!(unreadable.runs().is_empty());
}

#[test]
fn a_failing_or_hanging_tool_fails_the_fix() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let failing = cargo_runner(Box::new(|_| ToolOutput {
        status: Some(101),
        stderr: "error: failed to download".into(),
        ..Default::default()
    }));
    let run = fix(&dir, true, &failing, &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Failed);
    assert!(
        project
            .reason
            .as_deref()
            .unwrap()
            .contains("failed to download")
    );

    let hanging = cargo_runner(Box::new(|_| ToolOutput {
        timed_out: true,
        ..Default::default()
    }));
    let run = fix(&dir, true, &hanging, &FakeRescan::default());
    assert!(
        only(&run.report)
            .reason
            .as_deref()
            .unwrap()
            .contains("did not finish")
    );
    assert!(!dir.join("Cargo.lock").exists());
}

#[test]
fn a_clean_project_needs_nothing() {
    let dir = project(&[("Cargo.toml", CARGO_TOML), ("Cargo.lock", CARGO_LOCK)]);
    let runner = cargo_runner(writes(&[]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    assert_eq!(only(&run.report).result, Outcome::NothingToFix);
    assert!(runner.calls.lock().unwrap().is_empty());
    assert!(run.report.success());
}

#[test]
fn json_output_has_the_plan_diff_and_result() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK)]));
    let run = fix(&dir, false, &runner, &FakeRescan::default());
    let json: serde_json::Value = serde_json::from_str(&run.report.to_json()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["write"], false);
    let project = &json["projects"][0];
    assert_eq!(project["result"], "verified");
    assert_eq!(project["problems"][0]["class"], "fixable");
    assert_eq!(project["command"], "cargo generate-lockfile");
    assert!(!project["diff"]["added"].as_array().unwrap().is_empty());
    let human = run.report.to_human();
    assert!(human.contains("versions: "), "{human}");
    assert!(human.contains("--write"), "{human}");
}

#[test]
fn a_temporary_directory_inside_the_project_is_refused() {
    let dir = project(&[("Cargo.toml", CARGO_TOML)]);
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    let request = FixRequest {
        dir: dir.clone(),
        project_type: None,
        config: config::SloppyJoeConfig::default(),
        write: true,
        scratch_parent: dir.join("tmp"),
        timeout: Duration::from_secs(5),
    };
    let runner = cargo_runner(writes(&[("Cargo.lock", CARGO_LOCK)]));
    let error = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(fix_lockfiles(&request, &runner, &FakeRescan::default()))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("inside the project"),
        "{error:#}"
    );
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[test]
fn terminal_output_escapes_control_and_reordering_characters() {
    let shown = super::report::terminal_safe("it's \u{1b}[31mred\u{202e}x\nnext");
    assert!(shown.contains("it's"), "{shown}");
    assert!(
        !shown.contains('\u{1b}') && !shown.contains('\u{202e}'),
        "{shown}"
    );
    assert!(shown.contains("\n      next"), "{shown}");
}

#[test]
fn guided_ecosystems_never_run_a_tool() {
    let dir = project(&[(
        "Gemfile",
        "source 'https://rubygems.org'\ngem 'rake', '13.0.6'\n",
    )]);
    let runner = FakeRunner::default().with("bundle", Some("2.5.0"), writes(&[]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = only(&run.report);
    assert_eq!(project.result, Outcome::Guided, "{project:#?}");
    assert_eq!(project.problems[0].class, "guided");
    assert_eq!(project.problems[0].command.as_deref(), Some("bundle lock"));
    assert!(
        project.problems[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("executes repository code")
    );
    assert!(runner.calls.lock().unwrap().is_empty());
    assert!(!run.report.success(), "a guided problem is not success");
}

/// The real `cargo` on this machine, in the real scrubbed environment, offline: a crate with no
/// dependencies needs no registry. Ignored by default because it depends on the host toolchain;
/// run it with `cargo test real_cargo_smoke -- --ignored`.
#[test]
#[ignore = "runs the host's cargo; needs no network"]
fn real_cargo_smoke_generates_a_lockfile_offline() {
    let dir = project(&[(
        "Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )]);
    let scratch_parent = unique_dir("scratch");
    let runner = runner::RealRunner::new(
        std::env::var_os("PATH"),
        &[dir.clone(), scratch_parent.clone()],
    );
    if runner::ProcessRunner::locate(&runner, "cargo").is_none() {
        eprintln!("cargo is not installed; skipping");
        return;
    }
    let request = FixRequest {
        dir: dir.clone(),
        project_type: None,
        config: config::SloppyJoeConfig::default(),
        write: true,
        scratch_parent: scratch_parent.clone(),
        timeout: Duration::from_secs(120),
    };
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(fix_lockfiles(&request, &runner, &FakeRescan::default()))
        .unwrap();
    let project = only(&report);
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    let lock = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap();
    assert!(lock.contains("name = \"app\""), "{lock}");
    assert!(std::fs::read_dir(&scratch_parent).unwrap().next().is_none());
}
