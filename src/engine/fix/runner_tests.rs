use super::*;

#[test]
fn versions_are_read_from_tool_output() {
    assert_eq!(parse_version("9.15.0\n"), Some((9, 15, 0)));
    assert_eq!(parse_version("cargo 1.96.0 (30a34c682 2026-05-25)"), Some((1, 96, 0)));
    assert_eq!(parse_version("go version go1.27.3 darwin/arm64"), Some((1, 27, 3)));
    assert_eq!(parse_version("Poetry (version 2.4.1)"), Some((2, 4, 1)));
    assert_eq!(parse_version("uv 0.11.19 (Homebrew 2026-06-03)"), Some((0, 11, 19)));
    assert_eq!(
        parse_version("Composer version 2.10.3 2026-08-27 13:34:23"),
        Some((2, 10, 3))
    );
    assert_eq!(parse_version("1.22"), Some((1, 22, 0)));
    assert_eq!(parse_version("no version here"), None);
    assert_eq!(parse_version("v8"), None);
}

#[test]
fn relative_and_repository_path_entries_are_not_trusted() {
    let project = std::env::temp_dir().join("sj-runner-project");
    let path = std::env::join_paths([
        PathBuf::from("/usr/bin"),
        PathBuf::from("node_modules/.bin"),
        PathBuf::from("."),
        project.join("bin"),
        PathBuf::from("/usr/bin"),
    ])
    .unwrap();
    let dirs = trusted_dirs(Some(path), &[project]);
    assert_eq!(dirs, vec![PathBuf::from("/usr/bin")]);
}

#[cfg(unix)]
fn command(program: &str, args: &[&str], timeout_ms: u64, cap: usize) -> ToolCommand {
    ToolCommand {
        program: PathBuf::from(program),
        args: args.iter().map(|arg| arg.to_string()).collect(),
        cwd: std::env::temp_dir(),
        env: vec![("ONLY_THIS".into(), "1".into())],
        timeout: Duration::from_millis(timeout_ms),
        output_cap: cap,
    }
}

#[cfg(unix)]
#[test]
fn the_environment_is_exactly_what_was_given() {
    let runner = RealRunner::new(None, &[]);
    let output = runner
        .run(&command("/usr/bin/env", &[], 10_000, 1 << 16))
        .unwrap();
    assert!(output.succeeded(), "{output:?}");
    assert_eq!(output.stdout.trim(), "ONLY_THIS=1");
}

#[cfg(unix)]
#[test]
fn stdin_is_empty() {
    let runner = RealRunner::new(None, &[]);
    let output = runner.run(&command("/bin/cat", &[], 10_000, 1 << 16)).unwrap();
    assert!(output.succeeded());
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn a_tool_that_runs_too_long_is_killed() {
    let runner = RealRunner::new(None, &[]);
    let started = Instant::now();
    let output = runner.run(&command("/bin/sleep", &["30"], 200, 1024)).unwrap();
    assert!(output.timed_out);
    assert!(!output.succeeded());
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[cfg(unix)]
#[test]
fn output_beyond_the_cap_is_dropped() {
    let runner = RealRunner::new(None, &[]);
    let output = runner
        .run(&command("/bin/cat", &["/dev/zero"], 300, 4096))
        .unwrap();
    assert!(output.truncated);
    assert_eq!(output.stdout.len(), 4096);
}

#[cfg(unix)]
#[test]
fn programs_are_found_only_on_trusted_directories() {
    let runner = RealRunner::new(Some("/bin".into()), &[]);
    assert_eq!(runner.locate("sh"), Some(PathBuf::from("/bin/sh")));
    assert_eq!(runner.locate("../bin/sh"), None);
    assert_eq!(runner.locate("/bin/sh"), None);
    assert_eq!(runner.locate("definitely-not-a-tool"), None);
}
