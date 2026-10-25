//! Running a package manager for `fix-lockfile`: an argument vector (never a shell), a complete
//! environment built from nothing, a working directory inside the scratch copy, a timeout, an
//! output cap and no stdin. The trait lets tests run the whole flow with a fake tool.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// One tool invocation. `env` is the whole environment: nothing is inherited.
#[derive(Debug, Clone)]
pub(super) struct ToolCommand {
    /// Absolute path of the program.
    pub(super) program: PathBuf,
    pub(super) args: Vec<String>,
    pub(super) cwd: PathBuf,
    pub(super) env: Vec<(String, String)>,
    pub(super) timeout: Duration,
    /// Bytes kept from each of stdout and stderr; the rest is read and discarded.
    pub(super) output_cap: usize,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ToolOutput {
    /// Exit code; `None` when the process was killed or ended by a signal.
    pub(super) status: Option<i32>,
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) timed_out: bool,
    pub(super) truncated: bool,
}

impl ToolOutput {
    pub(super) fn succeeded(&self) -> bool {
        self.status == Some(0) && !self.timed_out
    }

    /// The last lines of output, for a refusal message.
    pub(super) fn tail(&self) -> String {
        let text = format!("{}\n{}", self.stdout, self.stderr);
        let lines: Vec<&str> = crate::untrusted::rows(&text)
            .filter(|line| !line.trim().is_empty())
            .collect();
        let start = lines.len().saturating_sub(12);
        lines[start..].join("\n")
    }
}

/// Finds and runs tools. The real one searches only the trusted part of `PATH`.
pub(super) trait ProcessRunner: Sync {
    /// Absolute path of `program` on the trusted search path, or `None`.
    fn locate(&self, program: &str) -> Option<PathBuf>;
    /// The `PATH` value a tool gets (the trusted directories only).
    fn search_path(&self) -> String;
    fn run(&self, command: &ToolCommand) -> anyhow::Result<ToolOutput>;
}

/// Runs real processes.
pub(super) struct RealRunner {
    trusted_dirs: Vec<PathBuf>,
}

impl RealRunner {
    /// Trust the absolute `PATH` directories that are not inside any of `untrusted_roots` (the
    /// project and the scratch directory). Relative entries (`.`, `node_modules/.bin`) would let
    /// the repository pick the binary, so they are dropped.
    pub(super) fn new(path_var: Option<std::ffi::OsString>, untrusted_roots: &[PathBuf]) -> Self {
        Self {
            trusted_dirs: trusted_dirs(path_var, untrusted_roots),
        }
    }
}

pub(super) fn trusted_dirs(
    path_var: Option<std::ffi::OsString>,
    untrusted_roots: &[PathBuf],
) -> Vec<PathBuf> {
    let roots: Vec<PathBuf> = untrusted_roots
        .iter()
        .map(|root| std::fs::canonicalize(root).unwrap_or_else(|_| root.clone()))
        .collect();
    let mut dirs = Vec::new();
    for dir in path_var
        .as_deref()
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
    {
        if !dir.is_absolute() {
            continue;
        }
        let resolved = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        if roots
            .iter()
            .any(|root| resolved.starts_with(root) || dir.starts_with(root))
        {
            continue;
        }
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

impl ProcessRunner for RealRunner {
    fn locate(&self, program: &str) -> Option<PathBuf> {
        if program.contains('/') || program.contains('\\') {
            return None;
        }
        self.trusted_dirs
            .iter()
            .map(|dir| dir.join(program))
            .find(|candidate| is_executable(candidate))
    }

    fn search_path(&self) -> String {
        std::env::join_paths(&self.trusted_dirs)
            .map(|joined| joined.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn run(&self, command: &ToolCommand) -> anyhow::Result<ToolOutput> {
        run_process(command)
    }
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

fn spawn_reader(
    mut source: impl Read + Send + 'static,
    cap: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut truncated = false;
        let mut buffer = [0u8; 8192];
        loop {
            match source.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let room = cap.saturating_sub(kept.len());
                    kept.extend_from_slice(&buffer[..read.min(room)]);
                    truncated |= read > room;
                }
            }
        }
        (kept, truncated)
    })
}

fn run_process(command: &ToolCommand) -> anyhow::Result<ToolOutput> {
    let mut builder = std::process::Command::new(&command.program);
    builder
        .args(&command.args)
        .current_dir(&command.cwd)
        .env_clear()
        .envs(command.env.iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        builder.process_group(0);
    }
    let mut child = builder
        .spawn()
        .map_err(|err| anyhow::anyhow!("could not start {}: {err}", command.program.display()))?;
    let stdout = spawn_reader(child.stdout.take().expect("piped"), command.output_cap);
    let stderr = spawn_reader(child.stderr.take().expect("piped"), command.output_cap);
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= command.timeout {
            timed_out = true;
            kill_group(child.id());
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let (out, out_cut) = stdout.join().unwrap_or_default();
    let (err, err_cut) = stderr.join().unwrap_or_default();
    Ok(ToolOutput {
        status: if timed_out { None } else { status.code() },
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        timed_out,
        truncated: out_cut || err_cut,
    })
}

/// Kill the tool's whole process group (it was started as its own group leader), so helpers it
/// spawned do not outlive the timeout. No unsafe code: the shell's `kill` builtin is run as a
/// program. The `kill` binaries differ between systems (procps on Ubuntu mishandled `-KILL
/// -<pid>` and killed the caller), so the builtin with an explicit `--` is used instead, and
/// the group id must be a real process (never 0 or 1, which would reach far beyond the tool).
fn kill_group(pid: u32) {
    #[cfg(unix)]
    {
        if pid <= 1 {
            return;
        }
        let _ = std::process::Command::new("/bin/sh")
            .args(["-c", "kill -s KILL -- \"-$1\"", "sh", &pid.to_string()])
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    let _ = pid;
}

/// The first `major.minor[.patch]` in a tool's `--version` output.
pub(super) fn parse_version(output: &str) -> Option<(u64, u64, u64)> {
    let bytes = output.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let starts_number = i == 0 || !(bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'.');
        if bytes[i].is_ascii_digit() && starts_number {
            let rest = &output[i..];
            let token: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let parts: Vec<u64> = token
                .split('.')
                .filter(|part| !part.is_empty())
                .map_while(|part| part.parse().ok())
                .collect();
            if parts.len() >= 2 {
                return Some((parts[0], parts[1], parts.get(2).copied().unwrap_or(0)));
            }
            i += token.len().max(1);
        } else {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;
