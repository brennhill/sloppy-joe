//! The `fix-lockfile` subcommand's arguments and exit status.

use super::{FixRequest, fix_lockfiles, runner::RealRunner, verify::FullRescan};
use std::path::PathBuf;
use std::time::Duration;

/// Arguments of `sloppy-joe fix-lockfile`.
#[derive(clap::Args, Debug, Clone)]
pub struct FixLockfileArgs {
    /// Project directory [default: current directory]
    #[arg(long, default_value = ".")]
    pub dir: PathBuf,

    /// Project type: npm, pypi, cargo, go, ruby, php, jvm, dotnet
    #[arg(long = "type", value_name = "ECOSYSTEM")]
    pub project_type: Option<String>,

    /// Config file path or URL, as for `check`. Never read from the project directory.
    #[arg(long, value_name = "PATH_OR_URL")]
    pub config: Option<String>,

    /// Write verified lockfiles (the previous file is kept as <name>.sloppy-joe.bak).
    /// Without it, nothing in the project is changed.
    #[arg(long)]
    pub write: bool,

    /// Output the plan, version diff and result per project as JSON
    #[arg(long)]
    pub json: bool,
}

/// How long one package-manager run may take.
const TOOL_TIMEOUT: Duration = Duration::from_secs(600);

/// Run the subcommand; returns the process exit status: 0 when nothing needed fixing or every fix
/// was verified (and written with `--write`), 1 when a problem remains, a fix was refused or a
/// tool failed, 2 on a runtime error.
pub async fn run_fix_lockfile(args: FixLockfileArgs) -> i32 {
    let dir = match std::fs::canonicalize(&args.dir) {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!(
                "Error: could not resolve directory {}: {err}",
                args.dir.display()
            );
            return 2;
        }
    };
    let source = match crate::config::resolve_config_source(args.config.as_deref(), Some(&dir)) {
        Ok(Some(source)) => source,
        Ok(None) => {
            eprintln!(
                "Error: No config found for {}.\n  Fix: Run `sloppy-joe register` to set up per-project config, or pass `--config`.",
                dir.display()
            );
            return 2;
        }
        Err(err) => {
            eprintln!("Error: {err}");
            return 2;
        }
    };
    let config = match crate::config::load_config_from_source(Some(&source), Some(&dir)).await {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Error: {err}");
            return 2;
        }
    };
    let scratch_parent = std::env::temp_dir();
    let runner = RealRunner::new(
        std::env::var_os("PATH"),
        &[dir.clone(), scratch_parent.clone()],
    );
    let request = FixRequest {
        dir,
        project_type: args.project_type,
        config,
        write: args.write,
        scratch_parent,
        timeout: TOOL_TIMEOUT,
    };
    match fix_lockfiles(&request, &runner, &FullRescan).await {
        Ok(report) => {
            if args.json {
                println!("{}", report.to_json());
            } else {
                print!("{}", report.to_human());
            }
            if report.success() { 0 } else { 1 }
        }
        Err(err) => {
            eprintln!("Error: {err:#}");
            2
        }
    }
}
