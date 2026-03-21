use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "sloppy-joe")]
#[command(about = "Detect hallucinated, typosquatted, and non-canonical dependencies")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check dependencies for issues
    Check {
        /// Project type (auto-detected if omitted)
        #[arg(long = "type")]
        project_type: Option<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Project directory (defaults to current directory)
        #[arg(long, default_value = ".")]
        dir: PathBuf,

        /// Path to config file. Overrides SLOPPY_JOE_CONFIG env var.
        /// Never reads from the project directory.
        #[arg(long, env = "SLOPPY_JOE_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Print a template config to stdout (pipe to a file outside the repo)
    Init,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            project_type,
            json,
            dir,
            config,
        } => {
            let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
            let config_path = config.as_deref();
            match sloppy_joe::scan(&dir, project_type.as_deref(), config_path).await {
                Ok(report) => {
                    if json {
                        report.print_json();
                    } else {
                        report.print_human();
                    }
                    if report.has_issues() {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {:#}", e);
                    process::exit(2);
                }
            }
        }
        Commands::Init => {
            sloppy_joe::config::print_template();
        }
    }
}
