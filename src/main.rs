#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "sloppy-joe")]
#[command(version)]
#[command(
    about = "Catch hallucinated, typosquatted, and non-canonical dependencies before they reach production."
)]
#[command(
    long_about = "Catch hallucinated, typosquatted, and non-canonical dependencies before they reach production.

Three layers of protection:
  1. Existence  — verifies every dependency exists on its registry
  2. Similarity — flags names close to popular packages (typosquatting)
  3. Canonical  — enforces your team's approved package choices

Supports: npm, PyPI, Cargo, Go, Ruby, PHP, JVM (Gradle/Maven), .NET

Examples:
  sloppy-joe check                              Auto-detect and check
  sloppy-joe check --type npm                   Check npm only
  sloppy-joe check --dir ./project              Check a specific directory
  sloppy-joe check --config /etc/sj/config.json Enforce canonical rules
  sloppy-joe check --json                       JSON output for CI
  sloppy-joe init > /etc/sj/config.json         Generate config template

Exit codes:
  0  No blocking errors found (warnings may still be reported)
  1  Blocking errors found
  2  Runtime error (missing manifest, network failure)

Config security:
  Config is NEVER read from the project directory. An AI agent with
  shell access could rewrite an in-repo config to allowlist its own
  hallucinated dependencies. Use --config or SLOPPY_JOE_CONFIG env var
  to point to a file outside the agent's write boundary."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check dependencies for issues
    ///
    /// Auto-detects project type from manifest files (package.json,
    /// requirements.txt, Cargo.toml, go.mod, Gemfile, composer.json,
    /// build.gradle/pom.xml, *.csproj). Override with --type.
    Check {
        /// Project type: npm, pypi, cargo, go, ruby, php, jvm, dotnet
        #[arg(long = "type", value_name = "ECOSYSTEM")]
        project_type: Option<String>,

        /// Output results as JSON (for CI pipelines and programmatic use)
        #[arg(long)]
        json: bool,

        /// Project directory to scan [default: current directory]
        #[arg(long, default_value = ".")]
        dir: PathBuf,

        /// Config file path or URL. Overrides SLOPPY_JOE_CONFIG env var.
        /// Accepts a local path or https:// URL. Never reads from the
        /// project directory — AI agents could rewrite it.
        /// See CONFIG.md for format details.
        #[arg(long, env = "SLOPPY_JOE_CONFIG", value_name = "PATH_OR_URL")]
        config: Option<String>,

        /// Run similarity checks on transitive dependencies (slower, more thorough)
        #[arg(long)]
        deep: bool,

        /// Enable expensive mutation generators (bitflip). Produces ~10x more
        /// similarity queries. Use for high-security environments.
        #[arg(long)]
        paranoid: bool,

        /// Disable reading from the similarity disk cache.
        #[arg(long)]
        no_cache: bool,

        /// Directory to store similarity cache files.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
    },
    /// Warm the cache by running all network queries without reporting issues.
    ///
    /// Run locally before pushing so CI benefits from warm cache.
    /// Always exits 0 — this is a preparation step, not a gate.
    ///
    ///   sloppy-joe cache
    ///   sloppy-joe cache --dir ./my-project
    ///   sloppy-joe cache --deep --paranoid   # warm everything
    Cache {
        /// Project type: npm, pypi, cargo, go, ruby, php, jvm, dotnet
        #[arg(long = "type", value_name = "ECOSYSTEM")]
        project_type: Option<String>,

        /// Project directory to scan [default: current directory]
        #[arg(long, default_value = ".")]
        dir: PathBuf,

        /// Config file path or URL.
        #[arg(long, env = "SLOPPY_JOE_CONFIG", value_name = "PATH_OR_URL")]
        config: Option<String>,

        /// Also warm transitive dependency caches
        #[arg(long)]
        deep: bool,

        /// Also warm bitflip mutation caches (expensive)
        #[arg(long)]
        paranoid: bool,

        /// Directory to store cache files.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
    },
    /// Print a template config to stdout
    ///
    /// Pipe to a file OUTSIDE the project directory:
    ///   sloppy-joe init > /etc/sloppy-joe/config.json
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
            deep,
            paranoid,
            no_cache,
            cache_dir,
        } => {
            let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
            match sloppy_joe::scan_with_source_full(
                &dir,
                project_type.as_deref(),
                config.as_deref(),
                deep,
                paranoid,
                no_cache,
                cache_dir.as_deref(),
            )
            .await
            {
                Ok(report) => {
                    if json {
                        report.print_json();
                    } else {
                        report.print_human();
                    }
                    if report.has_errors() {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {:#}", e);
                    process::exit(2);
                }
            }
        }
        Commands::Cache {
            project_type,
            dir,
            config,
            deep,
            paranoid,
            cache_dir,
        } => {
            let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
            eprintln!("Warming cache for {} ...", dir.display());
            match sloppy_joe::warm_cache(
                &dir,
                project_type.as_deref(),
                config.as_deref(),
                deep,
                paranoid,
                cache_dir.as_deref(),
            )
            .await
            {
                Ok(report) => {
                    eprintln!(
                        "Cache warmed. {} packages indexed.",
                        report.packages_checked
                    );
                }
                Err(e) => {
                    eprintln!("Warning: cache warming encountered errors: {:#}", e);
                    eprintln!("Partial cache may have been written. CI will retry failed queries.");
                    // Always exit 0 — cache warming is best-effort
                }
            }
        }
        Commands::Init => {
            sloppy_joe::config::print_template();
        }
    }
}
