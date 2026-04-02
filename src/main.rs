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
  sloppy-joe init --register                    Create config + register cwd
  sloppy-joe register                           Register cwd with existing config
  sloppy-joe list                               Show registered repos

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

        /// Emit review-ready exception candidates for supported findings.
        #[arg(long)]
        review_exceptions: bool,

        /// Project directory to scan [default: current directory]
        #[arg(long, default_value = ".")]
        dir: PathBuf,

        /// Config file path or URL. Overrides SLOPPY_JOE_CONFIG env var.
        /// Accepts a local path or https:// URL. Never reads from the
        /// project directory — AI agents could rewrite it.
        /// See CONFIG.md for format details.
        #[arg(long, value_name = "PATH_OR_URL")]
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
        #[arg(long, value_name = "PATH_OR_URL")]
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
    /// Without flags, prints a JSON config template to stdout.
    /// Use --register to create a config file and register the current repo.
    /// Use --global to create a global default config.
    ///
    ///   sloppy-joe init > /etc/sloppy-joe/config.json
    ///   sloppy-joe init --register
    ///   sloppy-joe init --global
    Init {
        /// Create config at config home and register current directory
        #[arg(long)]
        register: bool,

        /// Create a global default config at config home
        #[arg(long)]
        global: bool,
    },
    /// Register a repo → config path mapping
    ///
    /// Maps the git root of the specified directory to a config file.
    /// If no --config is specified, defaults to {config_home}/{dirname}/config.json.
    ///
    ///   sloppy-joe register
    ///   sloppy-joe register --dir ./my-project
    ///   sloppy-joe register --config /path/to/config.json
    Register {
        /// Project directory to register [default: current directory]
        #[arg(long, default_value = ".")]
        dir: PathBuf,

        /// Config file path to associate with this repo
        #[arg(long)]
        config: Option<String>,
    },
    /// Remove a repo from the config registry
    ///
    ///   sloppy-joe unregister
    ///   sloppy-joe unregister --dir ./my-project
    Unregister {
        /// Project directory to unregister [default: current directory]
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// List all registered repos and their config paths
    List,
}

/// Resolve config source, exiting with an error if none is found.
fn require_config(config: Option<&str>, dir: &std::path::Path) -> Option<String> {
    match sloppy_joe::config::resolve_config_source(config, Some(dir)) {
        Ok(Some(source)) => Some(source),
        Ok(None) => {
            eprintln!(
                "Error: No config found for {}.\n  Fix: Run `sloppy-joe register` to set up per-project config, or pass `--config`.",
                dir.display()
            );
            process::exit(2);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(2);
        }
    }
}

/// Extract the directory name from a path, defaulting to "project".
fn repo_dirname(git_root: &std::path::Path) -> String {
    git_root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string())
}

/// Write the template config to a path, exiting on error.
fn write_template_config(config_path: &std::path::Path) {
    let template = sloppy_joe::config::template_json();
    let template_value: serde_json::Value =
        serde_json::from_str(&template).expect("template_json produces valid JSON");
    if let Err(e) = sloppy_joe::cache::atomic_write_json_checked(config_path, &template_value) {
        eprintln!(
            "Error: Could not write config file.\n  Path: {}\n  Error: {}\n  Fix: Check file permissions.",
            config_path.display(),
            e
        );
        process::exit(2);
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            project_type,
            json,
            review_exceptions,
            dir,
            config,
            deep,
            paranoid,
            no_cache,
            cache_dir,
        } => {
            let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
            let config_source = require_config(config.as_deref(), &dir);
            let opts = sloppy_joe::ScanOptions {
                deep,
                paranoid,
                no_cache,
                cache_dir: cache_dir.as_deref(),
                disable_osv_disk_cache: false,
                skip_hash_check: false,
                review_exceptions,
            };
            match sloppy_joe::scan_with_source_full_options(
                &dir,
                project_type.as_deref(),
                config_source.as_deref(),
                &opts,
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
            let config_source = require_config(config.as_deref(), &dir);
            eprintln!("Warming cache for {} ...", dir.display());
            match sloppy_joe::warm_cache(
                &dir,
                project_type.as_deref(),
                config_source.as_deref(),
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
        Commands::Init { register, global } => {
            if register && global {
                eprintln!(
                    "Error: Use --register or --global, not both.\n  Fix: --register creates per-project config, --global creates a shared default."
                );
                process::exit(2);
            }

            if register {
                // Create config at {config_home}/{dirname}/config.json and register cwd
                let dir = match std::env::current_dir() {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!(
                            "Error: Could not determine current directory.\n  Error: {}\n  Fix: Check directory permissions.",
                            e
                        );
                        process::exit(2);
                    }
                };
                let git_root = match sloppy_joe::config::registry::find_git_root(&dir) {
                    Ok(Some(root)) => root,
                    Ok(None) => {
                        eprintln!(
                            "Error: Not inside a git repository.\n  Path: {}\n  Fix: Run this command from inside a git repo, or use `sloppy-joe init > config.json` to create a template manually.",
                            dir.display()
                        );
                        process::exit(2);
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        process::exit(2);
                    }
                };
                let config_home = match sloppy_joe::config::registry::config_home() {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        process::exit(2);
                    }
                };
                let dirname = repo_dirname(&git_root);
                let config_dir = config_home.join(&dirname);
                let config_path = config_dir.join("config.json");

                // Don't overwrite existing config
                if config_path.exists() {
                    eprintln!(
                        "Error: Config already exists at {}.\n  Fix: Use `sloppy-joe register` to re-register without overwriting.",
                        config_path.display()
                    );
                    process::exit(2);
                }

                if let Err(e) = std::fs::create_dir_all(&config_dir) {
                    eprintln!(
                        "Error: Could not create config directory.\n  Path: {}\n  Error: {}\n  Fix: Check directory permissions.",
                        config_dir.display(),
                        e
                    );
                    process::exit(2);
                }

                write_template_config(&config_path);

                if let Err(e) = sloppy_joe::config::registry::register(&git_root, &config_path) {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }

                eprintln!("Config created: {}", config_path.display());
                eprintln!(
                    "Registered: {} -> {}",
                    git_root.display(),
                    config_path.display()
                );
                eprintln!("Edit the config to add your canonical rules.");
            } else if global {
                // Create global default config at {config_home}/default/config.json
                let config_home = match sloppy_joe::config::registry::config_home() {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        process::exit(2);
                    }
                };
                let default_dir = config_home.join("default");
                let config_path = default_dir.join("config.json");

                if let Err(e) = std::fs::create_dir_all(&default_dir) {
                    eprintln!(
                        "Error: Could not create default config directory.\n  Path: {}\n  Error: {}\n  Fix: Check directory permissions.",
                        default_dir.display(),
                        e
                    );
                    process::exit(2);
                }

                write_template_config(&config_path);

                eprintln!("Global default config created: {}", config_path.display());
                eprintln!("Edit the config to add your canonical rules.");
                eprintln!("Any unregistered repo will use this config as fallback.");
            } else {
                // No flags: print template to stdout (backward compat)
                sloppy_joe::config::print_template();
            }
        }
        Commands::Register { dir, config } => {
            let dir = std::fs::canonicalize(&dir).unwrap_or_else(|e| {
                eprintln!(
                    "Error: Could not resolve directory.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists.",
                    dir.display(),
                    e
                );
                process::exit(2);
            });
            let git_root = match sloppy_joe::config::registry::find_git_root(&dir) {
                Ok(Some(root)) => root,
                Ok(None) => {
                    eprintln!(
                        "Error: Not inside a git repository.\n  Path: {}\n  Fix: Run this command from inside a git repo.",
                        dir.display()
                    );
                    process::exit(2);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }
            };

            let config_path = match config {
                Some(explicit) => std::fs::canonicalize(&explicit).unwrap_or_else(|e| {
                    eprintln!(
                        "Error: Could not resolve config path.\n  Path: {}\n  Error: {}\n  Fix: Check that the config file exists.",
                        explicit, e
                    );
                    process::exit(2);
                }),
                None => {
                    // Default: {config_home}/{dirname}/config.json
                    let config_home = match sloppy_joe::config::registry::config_home() {
                        Ok(h) => h,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            process::exit(2);
                        }
                    };
                    let dirname = repo_dirname(&git_root);
                    config_home.join(&dirname).join("config.json")
                }
            };

            if !config_path.exists() {
                eprintln!(
                    "Error: Config file does not exist.\n  Path: {}\n  Fix: Create it first with `sloppy-joe init --register` or create it manually.",
                    config_path.display()
                );
                process::exit(2);
            }

            if let Err(e) = sloppy_joe::config::registry::register(&git_root, &config_path) {
                eprintln!("Error: {}", e);
                process::exit(2);
            }

            eprintln!(
                "Registered: {} -> {}",
                git_root.display(),
                config_path.display()
            );
        }
        Commands::Unregister { dir } => {
            let dir = std::fs::canonicalize(&dir).unwrap_or_else(|e| {
                eprintln!(
                    "Error: Could not resolve directory.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists.",
                    dir.display(),
                    e
                );
                process::exit(2);
            });
            let git_root = match sloppy_joe::config::registry::find_git_root(&dir) {
                Ok(Some(root)) => root,
                Ok(None) => {
                    eprintln!(
                        "Error: Not inside a git repository.\n  Path: {}\n  Fix: Run this command from inside a git repo.",
                        dir.display()
                    );
                    process::exit(2);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }
            };

            match sloppy_joe::config::registry::unregister(&git_root) {
                Ok(true) => {
                    eprintln!("Unregistered: {}", git_root.display());
                }
                Ok(false) => {
                    eprintln!("Warning: {} was not registered.", git_root.display());
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }
            }
        }
        Commands::List => {
            let entries = match sloppy_joe::config::registry::load_registry() {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }
            };

            if entries.is_empty() {
                eprintln!("No repos registered.");
                eprintln!("Run `sloppy-joe register` in a git repo to get started.");
            } else {
                for (repo, config) in &entries {
                    println!("{} -> {}", repo, config);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_cli_parses_review_exceptions_flag() {
        let cli = Cli::try_parse_from(["sloppy-joe", "check", "--review-exceptions", "--json"])
            .expect("check command should parse review-exceptions");

        match cli.command {
            Commands::Check {
                json,
                review_exceptions,
                ..
            } => {
                assert!(json);
                assert!(review_exceptions);
            }
            _ => panic!("expected check command"),
        }
    }
}
