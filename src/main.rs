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
  sloppy-joe check                              Fast local guardrail
  sloppy-joe check --full                       Strict online scan
  sloppy-joe check --ci                         Strict CI-oriented scan
  sloppy-joe check --type npm                   Check npm only
  sloppy-joe check --dir ./project              Check a specific directory
  sloppy-joe check --config /etc/sj/config.json Enforce canonical rules
  sloppy-joe check --json                       JSON output for CI
  sloppy-joe init --register                    Create config + register cwd safely
  sloppy-joe init --greenfield --ecosystem npm   Create an ecosystem-specific starter policy
  sloppy-joe init --from-current                 Print review-only bootstrap suggestions
  sloppy-joe init --from-current --register      Write and register bootstrap suggestions
  sloppy-joe init > /secure/sloppy-joe.json    Generate config template at a safe path
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Fast,
    Full,
    Ci,
}

fn fast_mode_ci_guidance() -> &'static str {
    "For CI or release gating, use `sloppy-joe check --ci` or `sloppy-joe check --full`."
}

#[derive(Subcommand)]
enum Commands {
    /// Check dependencies for issues
    ///
    /// Auto-detects project type from manifest files (package.json,
    /// requirements.txt, Cargo.toml, go.mod, Gemfile, composer.json,
    /// build.gradle/pom.xml, *.csproj). Override with --type.
    ///
    /// Default mode is a fast local guardrail. Use --full or --ci for the
    /// strict online scan.
    Check {
        /// Run the strict full scan mode
        #[arg(long, conflicts_with = "ci")]
        full: bool,

        /// Run the strict CI scan mode
        #[arg(long, conflicts_with = "full")]
        ci: bool,

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
    /// Create a config template or register a safe per-repo config
    ///
    /// Without flags, prints a JSON config template to stdout.
    /// Write that file outside the repo, or use --register to create and
    /// register a safe per-repo config automatically.
    /// Use --global to create a global default config.
    ///
    ///   sloppy-joe init > /secure/sloppy-joe/config.json
    ///   sloppy-joe init --register
    ///   sloppy-joe init --greenfield --ecosystem npm
    ///   sloppy-joe init --from-current
    ///   sloppy-joe init --from-current --register
    ///   sloppy-joe init --global
    Init {
        /// Create an opinionated starter policy for a specific ecosystem
        #[arg(long, requires = "ecosystem", conflicts_with_all = ["from_current", "global"])]
        greenfield: bool,

        /// Ecosystem to use for greenfield bootstrap
        #[arg(long = "ecosystem", value_name = "ECO", requires = "greenfield")]
        ecosystem: Option<String>,

        /// Seed config from the current repository
        #[arg(long, conflicts_with_all = ["greenfield", "global"])]
        from_current: bool,

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

fn resolve_scan_mode(full: bool, ci: bool) -> Result<ScanMode, String> {
    if full && ci {
        return Err("--full and --ci cannot be used together".to_string());
    }

    if full {
        Ok(ScanMode::Full)
    } else if ci {
        Ok(ScanMode::Ci)
    } else {
        Ok(ScanMode::Fast)
    }
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

/// Write a config JSON string to a path.
fn write_config_json(config_path: &std::path::Path, config_json: &str) -> Result<(), String> {
    let config_value: serde_json::Value =
        serde_json::from_str(config_json).expect("bootstrap helpers must produce valid JSON");
    sloppy_joe::cache::atomic_write_json_checked(config_path, &config_value).map_err(|e| {
        format!(
            "Could not write config file.\n  Path: {}\n  Error: {}\n  Fix: Check file permissions.",
            config_path.display(),
            e
        )
    })
}

fn init_config_json(
    greenfield: bool,
    ecosystem: Option<&str>,
    from_current: bool,
    project_dir: &std::path::Path,
) -> String {
    if greenfield {
        return sloppy_joe::config::greenfield_json(
            ecosystem.expect("--greenfield requires --ecosystem"),
        )
        .unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            process::exit(2);
        });
    }

    if from_current {
        return sloppy_joe::config::discover_current_json(project_dir).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            process::exit(2);
        });
    }

    sloppy_joe::config::template_json()
}

fn create_registered_init_config(
    project_dir: &std::path::Path,
    config_home: &std::path::Path,
    config_json: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let git_root = match sloppy_joe::config::registry::find_git_root(project_dir)? {
        Some(root) => root,
        None => {
            return Err(format!(
                "Not inside a git repository.\n  Path: {}\n  Fix: Run this command from inside a git repo, or write a template to a safe external path with `sloppy-joe init > /secure/sloppy-joe.json`.",
                project_dir.display()
            ));
        }
    };

    let dirname = repo_dirname(&git_root);
    let config_dir = config_home.join(&dirname);
    let config_path = config_dir.join("config.json");

    if config_path.exists() {
        return Err(format!(
            "Config already exists at {}.\n  Fix: Use `sloppy-joe register` to re-register without overwriting.",
            config_path.display()
        ));
    }

    std::fs::create_dir_all(&config_dir).map_err(|e| {
        format!(
            "Could not create config directory.\n  Path: {}\n  Error: {}\n  Fix: Check directory permissions.",
            config_dir.display(),
            e
        )
    })?;

    write_config_json(&config_path, config_json)?;
    sloppy_joe::config::registry::register_at_config_home(&git_root, &config_path, config_home)?;
    Ok((git_root, config_path))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            full,
            ci,
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
            let scan_mode = match resolve_scan_mode(full, ci) {
                Ok(mode) => mode,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }
            };
            let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
            let config_source = require_config(config.as_deref(), &dir);
            let opts = sloppy_joe::ScanOptions {
                scan_mode: match scan_mode {
                    ScanMode::Fast => sloppy_joe::ScanMode::Fast,
                    ScanMode::Full => sloppy_joe::ScanMode::Full,
                    ScanMode::Ci => sloppy_joe::ScanMode::Ci,
                },
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
                        if matches!(scan_mode, ScanMode::Fast) {
                            println!("\n{}", fast_mode_ci_guidance());
                        }
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
        Commands::Init {
            greenfield,
            ecosystem,
            from_current,
            register,
            global,
        } => {
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
                            "Error: Not inside a git repository.\n  Path: {}\n  Fix: Run this command from inside a git repo, or write a template to a safe external path with `sloppy-joe init > /secure/sloppy-joe.json`.",
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
                let config_json =
                    init_config_json(greenfield, ecosystem.as_deref(), from_current, &git_root);
                let (git_root, config_path) =
                    match create_registered_init_config(&dir, &config_home, &config_json) {
                        Ok(result) => result,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            process::exit(2);
                        }
                    };

                eprintln!("Config created: {}", config_path.display());
                eprintln!(
                    "Registered: {} -> {}",
                    git_root.display(),
                    config_path.display()
                );
                if from_current {
                    eprintln!(
                        "Seeded config from the current repo state. Review bootstrap_review suggestions before enforcing canonicals."
                    );
                } else if greenfield {
                    eprintln!(
                        "Created an ecosystem-specific starter policy. Review and tighten it before pushing."
                    );
                } else {
                    eprintln!("Edit the config to add your policy.");
                }
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

                if let Err(e) =
                    write_config_json(&config_path, &sloppy_joe::config::template_json())
                {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }

                eprintln!("Global default config created: {}", config_path.display());
                eprintln!("Edit the config to add your policy.");
                eprintln!("Any unregistered repo will use this config as fallback.");
            } else if greenfield || from_current {
                println!(
                    "{}",
                    init_config_json(
                        greenfield,
                        ecosystem.as_deref(),
                        from_current,
                        std::path::Path::new(".")
                    )
                );
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
    use clap::error::ErrorKind;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let unique = format!(
            "sloppy-joe-main-test-{}-{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &std::path::Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn resolve_scan_mode_defaults_to_fast() {
        assert_eq!(resolve_scan_mode(false, false), Ok(ScanMode::Fast));
    }

    #[test]
    fn resolve_scan_mode_selects_full() {
        assert_eq!(resolve_scan_mode(true, false), Ok(ScanMode::Full));
    }

    #[test]
    fn resolve_scan_mode_selects_ci() {
        assert_eq!(resolve_scan_mode(false, true), Ok(ScanMode::Ci));
    }

    #[test]
    fn resolve_scan_mode_rejects_full_and_ci_together() {
        assert_eq!(
            resolve_scan_mode(true, true),
            Err("--full and --ci cannot be used together".to_string())
        );
    }

    #[test]
    fn fast_mode_guidance_mentions_ci_and_full() {
        let message = fast_mode_ci_guidance();
        assert!(message.contains("check --ci"));
        assert!(message.contains("check --full"));
    }

    #[test]
    fn check_cli_defaults_to_fast_mode() {
        let cli = Cli::try_parse_from(["sloppy-joe", "check"])
            .expect("check command should parse without scan mode flags");

        match cli.command {
            Commands::Check { full, ci, .. } => {
                assert!(!full);
                assert!(!ci);
                assert_eq!(resolve_scan_mode(full, ci), Ok(ScanMode::Fast));
            }
            _ => panic!("expected check command"),
        }
    }

    #[test]
    fn check_cli_full_selects_full_mode() {
        let cli = Cli::try_parse_from(["sloppy-joe", "check", "--full"])
            .expect("check command should parse --full");

        match cli.command {
            Commands::Check { full, ci, .. } => {
                assert!(full);
                assert!(!ci);
                assert_eq!(resolve_scan_mode(full, ci), Ok(ScanMode::Full));
            }
            _ => panic!("expected check command"),
        }
    }

    #[test]
    fn check_cli_ci_selects_ci_mode() {
        let cli = Cli::try_parse_from(["sloppy-joe", "check", "--ci"])
            .expect("check command should parse --ci");

        match cli.command {
            Commands::Check { full, ci, .. } => {
                assert!(!full);
                assert!(ci);
                assert_eq!(resolve_scan_mode(full, ci), Ok(ScanMode::Ci));
            }
            _ => panic!("expected check command"),
        }
    }

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

    #[test]
    fn check_cli_rejects_full_and_ci_together() {
        let err = match Cli::try_parse_from(["sloppy-joe", "check", "--full", "--ci"]) {
            Ok(_) => panic!("check command should reject conflicting scan modes"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn init_cli_parses_greenfield_with_ecosystem() {
        let cli = Cli::try_parse_from(["sloppy-joe", "init", "--greenfield", "--ecosystem", "npm"])
            .expect("init command should parse greenfield with ecosystem");

        match cli.command {
            Commands::Init {
                greenfield,
                from_current,
                ecosystem,
                register,
                global,
            } => {
                assert!(greenfield);
                assert!(!from_current);
                assert_eq!(ecosystem.as_deref(), Some("npm"));
                assert!(!register);
                assert!(!global);
            }
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn init_cli_parses_from_current() {
        let cli = Cli::try_parse_from(["sloppy-joe", "init", "--from-current"])
            .expect("init command should parse from-current");

        match cli.command {
            Commands::Init {
                greenfield,
                from_current,
                ecosystem,
                register,
                global,
            } => {
                assert!(!greenfield);
                assert!(from_current);
                assert_eq!(ecosystem, None);
                assert!(!register);
                assert!(!global);
            }
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn init_cli_rejects_greenfield_without_ecosystem() {
        let err = match Cli::try_parse_from(["sloppy-joe", "init", "--greenfield"]) {
            Ok(_) => panic!("init command should require ecosystem for greenfield"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn init_cli_rejects_greenfield_and_from_current_together() {
        let err = match Cli::try_parse_from([
            "sloppy-joe",
            "init",
            "--greenfield",
            "--ecosystem",
            "npm",
            "--from-current",
        ]) {
            Ok(_) => panic!("init command should reject conflicting bootstrap modes"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn init_cli_rejects_greenfield_with_global() {
        let err = match Cli::try_parse_from([
            "sloppy-joe",
            "init",
            "--greenfield",
            "--ecosystem",
            "npm",
            "--global",
        ]) {
            Ok(_) => panic!("init command should reject greenfield with global"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn init_cli_rejects_from_current_with_global() {
        let err = match Cli::try_parse_from(["sloppy-joe", "init", "--from-current", "--global"]) {
            Ok(_) => panic!("init command should reject from-current with global"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn init_cli_allows_greenfield_with_register() {
        let cli = Cli::try_parse_from([
            "sloppy-joe",
            "init",
            "--greenfield",
            "--ecosystem",
            "npm",
            "--register",
        ])
        .expect("init command should allow greenfield with register");

        match cli.command {
            Commands::Init {
                greenfield,
                from_current,
                ecosystem,
                register,
                global,
            } => {
                assert!(greenfield);
                assert!(!from_current);
                assert_eq!(ecosystem.as_deref(), Some("npm"));
                assert!(register);
                assert!(!global);
            }
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn create_registered_init_config_writes_config_and_registry() {
        let dir = unique_temp_dir("register");
        let repo = dir.join("repo");
        let config_home = dir.join("config-home");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let (git_root, config_path) = create_registered_init_config(
            &repo,
            &config_home,
            &sloppy_joe::config::template_json(),
        )
        .expect("register helper should write config and registry");
        let canonical_config_path = std::fs::canonicalize(&config_path).unwrap();

        assert_eq!(git_root, std::fs::canonicalize(&repo).unwrap());
        assert!(config_path.exists());
        let registry_path = config_home.join("registry.json");
        let registry: BTreeMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(&registry_path).unwrap()).unwrap();
        assert_eq!(
            registry.get(&git_root.to_string_lossy().to_string()),
            Some(&canonical_config_path.to_string_lossy().to_string())
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn create_registered_init_config_rejects_existing_config() {
        let dir = unique_temp_dir("register-existing");
        let repo = dir.join("repo");
        let config_home = dir.join("config-home");
        let config_path = config_home.join("repo").join("config.json");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        write_file(&config_path, "{}");

        let err = create_registered_init_config(
            &repo,
            &config_home,
            &sloppy_joe::config::template_json(),
        )
        .expect_err("existing config path must not be overwritten");
        assert!(err.contains("Config already exists"));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
