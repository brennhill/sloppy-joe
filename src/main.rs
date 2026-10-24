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
  sloppy-joe check --python-groups dev,test    Scan only these Python groups (default: all)
  sloppy-joe check --python-extras docs        Scan only these Python extras (default: all)
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

        /// Singles out dependencies added since this git ref (for example HEAD, or
        /// origin/main in CI) for extra scrutiny. Off unless given.
        #[arg(long, value_name = "REF")]
        base_ref: Option<String>,

        /// Disable reading from disk caches, including OSV.
        #[arg(long)]
        no_cache: bool,

        /// Directory to store scan cache files.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,

        /// Scan only these Python dependency groups (comma-separated). Default: every group.
        #[arg(long, value_name = "GROUPS")]
        python_groups: Option<String>,

        /// Scan only these Python extras (comma-separated). Default: every extra.
        #[arg(long, value_name = "EXTRAS")]
        python_extras: Option<String>,

        /// Override the Python target platform for marker evaluation.
        #[arg(long, value_name = "PLATFORM")]
        python_platform: Option<String>,

        /// Override the Python target architecture for marker evaluation.
        #[arg(long, value_name = "ARCH")]
        python_arch: Option<String>,

        /// Override the Python target version for marker evaluation.
        #[arg(long, value_name = "VERSION")]
        python_version: Option<String>,
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

fn split_csv_arg(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
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
        return sloppy_joe::bootstrap::greenfield_json(
            ecosystem.expect("--greenfield requires --ecosystem"),
        )
        .unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            process::exit(2);
        });
    }

    if from_current {
        return sloppy_joe::bootstrap::discover_current_json(project_dir).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            process::exit(2);
        });
    }

    sloppy_joe::bootstrap::template_json()
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
    sloppy_joe::config::registry::ensure_config_path_outside_repo(
        &git_root,
        &config_path,
        "Config file",
    )?;

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

fn ensure_global_init_target_safe(
    project_dir: &std::path::Path,
    config_home: &std::path::Path,
) -> Result<(), String> {
    sloppy_joe::config::registry::ensure_config_home_outside_project(project_dir, config_home)
}

/// Print an error to stderr and exit with the runtime-error status.
fn exit_with(message: impl std::fmt::Display) -> ! {
    eprintln!("Error: {}", message);
    process::exit(2);
}

fn current_dir_or_exit() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|e| {
        exit_with(format!(
            "Could not determine current directory.\n  Error: {}\n  Fix: Check directory permissions.",
            e
        ))
    })
}

fn config_home_or_exit() -> PathBuf {
    sloppy_joe::config::registry::config_home().unwrap_or_else(|e| exit_with(e))
}

fn canonical_dir_or_exit(dir: PathBuf) -> PathBuf {
    std::fs::canonicalize(&dir).unwrap_or_else(|e| {
        exit_with(format!(
            "Could not resolve directory.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists.",
            dir.display(),
            e
        ))
    })
}

/// Git root of `dir`, or exit with `not_a_repo_fix` as the remedy.
fn git_root_or_exit(dir: &std::path::Path, not_a_repo_fix: &str) -> PathBuf {
    match sloppy_joe::config::registry::find_git_root(dir) {
        Ok(Some(root)) => root,
        Ok(None) => exit_with(format!(
            "Not inside a git repository.\n  Path: {}\n  Fix: {}",
            dir.display(),
            not_a_repo_fix
        )),
        Err(e) => exit_with(e),
    }
}

struct CheckArgs {
    full: bool,
    ci: bool,
    project_type: Option<String>,
    json: bool,
    review_exceptions: bool,
    dir: PathBuf,
    config: Option<String>,
    deep: bool,
    paranoid: bool,
    base_ref: Option<String>,
    no_cache: bool,
    cache_dir: Option<PathBuf>,
    python_groups: Option<String>,
    python_extras: Option<String>,
    python_platform: Option<String>,
    python_arch: Option<String>,
    python_version: Option<String>,
}

async fn run_check(args: CheckArgs) {
    let scan_mode = match resolve_scan_mode(args.full, args.ci) {
        Ok(mode) => mode,
        Err(e) => exit_with(e),
    };
    let dir = std::fs::canonicalize(&args.dir).unwrap_or(args.dir);
    let config_source = require_config(args.config.as_deref(), &dir);
    let opts = sloppy_joe::ScanOptions {
        scan_mode: match scan_mode {
            ScanMode::Fast => sloppy_joe::ScanMode::Fast,
            ScanMode::Full => sloppy_joe::ScanMode::Full,
            ScanMode::Ci => sloppy_joe::ScanMode::Ci,
        },
        deep: args.deep,
        paranoid: args.paranoid,
        no_cache: args.no_cache,
        cache_dir: args.cache_dir.as_deref(),
        disable_osv_disk_cache: false,
        skip_hash_check: false,
        review_exceptions: args.review_exceptions,
        python_groups: split_csv_arg(args.python_groups.as_deref()),
        python_extras: split_csv_arg(args.python_extras.as_deref()),
        python_platform: args.python_platform,
        python_arch: args.python_arch,
        python_version: args.python_version,
        base_ref: args.base_ref,
        ..Default::default()
    };
    match sloppy_joe::scan_with_source_full_options(
        &dir,
        args.project_type.as_deref(),
        config_source.as_deref(),
        &opts,
    )
    .await
    {
        Ok(report) => {
            if args.json {
                report.print_json();
            } else {
                report.print_human();
                if matches!(scan_mode, ScanMode::Fast) {
                    println!("\n{}", fast_mode_ci_guidance());
                }
            }
            if report.has_incomplete_projects() {
                process::exit(2);
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

async fn run_cache(
    project_type: Option<String>,
    dir: PathBuf,
    config: Option<String>,
    deep: bool,
    paranoid: bool,
    cache_dir: Option<PathBuf>,
) {
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
            report.print_human();
            eprintln!(
                "Cache warm-up finished. {} packages indexed.",
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

struct InitArgs {
    greenfield: bool,
    ecosystem: Option<String>,
    from_current: bool,
    register: bool,
    global: bool,
}

fn run_init(args: InitArgs) {
    if args.register && args.global {
        exit_with(
            "Use --register or --global, not both.\n  Fix: --register creates per-project config, --global creates a shared default.",
        );
    }
    if args.register {
        init_register(&args);
    } else if args.global {
        init_global();
    } else if args.greenfield || args.from_current {
        println!(
            "{}",
            init_config_json(
                args.greenfield,
                args.ecosystem.as_deref(),
                args.from_current,
                std::path::Path::new(".")
            )
        );
    } else {
        // No flags: print template to stdout (backward compat)
        sloppy_joe::bootstrap::print_template();
    }
}

/// Create config at {config_home}/{dirname}/config.json and register cwd.
fn init_register(args: &InitArgs) {
    let dir = current_dir_or_exit();
    let git_root = git_root_or_exit(
        &dir,
        "Run this command from inside a git repo, or write a template to a safe external path with `sloppy-joe init > /secure/sloppy-joe.json`.",
    );
    let config_home = config_home_or_exit();
    let config_json = init_config_json(
        args.greenfield,
        args.ecosystem.as_deref(),
        args.from_current,
        &git_root,
    );
    let (git_root, config_path) = create_registered_init_config(&dir, &config_home, &config_json)
        .unwrap_or_else(|e| exit_with(e));

    eprintln!("Config created: {}", config_path.display());
    eprintln!(
        "Registered: {} -> {}",
        git_root.display(),
        config_path.display()
    );
    if args.from_current {
        eprintln!(
            "Seeded config from the current repo state. Review bootstrap_review suggestions before enforcing canonicals."
        );
    } else if args.greenfield {
        eprintln!(
            "Created an ecosystem-specific starter policy. Review and tighten it before pushing."
        );
    } else {
        eprintln!("Edit the config to add your policy.");
    }
}

/// Create the global default config at {config_home}/default/config.json.
fn init_global() {
    let config_home = config_home_or_exit();
    let default_dir = config_home.join("default");
    let config_path = default_dir.join("config.json");
    let current_dir = current_dir_or_exit();
    if let Err(e) = ensure_global_init_target_safe(&current_dir, &config_home) {
        exit_with(e);
    }

    if let Err(e) = std::fs::create_dir_all(&default_dir) {
        exit_with(format!(
            "Could not create default config directory.\n  Path: {}\n  Error: {}\n  Fix: Check directory permissions.",
            default_dir.display(),
            e
        ));
    }

    if let Err(e) = write_config_json(&config_path, &sloppy_joe::bootstrap::template_json()) {
        exit_with(e);
    }

    eprintln!("Global default config created: {}", config_path.display());
    eprintln!("Edit the config to add your policy.");
    eprintln!("Any unregistered repo will use this config as fallback.");
}

fn run_register(dir: PathBuf, config: Option<String>) {
    let dir = canonical_dir_or_exit(dir);
    let git_root = git_root_or_exit(&dir, "Run this command from inside a git repo.");

    let config_path = match config {
        Some(explicit) => std::fs::canonicalize(&explicit).unwrap_or_else(|e| {
            exit_with(format!(
                "Could not resolve config path.\n  Path: {}\n  Error: {}\n  Fix: Check that the config file exists.",
                explicit, e
            ))
        }),
        // Default: {config_home}/{dirname}/config.json
        None => config_home_or_exit()
            .join(repo_dirname(&git_root))
            .join("config.json"),
    };

    if !config_path.exists() {
        exit_with(format!(
            "Config file does not exist.\n  Path: {}\n  Fix: Create it first with `sloppy-joe init --register` or create it manually.",
            config_path.display()
        ));
    }

    if let Err(e) = sloppy_joe::config::registry::register(&git_root, &config_path) {
        exit_with(e);
    }

    eprintln!(
        "Registered: {} -> {}",
        git_root.display(),
        config_path.display()
    );
}

fn run_unregister(dir: PathBuf) {
    let dir = canonical_dir_or_exit(dir);
    let git_root = git_root_or_exit(&dir, "Run this command from inside a git repo.");

    match sloppy_joe::config::registry::unregister(&git_root) {
        Ok(true) => eprintln!("Unregistered: {}", git_root.display()),
        Ok(false) => eprintln!("Warning: {} was not registered.", git_root.display()),
        Err(e) => exit_with(e),
    }
}

fn run_list() {
    let entries = sloppy_joe::config::registry::load_registry().unwrap_or_else(|e| exit_with(e));

    if entries.is_empty() {
        eprintln!("No repos registered.");
        eprintln!("Run `sloppy-joe register` in a git repo to get started.");
    } else {
        for (repo, config) in &entries {
            println!("{} -> {}", repo, config);
        }
    }
}

#[tokio::main]
async fn main() {
    match Cli::parse().command {
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
            base_ref,
            no_cache,
            cache_dir,
            python_groups,
            python_extras,
            python_platform,
            python_arch,
            python_version,
        } => {
            run_check(CheckArgs {
                full,
                ci,
                project_type,
                json,
                review_exceptions,
                dir,
                config,
                deep,
                paranoid,
                base_ref,
                no_cache,
                cache_dir,
                python_groups,
                python_extras,
                python_platform,
                python_arch,
                python_version,
            })
            .await
        }
        Commands::Cache {
            project_type,
            dir,
            config,
            deep,
            paranoid,
            cache_dir,
        } => run_cache(project_type, dir, config, deep, paranoid, cache_dir).await,
        Commands::Init {
            greenfield,
            ecosystem,
            from_current,
            register,
            global,
        } => run_init(InitArgs {
            greenfield,
            ecosystem,
            from_current,
            register,
            global,
        }),
        Commands::Register { dir, config } => run_register(dir, config),
        Commands::Unregister { dir } => run_unregister(dir),
        Commands::List => run_list(),
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
