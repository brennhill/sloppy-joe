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
fn check_cli_parses_python_profile_flags() {
    let cli = Cli::try_parse_from([
        "sloppy-joe",
        "check",
        "--python-groups",
        "dev,test",
        "--python-extras",
        "docs",
        "--python-platform",
        "linux",
        "--python-version",
        "3.12",
        "--python-arch",
        "aarch64",
    ])
    .expect("check command should parse python profile flags");

    match cli.command {
        Commands::Check {
            python_groups,
            python_extras,
            python_platform,
            python_version,
            python_arch,
            ..
        } => {
            assert_eq!(python_groups.as_deref(), Some("dev,test"));
            assert_eq!(python_extras.as_deref(), Some("docs"));
            assert_eq!(python_platform.as_deref(), Some("linux"));
            assert_eq!(python_version.as_deref(), Some("3.12"));
            assert_eq!(python_arch.as_deref(), Some("aarch64"));
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

    let (git_root, config_path) =
        create_registered_init_config(&repo, &config_home, &sloppy_joe::bootstrap::template_json())
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

    let err =
        create_registered_init_config(&repo, &config_home, &sloppy_joe::bootstrap::template_json())
            .expect_err("existing config path must not be overwritten");
    assert!(err.contains("Config already exists"));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn create_registered_init_config_rejects_in_repo_config_home() {
    let dir = unique_temp_dir("register-in-repo-config");
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();

    let err = create_registered_init_config(
        &repo,
        &repo.join(".config-home"),
        &sloppy_joe::bootstrap::template_json(),
    )
    .expect_err("config path under repo must be rejected before writes");
    assert!(err.contains("outside the project directory"));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn ensure_global_init_target_safe_rejects_in_repo_default_config() {
    let dir = unique_temp_dir("global-in-repo-config");
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();

    let err = ensure_global_init_target_safe(&repo, &repo.join(".config-home"))
        .expect_err("global config path under repo must be rejected");
    assert!(err.contains("outside the project directory"));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn ensure_global_init_target_safe_rejects_non_git_project_local_config_home() {
    let dir = unique_temp_dir("global-in-project-config");
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();

    let err = ensure_global_init_target_safe(&project, &project.join(".config-home"))
        .expect_err("global config path under a non-git project must be rejected");
    assert!(err.contains("outside the project directory"));

    std::fs::remove_dir_all(&dir).unwrap();
}
