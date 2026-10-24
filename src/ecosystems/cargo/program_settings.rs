//! Cargo config settings that run a program or pull in more config, which the scan cannot see.

/// Flags whose presence in a `rustflags` value makes rustc run a program or load code.
const PROGRAM_FLAGS: &[&str] = &[
    "linker",
    "link-arg",
    "link-args",
    "codegen-backend",
    "llvm-args",
    "-Z",
];

/// `[env]` names that are plainly inert. Build scripts and the `cc`, `cmake`, `pkg-config` and
/// `protoc` helpers read any other variable to decide which program to run, so a repository's
/// `[env]` may set only these.
const INERT_ENV_NAMES: &[&str] = &["RUST_BACKTRACE", "RUST_LIB_BACKTRACE", "RUST_LOG"];

fn env_name_is_inert(name: &str) -> bool {
    INERT_ENV_NAMES.contains(&name)
}

/// Flags whose presence in a `rustflags` value makes rustc run a program, load code or link
/// something the scan has not seen.
fn token_runs_programs(token: &str) -> bool {
    // `@file` makes rustc read more flags from a file in the repository.
    token.starts_with('@')
        || token.starts_with("-l")
        || token.starts_with("-L")
        || PROGRAM_FLAGS.iter().any(|flag| token.contains(flag))
}

fn flags_run_programs(value: &toml::Value) -> bool {
    let tokens: Vec<String> = match value {
        toml::Value::String(text) => text.split_whitespace().map(str::to_string).collect(),
        toml::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .flat_map(|item| {
                item.split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .collect(),
        _ => return true,
    };
    tokens.iter().any(|token| token_runs_programs(token))
}

/// Names of the settings in `value` that run a program or include another config file.
pub(super) fn program_running_settings(value: &toml::Value) -> Vec<String> {
    let mut found = Vec::new();
    if value.get("include").is_some() {
        found.push("include".to_string());
    }
    if let Some(build) = value.get("build") {
        for key in ["rustc", "rustdoc"] {
            if build.get(key).is_some() {
                found.push(format!("build.{key}"));
            }
        }
    }
    let mut tables = vec![("build".to_string(), value.get("build"))];
    if let Some(targets) = value.get("target").and_then(|t| t.as_table()) {
        for (triple, table) in targets {
            tables.push((format!("target.{triple}"), Some(table)));
        }
    }
    for (name, table) in tables {
        let Some(table) = table else { continue };
        for key in ["linker", "runner"] {
            if name.starts_with("target.") && table.get(key).is_some() {
                found.push(format!("{name}.{key}"));
            }
        }
        for key in ["rustflags", "rustdocflags"] {
            if table.get(key).is_some_and(flags_run_programs) {
                found.push(format!("{name}.{key}"));
            }
        }
    }
    if let Some(env) = value.get("env").and_then(|e| e.as_table()) {
        found.extend(
            env.keys()
                .filter(|name| !env_name_is_inert(name))
                .map(|name| format!("env.{name}")),
        );
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(config: &str) -> Vec<String> {
        program_running_settings(&toml::from_str(config).unwrap())
    }

    #[test]
    fn argfiles_native_links_and_llvm_args_in_flags_block() {
        for flags in [
            r#"["@/abs/tools/flags.txt"]"#,
            r#"["-l", "static=evil", "-L", "tools"]"#,
            r#"["-lstatic=evil"]"#,
            r#"["-Cllvm-args=-load=x.so"]"#,
            r#"["-C", "llvm-args=-load=x.so"]"#,
            r#""@flags.txt""#,
        ] {
            let found = settings(&format!("[build]\nrustflags = {flags}\n"));
            assert_eq!(found, vec!["build.rustflags"], "{flags}");
        }
        assert!(settings("[build]\nrustflags = [\"-C\", \"target-cpu=native\"]\n").is_empty());
    }

    #[test]
    fn only_inert_env_names_pass() {
        assert!(settings("[env]\nRUST_BACKTRACE = \"1\"\nRUST_LOG = \"info\"\n").is_empty());
        for name in [
            "CC_aarch64_apple_darwin",
            "TARGET_CC",
            "HOST_CC",
            "CFLAGS",
            "PROTOC",
            "CMAKE",
            "PKG_CONFIG",
            "MY_TOOL",
        ] {
            let found = settings(&format!(
                "[env]\n{name} = {{ value = \"tools/x.sh\", relative = true }}\n"
            ));
            assert_eq!(found, vec![format!("env.{name}")], "{name}");
        }
    }
}
