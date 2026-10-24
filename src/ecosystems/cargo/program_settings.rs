//! Cargo config settings that run a program or pull in more config, which the scan cannot see.

/// Flags whose presence in a `rustflags` value makes rustc run a program or load code.
const PROGRAM_FLAGS: &[&str] = &["linker", "link-arg", "link-args", "codegen-backend", "-Z"];

/// `[env]` names that change which programs Cargo and rustc run.
fn env_name_runs_programs(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("RUSTC")
        || upper.starts_with("RUSTDOC")
        || upper.starts_with("RUSTFLAGS")
        || upper.starts_with("CARGO_")
        || upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
        || matches!(upper.as_str(), "PATH" | "CC" | "CXX" | "AR" | "LD")
        || ["LINKER", "RUNNER", "WRAPPER"]
            .iter()
            .any(|word| upper.contains(word))
}

fn flags_run_programs(value: &toml::Value) -> bool {
    let text = match value {
        toml::Value::String(text) => text.clone(),
        toml::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        _ => return true,
    };
    PROGRAM_FLAGS.iter().any(|flag| text.contains(flag))
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
                .filter(|name| env_name_runs_programs(name))
                .map(|name| format!("env.{name}")),
        );
    }
    found
}
