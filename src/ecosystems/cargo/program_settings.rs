//! Predicates for the Cargo config allowlist (`cargo_surface`): which `rustflags` values and `[env]`
//! tables run a program or load code the scan cannot see.

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

/// Whether every name in an `[env]` table is inert.
pub(super) fn env_table_is_inert(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|table| {
        table
            .keys()
            .all(|name| INERT_ENV_NAMES.contains(&name.as_str()))
    })
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

/// Whether a `rustflags`/`rustdocflags` value is a plain list of flags that run nothing.
pub(super) fn flags_are_plain(value: &serde_json::Value) -> bool {
    let tokens: Vec<String> = match value {
        serde_json::Value::String(text) => text.split_whitespace().map(str::to_string).collect(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .flat_map(|item| {
                item.split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .collect(),
        _ => return false,
    };
    !tokens.iter().any(|token| token_runs_programs(token))
}

/// A `rust-toolchain(.toml)` with `path = ...` makes rustup run a cargo and rustc from a directory
/// in the repository (rustup searches the project directory and its parents).
pub(super) fn reject_toolchain_path(project_dir: &std::path::Path) -> anyhow::Result<()> {
    let start = std::fs::canonicalize(project_dir)?;
    for dir in start.ancestors() {
        for name in ["rust-toolchain.toml", "rust-toolchain"] {
            let file = dir.join(name);
            if std::fs::symlink_metadata(&file).is_err() {
                continue;
            }
            let content =
                crate::parsers::read_file_limited(&file, crate::parsers::MAX_MANIFEST_BYTES)?;
            let has_path = toml::from_str::<toml::Value>(&content)
                .ok()
                .and_then(|value| value.get("toolchain")?.get("path").cloned())
                .is_some();
            if has_path {
                anyhow::bail!(
                    "Unsupported rustup toolchain path in {}: rustup would run a cargo and rustc from a directory the scan has not seen",
                    file.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(flags: &str) -> bool {
        let value: toml::Value = toml::from_str(&format!("flags = {flags}")).unwrap();
        flags_are_plain(&serde_json::to_value(&value["flags"]).unwrap())
    }

    #[test]
    fn argfiles_native_links_and_llvm_args_in_flags_are_not_plain() {
        for flags in [
            r#"["@/abs/tools/flags.txt"]"#,
            r#"["-l", "static=evil", "-L", "tools"]"#,
            r#"["-lstatic=evil"]"#,
            r#"["-Cllvm-args=-load=x.so"]"#,
            r#"["-C", "llvm-args=-load=x.so"]"#,
            r#""@flags.txt""#,
        ] {
            assert!(!plain(flags), "{flags}");
        }
        assert!(plain(r#"["-C", "target-cpu=native"]"#));
    }

    #[test]
    fn only_inert_env_names_are_plain() {
        let env = |text: &str| {
            serde_json::to_value(toml::from_str::<toml::Value>(text).unwrap()["env"].clone())
                .unwrap()
        };
        assert!(env_table_is_inert(&env(
            "[env]\nRUST_BACKTRACE = \"1\"\nRUST_LOG = \"info\"\n"
        )));
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
            let table = env(&format!(
                "[env]\n{name} = {{ value = \"tools/x.sh\", relative = true }}\n"
            ));
            assert!(!env_table_is_inert(&table), "{name}");
        }
    }
}

#[cfg(test)]
mod toolchain_tests {
    use super::*;

    #[test]
    fn a_toolchain_path_blocks() {
        let dir = std::env::temp_dir().join(format!("sj-toolchain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\npath = \"tools/rust\"\n",
        )
        .unwrap();
        assert!(reject_toolchain_path(&dir).is_err());
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.80.0\"\n",
        )
        .unwrap();
        assert!(reject_toolchain_path(&dir).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
