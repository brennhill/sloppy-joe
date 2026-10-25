//! Gradle `dependencyLocking { }` read as configuration, not as keywords.
//!
//! Only `lockAllConfigurations()` and the lock mode are understood. Every other
//! locking setting (`unlockAllConfigurations()`, `lockFile`, `ignoredDependencies`,
//! `deactivateDependencyLocking()`, ...) changes which dependencies Gradle checks
//! or which file it reads, so the build is rejected rather than trusted.

use super::*;

/// Whether Gradle enforces `gradle.lockfile` for the build at `path`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GradleLocking {
    /// `dependencyLocking { lockAllConfigurations() }` is active for this project.
    Strict,
    /// Locking is on but `LockMode.LENIENT` lets unlisted dependencies resolve.
    Lenient,
    /// Gradle resolves normally and ignores the lockfile.
    Off,
}

/// Which project a script's `dependencyLocking` block configures.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScriptRole {
    /// The scanned project's own build script.
    Own,
    /// A build script in an enclosing directory (a parent project).
    Parent,
}

#[derive(Default)]
struct LockingState {
    locks: bool,
    lenient: bool,
}

/// Locking settings that never appear outside a parsed `dependencyLocking` block.
const LOCKING_WORDS: &[&str] = &[
    "dependencyLocking",
    "lockAllConfigurations",
    "unlockAllConfigurations",
    "deactivateDependencyLocking",
    "lockFile",
    "lockMode",
    "ignoredDependencies",
];

pub(crate) fn gradle_locking(path: &Path) -> Result<GradleLocking> {
    let project_dir = std::fs::canonicalize(path.parent().unwrap_or(Path::new(".")))?;
    let boundary = gradle_boundary(&project_dir)?;
    let mut state = LockingState::default();
    for dir in project_dir
        .ancestors()
        .take_while(|dir| dir.starts_with(&boundary))
    {
        let role = if dir == project_dir {
            ScriptRole::Own
        } else {
            ScriptRole::Parent
        };
        for name in ["build.gradle", "build.gradle.kts"] {
            let script = dir.join(name);
            if !super::super::path_detected(&script)? {
                continue;
            }
            let content = crate::untrusted::read_script_file(&script)?;
            read_script_locking(&tokenize_gradle(&content), role, &script, &mut state)?;
        }
    }
    Ok(match (state.locks, state.lenient) {
        (false, _) => GradleLocking::Off,
        (true, true) => GradleLocking::Lenient,
        (true, false) => GradleLocking::Strict,
    })
}

fn unsupported(path: &Path, what: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Unsupported Gradle dependency locking in {}: '{}' changes which dependencies Gradle locks or which lockfile it reads, so gradle.lockfile cannot be trusted. Fix: use only `dependencyLocking {{ lockAllConfigurations() }}` with the default lock mode.",
        path.display(),
        crate::report::sanitize_for_terminal(what)
    )
}

/// Whether a `dependencyLocking` block nested in `enclosing` configures the
/// scanned project. `None` means the placement is not understood.
fn block_applies(enclosing: &[String], role: ScriptRole) -> Option<bool> {
    match (enclosing, role) {
        ([], ScriptRole::Own) => Some(true),
        ([], ScriptRole::Parent) => Some(false),
        ([outer], ScriptRole::Own) if outer == "allprojects" => Some(true),
        ([outer], ScriptRole::Own) if outer == "subprojects" => Some(false),
        ([outer], ScriptRole::Parent)
            if matches!(outer.as_str(), "allprojects" | "subprojects") =>
        {
            Some(true)
        }
        // The build script's own classpath: parsed for unsupported settings only.
        ([outer], _) if outer == "buildscript" => Some(false),
        _ => None,
    }
}

fn read_script_locking(
    tokens: &[GradleToken],
    role: ScriptRole,
    path: &Path,
    state: &mut LockingState,
) -> Result<()> {
    let mut enclosing: Vec<String> = Vec::new();
    let mut idx = 0usize;
    while idx < tokens.len() {
        let opens_block = matches!(tokens.get(idx + 1), Some(GradleToken::Symbol('{')));
        match &tokens[idx] {
            GradleToken::Ident(name) if name == "import" => idx += 1,
            GradleToken::Ident(name) if name == "dependencyLocking" && opens_block => {
                let applies = block_applies(&enclosing, role)
                    .ok_or_else(|| unsupported(path, "dependencyLocking (in a nested block)"))?;
                let end = find_gradle_block_end(tokens, idx + 1)
                    .ok_or_else(|| unsupported(path, "dependencyLocking (unclosed)"))?;
                let mut block = LockingState::default();
                read_locking_block(&tokens[idx + 2..end], path, &mut block)?;
                if applies {
                    state.locks |= block.locks;
                    state.lenient |= block.lenient;
                }
                idx = end;
            }
            GradleToken::Ident(name) => {
                if name.split('.').any(|part| LOCKING_WORDS.contains(&part)) {
                    return Err(unsupported(path, name));
                }
                if opens_block {
                    enclosing.push(name.clone());
                    idx += 1;
                }
            }
            GradleToken::Symbol('{') => enclosing.push(String::new()),
            GradleToken::Symbol('}') => {
                enclosing.pop();
            }
            _ => {}
        }
        idx += 1;
    }
    Ok(())
}

/// The statements of one `dependencyLocking { }` block.
fn read_locking_block(block: &[GradleToken], path: &Path, state: &mut LockingState) -> Result<()> {
    use GradleToken::{Ident, Literal, Symbol};
    let mut idx = 0usize;
    while idx < block.len() {
        let rest = &block[idx..];
        let (consumed, mode) = match rest {
            [Ident(call), Symbol('('), Symbol(')'), ..] if call == "lockAllConfigurations" => {
                state.locks = true;
                (3, None)
            }
            [Ident(property), Ident(value), ..] if property == "lockMode" => {
                (2, Some(lock_mode_constant(value)))
            }
            [Ident(set), Symbol('('), Ident(value), Symbol(')'), ..] if set == "lockMode.set" => {
                (4, Some(lock_mode_constant(value)))
            }
            [
                Ident(set),
                Symbol('('),
                Ident(value_of),
                Symbol('('),
                Literal(text),
                Symbol(')'),
                Symbol(')'),
                ..,
            ] if set == "lockMode.set" && is_lock_mode_member(value_of, "valueOf") => {
                (7, Some(Some(text.trim_matches(['"', '\'']).to_string())))
            }
            [Ident(other), ..] => return Err(unsupported(path, other)),
            [Literal(other), ..] => return Err(unsupported(path, other)),
            [Symbol(other), ..] => return Err(unsupported(path, &other.to_string())),
            [] => break,
        };
        if let Some(mode) = mode {
            apply_lock_mode(mode.as_deref(), path, state)?;
        }
        idx += consumed;
    }
    Ok(())
}

fn apply_lock_mode(mode: Option<&str>, path: &Path, state: &mut LockingState) -> Result<()> {
    match mode {
        Some("STRICT" | "DEFAULT") => Ok(()),
        Some("LENIENT") => {
            state.lenient = true;
            Ok(())
        }
        _ => Err(unsupported(path, "lockMode")),
    }
}

/// `LockMode.X` (optionally package-qualified) is a `LockMode` member named `member`.
fn is_lock_mode_member(ident: &str, member: &str) -> bool {
    ident
        .rsplit_once('.')
        .is_some_and(|(owner, name)| name == member && owner.rsplit('.').next() == Some("LockMode"))
}

/// The constant named by `LockMode.X`, or `None` when it is not a `LockMode` constant.
fn lock_mode_constant(ident: &str) -> Option<String> {
    let (owner, name) = ident.rsplit_once('.')?;
    (owner.rsplit('.').next() == Some("LockMode")).then(|| name.to_string())
}

#[cfg(test)]
#[path = "locking_tests.rs"]
mod tests;
