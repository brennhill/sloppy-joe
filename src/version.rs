use crate::Ecosystem;

pub fn exact_version(raw: &str, ecosystem: Ecosystem) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    match ecosystem {
        Ecosystem::PyPI => {
            let exact = raw.strip_prefix("==")?.trim();
            if exact.is_empty()
                || exact.contains(',')
                || exact.contains(';')
                || exact.contains(' ')
                || has_wildcard_syntax(exact)
            {
                return None;
            }
            Some(exact.to_string())
        }
        Ecosystem::Cargo => {
            let exact = raw.strip_prefix('=')?.trim();
            if exact.is_empty() || has_range_syntax(exact) {
                return None;
            }
            Some(exact.to_string())
        }
        Ecosystem::Npm => {
            if has_range_syntax(raw) || has_wildcard_syntax(raw) || raw.matches('.').count() < 2 {
                return None;
            }
            Some(raw.to_string())
        }
        _ => {
            if has_range_syntax(raw) {
                return None;
            }
            Some(raw.to_string())
        }
    }
}

fn has_range_syntax(raw: &str) -> bool {
    raw.starts_with("workspace:")
        || raw.starts_with("file:")
        || raw.starts_with("git")
        || raw.contains("://")
        || raw.contains(',')
        || raw.contains("||")
        || raw.contains(' ')
        || raw.chars().any(|ch| {
            matches!(
                ch,
                '^' | '~' | '>' | '<' | '!' | '*' | '[' | ']' | '(' | ')'
            )
        })
}

fn has_wildcard_syntax(raw: &str) -> bool {
    raw.split(['.', '-', '+'])
        .any(|part| matches!(part, "*" | "x" | "X"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_exact_versions_require_a_literal_release() {
        assert_eq!(exact_version("1.2.3", Ecosystem::Npm), Some("1.2.3".to_string()));
        assert_eq!(exact_version("^1.2.3", Ecosystem::Npm), None);
        assert_eq!(exact_version("1", Ecosystem::Npm), None);
    }

    #[test]
    fn pypi_requires_double_equals_for_exact_versions() {
        assert_eq!(
            exact_version("==2.31.0", Ecosystem::PyPI),
            Some("2.31.0".to_string())
        );
        assert_eq!(exact_version(">=2.31.0", Ecosystem::PyPI), None);
        assert_eq!(exact_version("==2.31.*", Ecosystem::PyPI), None);
    }

    #[test]
    fn cargo_requires_explicit_equals_for_exact_versions() {
        assert_eq!(exact_version("=1.2.3", Ecosystem::Cargo), Some("1.2.3".to_string()));
        assert_eq!(exact_version("1.2.3", Ecosystem::Cargo), None);
    }

    #[test]
    fn npm_rejects_wildcard_versions() {
        assert_eq!(exact_version("1.2.x", Ecosystem::Npm), None);
        assert_eq!(exact_version("1.2.*", Ecosystem::Npm), None);
        assert_eq!(exact_version("1.2.X", Ecosystem::Npm), None);
    }

    // ── empty string early return (line 6) ──

    #[test]
    fn empty_string_returns_none() {
        assert_eq!(exact_version("", Ecosystem::Npm), None);
        assert_eq!(exact_version("", Ecosystem::PyPI), None);
        assert_eq!(exact_version("", Ecosystem::Cargo), None);
        assert_eq!(exact_version("", Ecosystem::Go), None);
        assert_eq!(exact_version("", Ecosystem::Ruby), None);
    }

    #[test]
    fn whitespace_only_returns_none() {
        assert_eq!(exact_version("   ", Ecosystem::Npm), None);
        assert_eq!(exact_version("  \t  ", Ecosystem::Cargo), None);
    }

    // ── Cargo edge cases (line 24-25) ──

    #[test]
    fn cargo_equals_empty_after_prefix_returns_none() {
        // "=" with nothing after it — line 24 exact.is_empty() check
        assert_eq!(exact_version("=", Ecosystem::Cargo), None);
    }

    #[test]
    fn cargo_equals_with_range_syntax_returns_none() {
        // "=" followed by something with range syntax — line 24 has_range_syntax check
        assert_eq!(exact_version("=>=1.0", Ecosystem::Cargo), None);
        assert_eq!(exact_version("=^1.0", Ecosystem::Cargo), None);
        assert_eq!(exact_version("=1.0,2.0", Ecosystem::Cargo), None);
    }

    #[test]
    fn cargo_no_equals_prefix_returns_none() {
        // No "=" prefix at all — strip_prefix returns None
        assert_eq!(exact_version("1.2.3", Ecosystem::Cargo), None);
        assert_eq!(exact_version("^1.2.3", Ecosystem::Cargo), None);
    }

    // ── Other ecosystem fallback (line 35-41) ──

    #[test]
    fn other_ecosystems_accept_plain_version() {
        assert_eq!(
            exact_version("7.0.4", Ecosystem::Ruby),
            Some("7.0.4".to_string())
        );
        assert_eq!(
            exact_version("1.0.0", Ecosystem::Go),
            Some("1.0.0".to_string())
        );
        assert_eq!(
            exact_version("13.0.1", Ecosystem::Dotnet),
            Some("13.0.1".to_string())
        );
    }

    #[test]
    fn other_ecosystems_reject_range_syntax() {
        assert_eq!(exact_version("~> 7.0", Ecosystem::Ruby), None);
        assert_eq!(exact_version(">=1.0", Ecosystem::Go), None);
        assert_eq!(exact_version("^13.0", Ecosystem::Dotnet), None);
        assert_eq!(exact_version("workspace:*", Ecosystem::Ruby), None);
    }

    // ── PyPI edge cases ──

    #[test]
    fn pypi_rejects_double_equals_with_semicolon() {
        // Contains ';' — rejected
        assert_eq!(exact_version("==2.31.0; python_version >= '3.8'", Ecosystem::PyPI), None);
    }

    #[test]
    fn pypi_rejects_double_equals_with_comma() {
        assert_eq!(exact_version("==2.31.0,!=2.31.1", Ecosystem::PyPI), None);
    }

    #[test]
    fn pypi_rejects_double_equals_with_embedded_space() {
        // Space inside the version string (not trailing whitespace which gets trimmed)
        assert_eq!(exact_version("==2.31.0 beta", Ecosystem::PyPI), None);
    }

    #[test]
    fn pypi_double_equals_empty_version() {
        assert_eq!(exact_version("==", Ecosystem::PyPI), None);
    }
}
