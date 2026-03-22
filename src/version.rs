pub fn exact_version(raw: &str, ecosystem: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    match ecosystem {
        "pypi" => {
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
        "cargo" => {
            let exact = raw.strip_prefix('=')?.trim();
            if exact.is_empty() || has_range_syntax(exact) {
                return None;
            }
            Some(exact.to_string())
        }
        "npm" => {
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
        assert_eq!(exact_version("1.2.3", "npm"), Some("1.2.3".to_string()));
        assert_eq!(exact_version("^1.2.3", "npm"), None);
        assert_eq!(exact_version("1", "npm"), None);
    }

    #[test]
    fn pypi_requires_double_equals_for_exact_versions() {
        assert_eq!(
            exact_version("==2.31.0", "pypi"),
            Some("2.31.0".to_string())
        );
        assert_eq!(exact_version(">=2.31.0", "pypi"), None);
        assert_eq!(exact_version("==2.31.*", "pypi"), None);
    }

    #[test]
    fn cargo_requires_explicit_equals_for_exact_versions() {
        assert_eq!(exact_version("=1.2.3", "cargo"), Some("1.2.3".to_string()));
        assert_eq!(exact_version("1.2.3", "cargo"), None);
    }

    #[test]
    fn npm_rejects_wildcard_versions() {
        assert_eq!(exact_version("1.2.x", "npm"), None);
        assert_eq!(exact_version("1.2.*", "npm"), None);
        assert_eq!(exact_version("1.2.X", "npm"), None);
    }
}
