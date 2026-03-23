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
}
