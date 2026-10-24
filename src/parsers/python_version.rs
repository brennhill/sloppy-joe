//! Version-specifier matching for Python-style constraints (uv, Pipfile, Poetry).
use anyhow::{Result, bail};

pub(crate) fn version_matches_uv_specifier(version: &str, specifier: Option<&str>) -> Result<bool> {
    let version: pep440_rs::Version = version.parse()?;
    let Some(specifier) = specifier.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(true);
    };
    let mut clauses = Vec::new();
    for clause in specifier.split(',').map(str::trim) {
        if clause == "*" {
            continue;
        }
        if let Some(lower) = clause.strip_prefix('^') {
            clauses.push(format!(">={},<{}", lower.trim(), caret_upper_bound(lower)?));
        } else if let Some(lower) = clause
            .strip_prefix('~')
            .filter(|value| !value.starts_with('='))
        {
            clauses.push(format!(">={},<{}", lower.trim(), tilde_upper_bound(lower)?));
        } else if clause.starts_with(|ch: char| ch.is_ascii_digit()) {
            clauses.push(format!("=={clause}"));
        } else {
            clauses.push(clause.to_string());
        }
    }
    let constraints: pep440_rs::VersionSpecifiers = clauses.join(",").parse()?;
    Ok(constraints.iter().all(|constraint| {
        match constraint.operator() {
            // shortcut: guard truncated wildcards in pep440_rs 0.7.3; remove after an upstream fix.
            pep440_rs::Operator::EqualStar | pep440_rs::Operator::NotEqualStar => {
                let prefix = constraint.version();
                let matches = prefix.epoch() == version.epoch()
                    && prefix.release().iter().enumerate().all(|(index, part)| {
                        version.release().get(index).copied().unwrap_or_default() == *part
                    });
                if *constraint.operator() == pep440_rs::Operator::EqualStar {
                    matches
                } else {
                    !matches
                }
            }
            _ => constraint.contains(&version),
        }
    }))
}

fn parse_numeric_release(value: &str) -> Result<Vec<u64>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("Broken uv.lock: empty version specifier component cannot be trusted exactly");
    }
    trimmed
        .split('.')
        .map(|part| {
            part.trim().parse::<u64>().map_err(|_| {
                anyhow::anyhow!(
                    "Broken uv.lock: unsupported non-numeric uv version specifier component '{}'",
                    crate::report::sanitize_for_terminal(value)
                )
            })
        })
        .collect()
}

fn caret_upper_bound(value: &str) -> Result<String> {
    let mut parts = parse_numeric_release(value)?;
    let index = parts
        .iter()
        .position(|part| *part != 0)
        .unwrap_or(parts.len() - 1);
    parts[index] = parts[index]
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("Python version constraint upper bound is too large"))?;
    parts.truncate(index + 1);
    Ok(parts
        .into_iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

fn tilde_upper_bound(value: &str) -> Result<String> {
    let mut parts = parse_numeric_release(value)?;
    let index = if parts.len() <= 1 { 0 } else { 1 };
    parts[index] = parts[index]
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("Python version constraint upper bound is too large"))?;
    parts.truncate(index + 1);
    Ok(parts
        .into_iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join("."))
}
