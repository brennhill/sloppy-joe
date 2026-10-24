use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MarkerValue {
    Variable(String),
    Literal(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MarkerOperator {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    In,
    NotIn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MarkerExpr {
    Compare {
        left: MarkerValue,
        op: MarkerOperator,
        right: MarkerValue,
    },
    And(Box<MarkerExpr>, Box<MarkerExpr>),
    Or(Box<MarkerExpr>, Box<MarkerExpr>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MarkerToken {
    Ident(String),
    String(String),
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    In,
    Not,
    And,
    Or,
    LParen,
    RParen,
}

#[cfg(test)]
pub(crate) fn evaluate_marker(marker: &str, profile: &PythonProfile) -> Result<bool> {
    evaluate_marker_with_extra(marker, profile, None)
}

/// Evaluate a project-level marker against the profile's extra selection. When every extra is
/// in scope, the marker matches if it holds for the base install or for any extra it names.
pub(crate) fn evaluate_marker_for_profile_extras(
    marker: &str,
    profile: &PythonProfile,
) -> Result<bool> {
    if !profile.all_extras {
        return evaluate_marker_for_extras(marker, profile, &profile.selected_extras);
    }
    let mut candidates: BTreeSet<String> = BTreeSet::from([String::new()]);
    for token in tokenize_marker(marker)? {
        if let MarkerToken::String(value) = token {
            candidates.insert(value);
        }
    }
    for extra in &candidates {
        if evaluate_marker_with_extra(marker, profile, Some(extra))? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn evaluate_marker_for_extras(
    marker: &str,
    profile: &PythonProfile,
    active_extras: &BTreeSet<String>,
) -> Result<bool> {
    if active_extras.is_empty() {
        return evaluate_marker_with_extra(marker, profile, Some(""));
    }
    for extra in active_extras {
        if evaluate_marker_with_extra(marker, profile, Some(extra))? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn evaluate_marker_with_extra(
    marker: &str,
    profile: &PythonProfile,
    active_extra: Option<&str>,
) -> Result<bool> {
    let tokens = tokenize_marker(marker)?;
    let mut parser = MarkerParser {
        tokens: &tokens,
        index: 0,
    };
    let expr = parser.parse_expr()?;
    if parser.index != parser.tokens.len() {
        bail!(
            "Unsupported Python environment marker '{}': trailing tokens are not supported",
            crate::report::sanitize_for_terminal(marker)
        );
    }
    expr.evaluate(profile, active_extra)
}

impl MarkerExpr {
    pub(crate) fn evaluate(
        &self,
        profile: &PythonProfile,
        active_extra: Option<&str>,
    ) -> Result<bool> {
        match self {
            Self::Compare { left, op, right } => {
                let left = resolve_marker_value(left, profile, active_extra)?;
                let right = resolve_marker_value(right, profile, active_extra)?;
                Ok(match op {
                    MarkerOperator::Eq => {
                        compare_marker_values(&left, &right) == Some(std::cmp::Ordering::Equal)
                    }
                    MarkerOperator::NotEq => {
                        compare_marker_values(&left, &right) != Some(std::cmp::Ordering::Equal)
                    }
                    MarkerOperator::Lt => {
                        compare_marker_values(&left, &right) == Some(std::cmp::Ordering::Less)
                    }
                    MarkerOperator::LtEq => compare_marker_values(&left, &right)
                        .is_some_and(|ordering| ordering != std::cmp::Ordering::Greater),
                    MarkerOperator::Gt => {
                        compare_marker_values(&left, &right) == Some(std::cmp::Ordering::Greater)
                    }
                    MarkerOperator::GtEq => compare_marker_values(&left, &right)
                        .is_some_and(|ordering| ordering != std::cmp::Ordering::Less),
                    MarkerOperator::In => marker_membership(&left, &right),
                    MarkerOperator::NotIn => !marker_membership(&left, &right),
                })
            }
            Self::And(left, right) => {
                Ok(left.evaluate(profile, active_extra)?
                    && right.evaluate(profile, active_extra)?)
            }
            Self::Or(left, right) => {
                Ok(left.evaluate(profile, active_extra)?
                    || right.evaluate(profile, active_extra)?)
            }
        }
    }
}

pub(crate) fn resolve_marker_value(
    value: &MarkerValue,
    profile: &PythonProfile,
    active_extra: Option<&str>,
) -> Result<String> {
    match value {
        MarkerValue::Literal(value) => Ok(value.clone()),
        MarkerValue::Variable(name) => resolve_marker_variable(name, profile, active_extra),
    }
}

pub(crate) fn resolve_marker_variable(
    name: &str,
    profile: &PythonProfile,
    active_extra: Option<&str>,
) -> Result<String> {
    match name {
        "sys_platform" => Ok(profile.target_platform.clone()),
        "os_name" => Ok(match profile.target_platform.as_str() {
            "win32" => "nt".to_string(),
            "darwin" | "linux" => "posix".to_string(),
            other => other.to_string(),
        }),
        "platform_system" => Ok(match profile.target_platform.as_str() {
            "win32" => "Windows".to_string(),
            "darwin" => "Darwin".to_string(),
            "linux" => "Linux".to_string(),
            other => other.to_string(),
        }),
        "platform_machine" => Ok(profile.target_arch.clone()),
        "platform_python_implementation" => Ok("CPython".to_string()),
        "implementation_name" => Ok("cpython".to_string()),
        "implementation_version" => profile.python_full_version.clone().or_else(|| {
            profile
                .python_version
                .as_deref()
                .map(normalize_python_full_version)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Python environment marker requires an explicit implementation version for trusted evaluation"
            )
        }),
        "python_version" => profile.python_version.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "Python environment marker requires an explicit Python version for trusted evaluation"
            )
        }),
        "python_full_version" => profile.python_full_version.clone().or_else(|| {
            profile
                .python_version
                .as_ref()
                .map(|version| format!("{version}.0"))
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Python environment marker requires an explicit full Python version for trusted evaluation"
            )
        }),
        "platform_release" => {
            resolve_host_platform_metadata(name, profile, "-r", "PLATFORM_RELEASE")
        }
        "platform_version" => {
            resolve_host_platform_metadata(name, profile, "-v", "PLATFORM_VERSION")
        }
        "extra" => Ok(active_extra.unwrap_or("").to_string()),
        other => bail!(
            "Unsupported Python environment marker variable '{}'",
            crate::report::sanitize_for_terminal(other)
        ),
    }
}

pub(crate) fn compare_marker_values(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    if looks_like_python_version(left) && looks_like_python_version(right) {
        return Some(compare_python_versions(left, right));
    }
    Some(left.cmp(right))
}

pub(crate) fn looks_like_python_version(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ch == '.' || ch == '*')
}

pub(crate) fn compare_python_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_parts = left.split('.').map(parse_version_part);
    let mut right_parts = right.split('.').map(parse_version_part);
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (Some(left), None) => {
                if left != 0 {
                    return std::cmp::Ordering::Greater;
                }
            }
            (None, Some(right)) => {
                if right != 0 {
                    return std::cmp::Ordering::Less;
                }
            }
            (Some(left), Some(right)) => match left.cmp(&right) {
                std::cmp::Ordering::Equal => {}
                ordering => return ordering,
            },
        }
    }
}

pub(crate) fn parse_version_part(part: &str) -> u64 {
    part.parse::<u64>().unwrap_or(0)
}

pub(crate) fn marker_membership(left: &str, right: &str) -> bool {
    right.contains(left)
}

pub(crate) fn tokenize_marker(marker: &str) -> Result<Vec<MarkerToken>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = marker.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_whitespace() {
            index += 1;
            continue;
        }
        match ch {
            '(' => {
                tokens.push(MarkerToken::LParen);
                index += 1;
            }
            ')' => {
                tokens.push(MarkerToken::RParen);
                index += 1;
            }
            '=' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(MarkerToken::Eq);
                    index += 2;
                } else {
                    bail!(
                        "Unsupported Python environment marker '{}': unexpected '='",
                        crate::report::sanitize_for_terminal(marker)
                    );
                }
            }
            '!' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(MarkerToken::NotEq);
                    index += 2;
                } else {
                    bail!(
                        "Unsupported Python environment marker '{}': unexpected '!'",
                        crate::report::sanitize_for_terminal(marker)
                    );
                }
            }
            '<' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(MarkerToken::LtEq);
                    index += 2;
                } else {
                    tokens.push(MarkerToken::Lt);
                    index += 1;
                }
            }
            '>' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(MarkerToken::GtEq);
                    index += 2;
                } else {
                    tokens.push(MarkerToken::Gt);
                    index += 1;
                }
            }
            '\'' | '"' => {
                let quote = ch;
                index += 1;
                let start = index;
                while index < chars.len() && chars[index] != quote {
                    index += 1;
                }
                if index >= chars.len() {
                    bail!(
                        "Unsupported Python environment marker '{}': unterminated string",
                        crate::report::sanitize_for_terminal(marker)
                    );
                }
                tokens.push(MarkerToken::String(chars[start..index].iter().collect()));
                index += 1;
            }
            _ if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' => {
                let start = index;
                index += 1;
                while index < chars.len()
                    && (chars[index].is_ascii_alphanumeric()
                        || chars[index] == '_'
                        || chars[index] == '.')
                {
                    index += 1;
                }
                let ident: String = chars[start..index].iter().collect();
                tokens.push(match ident.as_str() {
                    "and" => MarkerToken::And,
                    "or" => MarkerToken::Or,
                    "not" => MarkerToken::Not,
                    "in" => MarkerToken::In,
                    _ => MarkerToken::Ident(ident),
                });
            }
            _ => {
                bail!(
                    "Unsupported Python environment marker '{}': unexpected character '{}'",
                    crate::report::sanitize_for_terminal(marker),
                    ch
                );
            }
        }
    }
    Ok(tokens)
}

pub(crate) struct MarkerParser<'a> {
    pub(crate) tokens: &'a [MarkerToken],
    pub(crate) index: usize,
}

impl MarkerParser<'_> {
    pub(crate) fn parse_expr(&mut self) -> Result<MarkerExpr> {
        self.parse_or()
    }

    pub(crate) fn parse_or(&mut self) -> Result<MarkerExpr> {
        let mut expr = self.parse_and()?;
        while matches!(self.peek(), Some(MarkerToken::Or)) {
            self.index += 1;
            let right = self.parse_and()?;
            expr = MarkerExpr::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    pub(crate) fn parse_and(&mut self) -> Result<MarkerExpr> {
        let mut expr = self.parse_primary()?;
        while matches!(self.peek(), Some(MarkerToken::And)) {
            self.index += 1;
            let right = self.parse_primary()?;
            expr = MarkerExpr::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    pub(crate) fn parse_primary(&mut self) -> Result<MarkerExpr> {
        if matches!(self.peek(), Some(MarkerToken::LParen)) {
            self.index += 1;
            let expr = self.parse_expr()?;
            match self.next() {
                Some(MarkerToken::RParen) => return Ok(expr),
                _ => bail!("Unsupported Python environment marker: unclosed '('"),
            }
        }
        self.parse_compare()
    }

    pub(crate) fn parse_compare(&mut self) -> Result<MarkerExpr> {
        let left = self.parse_value()?;
        let op = self.parse_operator()?;
        let right = self.parse_value()?;
        Ok(MarkerExpr::Compare { left, op, right })
    }

    pub(crate) fn parse_value(&mut self) -> Result<MarkerValue> {
        match self.next() {
            Some(MarkerToken::Ident(value)) => Ok(MarkerValue::Variable(value.to_string())),
            Some(MarkerToken::String(value)) => Ok(MarkerValue::Literal(value.to_string())),
            token => bail!("Unsupported Python environment marker value: {:?}", token),
        }
    }

    pub(crate) fn parse_operator(&mut self) -> Result<MarkerOperator> {
        match self.next() {
            Some(MarkerToken::Eq) => Ok(MarkerOperator::Eq),
            Some(MarkerToken::NotEq) => Ok(MarkerOperator::NotEq),
            Some(MarkerToken::Lt) => Ok(MarkerOperator::Lt),
            Some(MarkerToken::LtEq) => Ok(MarkerOperator::LtEq),
            Some(MarkerToken::Gt) => Ok(MarkerOperator::Gt),
            Some(MarkerToken::GtEq) => Ok(MarkerOperator::GtEq),
            Some(MarkerToken::In) => Ok(MarkerOperator::In),
            Some(MarkerToken::Not) => match self.next() {
                Some(MarkerToken::In) => Ok(MarkerOperator::NotIn),
                token => bail!(
                    "Unsupported Python environment marker operator after 'not': {:?}",
                    token
                ),
            },
            token => bail!(
                "Unsupported Python environment marker operator: {:?}",
                token
            ),
        }
    }

    pub(crate) fn peek(&self) -> Option<&MarkerToken> {
        self.tokens.get(self.index)
    }

    pub(crate) fn next(&mut self) -> Option<&MarkerToken> {
        let token = self.tokens.get(self.index);
        if token.is_some() {
            self.index += 1;
        }
        token
    }
}
