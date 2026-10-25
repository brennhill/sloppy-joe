//! PEP 508 environment markers: tokenizer and parser. Evaluation lives in `marker_eval`.
use super::*;

/// Markers with more tokens than this are refused. Real markers (including the long ones uv and
/// Poetry write) stay far below it; unbounded input would make evaluation quadratic.
pub(crate) const MAX_MARKER_TOKENS: usize = 4096;
/// Parentheses nested deeper than this are refused instead of exhausting the stack.
pub(crate) const MAX_MARKER_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MarkerValue {
    Variable(String),
    Literal(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MarkerOperator {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    Compatible,
    ArbitraryEq,
    In,
    NotIn,
}

impl MarkerOperator {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::NotEq => "!=",
            Self::Lt => "<",
            Self::LtEq => "<=",
            Self::Gt => ">",
            Self::GtEq => ">=",
            Self::Compatible => "~=",
            Self::ArbitraryEq => "===",
            Self::In => "in",
            Self::NotIn => "not in",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MarkerExpr {
    Compare {
        left: MarkerValue,
        op: MarkerOperator,
        right: MarkerValue,
    },
    /// Every operand must hold. Chains stay flat, so a long `a and b and ...` does not nest.
    And(Vec<MarkerExpr>),
    /// Any operand may hold.
    Or(Vec<MarkerExpr>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MarkerToken {
    Ident(String),
    String(String),
    Op(MarkerOperator),
    Not,
    And,
    Or,
    LParen,
    RParen,
}

/// The marker variables PEP 508 defines, plus the legacy dotted spellings `packaging` still
/// accepts. Anything else is a syntax error, as it is for pip.
pub(crate) fn canonical_marker_variable(name: &str) -> Option<&'static str> {
    Some(match name {
        "os_name" | "os.name" => "os_name",
        "sys_platform" | "sys.platform" => "sys_platform",
        "platform_machine" | "platform.machine" => "platform_machine",
        "platform_python_implementation"
        | "platform.python_implementation"
        | "python_implementation" => "platform_python_implementation",
        "platform_release" => "platform_release",
        "platform_system" => "platform_system",
        "platform_version" | "platform.version" => "platform_version",
        "python_version" => "python_version",
        "python_full_version" => "python_full_version",
        "implementation_name" => "implementation_name",
        "implementation_version" => "implementation_version",
        "extra" => "extra",
        _ => return None,
    })
}

/// Characters of a refused marker quoted in the error; the rest is elided.
const QUOTED_MARKER_CHARS: usize = 160;

pub(crate) fn unsupported_marker(marker: &str, detail: impl std::fmt::Display) -> anyhow::Error {
    let quoted: String = marker.chars().take(QUOTED_MARKER_CHARS).collect();
    let elided = if marker.chars().nth(QUOTED_MARKER_CHARS).is_some() {
        "..."
    } else {
        ""
    };
    anyhow::anyhow!(
        "Unsupported Python environment marker '{}{elided}': {detail}",
        crate::report::sanitize_for_terminal(&quoted)
    )
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'
}

/// Operator starting at `index`: the token and how many characters it spans.
fn tokenize_operator(
    marker: &str,
    chars: &[char],
    index: usize,
) -> Result<Option<(MarkerToken, usize)>> {
    let next = chars.get(index + 1).copied();
    let op = |op| MarkerToken::Op(op);
    let token = match (chars[index], next) {
        ('(', _) => (MarkerToken::LParen, 1),
        (')', _) => (MarkerToken::RParen, 1),
        ('=', Some('=')) if chars.get(index + 2) == Some(&'=') => {
            (op(MarkerOperator::ArbitraryEq), 3)
        }
        ('=', Some('=')) => (op(MarkerOperator::Eq), 2),
        ('!', Some('=')) => (op(MarkerOperator::NotEq), 2),
        ('~', Some('=')) => (op(MarkerOperator::Compatible), 2),
        ('<', Some('=')) => (op(MarkerOperator::LtEq), 2),
        ('<', _) => (op(MarkerOperator::Lt), 1),
        ('>', Some('=')) => (op(MarkerOperator::GtEq), 2),
        ('>', _) => (op(MarkerOperator::Gt), 1),
        (ch @ ('=' | '!' | '~'), _) => {
            return Err(unsupported_marker(marker, format!("unexpected '{ch}'")));
        }
        _ => return Ok(None),
    };
    Ok(Some(token))
}

/// Quoted string starting at `index`: the token and how many characters it spans.
fn tokenize_string(marker: &str, chars: &[char], index: usize) -> Result<(MarkerToken, usize)> {
    let quote = chars[index];
    let start = index + 1;
    let Some(len) = chars[start..].iter().position(|&c| c == quote) else {
        return Err(unsupported_marker(marker, "unterminated string"));
    };
    let value = chars[start..start + len].iter().collect();
    Ok((MarkerToken::String(value), len + 2))
}

fn tokenize_identifier(chars: &[char], index: usize) -> (MarkerToken, usize) {
    let len = chars[index..]
        .iter()
        .take_while(|&&c| is_ident_char(c))
        .count();
    let ident: String = chars[index..index + len].iter().collect();
    let token = match ident.as_str() {
        "and" => MarkerToken::And,
        "or" => MarkerToken::Or,
        "not" => MarkerToken::Not,
        "in" => MarkerToken::Op(MarkerOperator::In),
        _ => MarkerToken::Ident(ident),
    };
    (token, len)
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
        let (token, len) = if let Some(operator) = tokenize_operator(marker, &chars, index)? {
            operator
        } else if ch == '\'' || ch == '"' {
            tokenize_string(marker, &chars, index)?
        } else if is_ident_char(ch) {
            tokenize_identifier(&chars, index)
        } else {
            return Err(unsupported_marker(
                marker,
                format!("unexpected character '{ch}'"),
            ));
        };
        tokens.push(token);
        if tokens.len() > MAX_MARKER_TOKENS {
            return Err(unsupported_marker(
                marker,
                format!("more than {MAX_MARKER_TOKENS} tokens"),
            ));
        }
        index += len;
    }
    Ok(tokens)
}

/// Parse a whole marker. Unknown variables, trailing tokens and excessive nesting are errors.
pub(crate) fn parse_marker(marker: &str) -> Result<MarkerExpr> {
    let tokens = tokenize_marker(marker)?;
    let mut parser = MarkerParser {
        marker,
        tokens: &tokens,
        index: 0,
        depth: 0,
    };
    let expr = parser.parse_or()?;
    if parser.index != tokens.len() {
        return Err(unsupported_marker(
            marker,
            "trailing tokens are not supported",
        ));
    }
    Ok(expr)
}

pub(crate) struct MarkerParser<'a> {
    marker: &'a str,
    tokens: &'a [MarkerToken],
    index: usize,
    depth: usize,
}

impl MarkerParser<'_> {
    fn parse_or(&mut self) -> Result<MarkerExpr> {
        let mut items = vec![self.parse_and()?];
        while matches!(self.peek(), Some(MarkerToken::Or)) {
            self.index += 1;
            items.push(self.parse_and()?);
        }
        Ok(flatten(items, MarkerExpr::Or))
    }

    fn parse_and(&mut self) -> Result<MarkerExpr> {
        let mut items = vec![self.parse_primary()?];
        while matches!(self.peek(), Some(MarkerToken::And)) {
            self.index += 1;
            items.push(self.parse_primary()?);
        }
        Ok(flatten(items, MarkerExpr::And))
    }

    fn parse_primary(&mut self) -> Result<MarkerExpr> {
        if !matches!(self.peek(), Some(MarkerToken::LParen)) {
            return self.parse_compare();
        }
        self.index += 1;
        self.depth += 1;
        if self.depth > MAX_MARKER_DEPTH {
            return Err(unsupported_marker(
                self.marker,
                format!("parentheses nested deeper than {MAX_MARKER_DEPTH}"),
            ));
        }
        let expr = self.parse_or()?;
        self.depth -= 1;
        match self.next() {
            Some(MarkerToken::RParen) => Ok(expr),
            _ => Err(unsupported_marker(self.marker, "unclosed '('")),
        }
    }

    fn parse_compare(&mut self) -> Result<MarkerExpr> {
        let left = self.parse_value()?;
        let op = self.parse_operator()?;
        let right = self.parse_value()?;
        Ok(MarkerExpr::Compare { left, op, right })
    }

    fn parse_value(&mut self) -> Result<MarkerValue> {
        let marker = self.marker;
        match self.next() {
            Some(MarkerToken::Ident(name)) => canonical_marker_variable(name)
                .map(|name| MarkerValue::Variable(name.to_string()))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported Python environment marker variable '{}'",
                        crate::report::sanitize_for_terminal(name)
                    )
                }),
            Some(MarkerToken::String(value)) => Ok(MarkerValue::Literal(value.to_string())),
            token => Err(unsupported_marker(marker, format!("unexpected {token:?}"))),
        }
    }

    fn parse_operator(&mut self) -> Result<MarkerOperator> {
        let marker = self.marker;
        match self.next() {
            Some(MarkerToken::Op(op)) => Ok(*op),
            Some(MarkerToken::Not) => match self.next() {
                Some(MarkerToken::Op(MarkerOperator::In)) => Ok(MarkerOperator::NotIn),
                token => Err(unsupported_marker(
                    marker,
                    format!("unexpected {token:?} after 'not'"),
                )),
            },
            token => Err(unsupported_marker(
                marker,
                format!("expected an operator, found {token:?}"),
            )),
        }
    }

    fn peek(&self) -> Option<&MarkerToken> {
        self.tokens.get(self.index)
    }

    fn next(&mut self) -> Option<&MarkerToken> {
        let token = self.tokens.get(self.index);
        if token.is_some() {
            self.index += 1;
        }
        token
    }
}

fn flatten(mut items: Vec<MarkerExpr>, combine: fn(Vec<MarkerExpr>) -> MarkerExpr) -> MarkerExpr {
    if items.len() == 1 {
        items.pop().expect("one item")
    } else {
        combine(items)
    }
}
