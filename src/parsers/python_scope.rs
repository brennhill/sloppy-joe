use crate::Dependency;
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub(crate) struct PythonScopedDependency {
    pub dependency: Dependency,
    pub marker: Option<String>,
    pub python_constraint: Option<String>,
    pub platform_constraint: Option<String>,
    pub groups: BTreeSet<String>,
    pub extras: BTreeSet<String>,
    pub requested_extras: BTreeSet<String>,
    pub runtime_default: bool,
}

pub(crate) type PythonRootExtras = BTreeMap<String, BTreeSet<String>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PythonPackageRequest {
    pub normalized_name: String,
    pub version: Option<String>,
    pub requested_extras: BTreeSet<String>,
}

impl PythonPackageRequest {
    pub(crate) fn new(normalized_name: String) -> Self {
        Self {
            normalized_name,
            version: None,
            requested_extras: BTreeSet::new(),
        }
    }

    pub(crate) fn with_requested_extras(
        normalized_name: String,
        version: Option<String>,
        requested_extras: BTreeSet<String>,
    ) -> Self {
        Self {
            normalized_name,
            version,
            requested_extras,
        }
    }

    pub(crate) fn normalized_extras_key(&self) -> String {
        self.requested_extras
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PythonProfile {
    pub target_platform: String,
    pub target_arch: String,
    pub python_version: Option<String>,
    pub python_full_version: Option<String>,
    pub selected_groups: BTreeSet<String>,
    pub selected_extras: BTreeSet<String>,
    pub explicit_selection: bool,
}

impl PythonScopedDependency {
    pub(crate) fn runtime(dependency: Dependency, marker: Option<String>) -> Self {
        Self {
            dependency,
            marker,
            python_constraint: None,
            platform_constraint: None,
            groups: BTreeSet::new(),
            extras: BTreeSet::new(),
            requested_extras: BTreeSet::new(),
            runtime_default: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn runtime_with_marker(name: &str, version: &str, marker: &str) -> Self {
        Self::runtime(
            crate::test_helpers::dep_with(name, Some(version), crate::Ecosystem::PyPI),
            Some(marker.to_string()),
        )
    }

    pub(crate) fn with_group(mut self, group: &str) -> Self {
        self.groups.insert(group.to_string());
        self.runtime_default = false;
        self
    }

    pub(crate) fn with_extra(mut self, extra: &str) -> Self {
        self.extras.insert(extra.to_string());
        self.runtime_default = false;
        self
    }

    pub(crate) fn with_requested_extra(mut self, extra: &str) -> Self {
        self.requested_extras.insert(extra.to_string());
        self
    }

    #[cfg(test)]
    pub(crate) fn group_only(name: &str, version: &str, group: &str) -> Self {
        Self::runtime(
            crate::test_helpers::dep_with(name, Some(version), crate::Ecosystem::PyPI),
            None,
        )
        .with_group(group)
    }

    pub(crate) fn is_scoped(&self) -> bool {
        self.marker.is_some()
            || self.python_constraint.is_some()
            || self.platform_constraint.is_some()
            || !self.groups.is_empty()
            || !self.extras.is_empty()
    }

    pub(crate) fn is_in_scope(&self, profile: &PythonProfile) -> Result<bool> {
        if !self.groups.is_empty()
            && !self
                .groups
                .iter()
                .any(|group| profile.selected_groups.contains(group))
        {
            return Ok(false);
        }
        if !self.extras.is_empty()
            && !self
                .extras
                .iter()
                .any(|extra| profile.selected_extras.contains(extra))
        {
            return Ok(false);
        }
        if !self.runtime_default && self.groups.is_empty() && self.extras.is_empty() {
            return Ok(false);
        }
        if let Some(constraint) = &self.python_constraint {
            let version = profile.python_version.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Poetry python shorthand requires an explicit Python version for trusted evaluation"
                )
            })?;
            if !crate::lockfiles::uv::version_matches_uv_specifier(version, Some(constraint))? {
                return Ok(false);
            }
        }
        if let Some(constraint) = &self.platform_constraint
            && !poetry_platform_constraint_matches(&profile.target_platform, constraint)?
        {
            return Ok(false);
        }
        if let Some(marker) = &self.marker {
            return evaluate_marker_for_extras(marker, profile, &profile.selected_extras);
        }
        Ok(true)
    }
}

impl PythonProfile {
    pub(crate) fn runtime_for_current_host() -> Self {
        let detected = detected_host_python_version();
        let python_version = std::env::var("SLOPPY_JOE_PYTHON_VERSION")
            .ok()
            .or_else(|| std::env::var("PYTHON_VERSION").ok())
            .or_else(|| {
                detected
                    .as_ref()
                    .map(|version| version.python_version.clone())
            });
        Self {
            target_platform: current_sys_platform().to_string(),
            target_arch: std::env::consts::ARCH.to_string(),
            python_version: python_version.clone(),
            python_full_version: std::env::var("SLOPPY_JOE_PYTHON_FULL_VERSION")
                .ok()
                .or_else(|| std::env::var("PYTHON_FULL_VERSION").ok())
                .or_else(|| {
                    detected
                        .as_ref()
                        .map(|version| version.python_full_version.clone())
                })
                .or_else(|| python_version.as_deref().map(normalize_python_full_version)),
            selected_groups: BTreeSet::new(),
            selected_extras: BTreeSet::new(),
            explicit_selection: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_target(platform: &str, python_version: &str) -> Self {
        Self::for_target_with_arch(platform, python_version, std::env::consts::ARCH)
    }

    #[cfg(test)]
    pub(crate) fn for_target_with_arch(
        platform: &str,
        python_version: &str,
        target_arch: &str,
    ) -> Self {
        Self {
            target_platform: platform.to_string(),
            target_arch: target_arch.to_string(),
            python_version: Some(python_version.to_string()),
            python_full_version: Some(normalize_python_full_version(python_version)),
            selected_groups: BTreeSet::new(),
            selected_extras: BTreeSet::new(),
            explicit_selection: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_group(mut self, group: &str) -> Self {
        self.selected_groups.insert(group.to_string());
        self.explicit_selection = true;
        self
    }
}

#[derive(Clone, Debug)]
struct DetectedPythonVersion {
    python_version: String,
    python_full_version: String,
}

#[derive(Clone, Debug, Default)]
struct DetectedHostPlatformMetadata {
    platform_release: Option<String>,
    platform_version: Option<String>,
}

static DETECTED_HOST_PYTHON_VERSION: OnceLock<Option<DetectedPythonVersion>> = OnceLock::new();
static DETECTED_HOST_PLATFORM_METADATA: OnceLock<DetectedHostPlatformMetadata> = OnceLock::new();

fn detected_host_python_version() -> Option<DetectedPythonVersion> {
    DETECTED_HOST_PYTHON_VERSION
        .get_or_init(detect_host_python_version_uncached)
        .clone()
}

fn detected_host_platform_metadata() -> DetectedHostPlatformMetadata {
    DETECTED_HOST_PLATFORM_METADATA
        .get_or_init(detect_host_platform_metadata_uncached)
        .clone()
}

fn detect_host_python_version_uncached() -> Option<DetectedPythonVersion> {
    ["python3", "python"]
        .into_iter()
        .find_map(detect_python_version_from_command)
}

fn detect_host_platform_metadata_uncached() -> DetectedHostPlatformMetadata {
    DetectedHostPlatformMetadata {
        platform_release: detect_uname_value("-r"),
        platform_version: detect_uname_value("-v"),
    }
}

fn detect_uname_value(flag: &str) -> Option<String> {
    let output = std::process::Command::new("uname")
        .arg(flag)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn detect_python_version_from_command(command: &str) -> Option<DetectedPythonVersion> {
    let output = std::process::Command::new(command)
        .args([
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}'); print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_detected_python_version_output(&output.stdout)
}

fn parse_detected_python_version_output(output: &[u8]) -> Option<DetectedPythonVersion> {
    let output = std::str::from_utf8(output).ok()?;
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let python_version = lines.next()?.to_string();
    let python_full_version = lines
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| normalize_python_full_version(&python_version));
    Some(DetectedPythonVersion {
        python_version,
        python_full_version,
    })
}

pub(crate) fn normalize_python_full_version(version: &str) -> String {
    if version.matches('.').count() >= 2 {
        version.to_string()
    } else {
        format!("{version}.0")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MarkerValue {
    Variable(String),
    Literal(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MarkerOperator {
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
enum MarkerExpr {
    Compare {
        left: MarkerValue,
        op: MarkerOperator,
        right: MarkerValue,
    },
    And(Box<MarkerExpr>, Box<MarkerExpr>),
    Or(Box<MarkerExpr>, Box<MarkerExpr>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MarkerToken {
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

fn evaluate_marker_with_extra(
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
    fn evaluate(&self, profile: &PythonProfile, active_extra: Option<&str>) -> Result<bool> {
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

fn resolve_marker_value(
    value: &MarkerValue,
    profile: &PythonProfile,
    active_extra: Option<&str>,
) -> Result<String> {
    match value {
        MarkerValue::Literal(value) => Ok(value.clone()),
        MarkerValue::Variable(name) => resolve_marker_variable(name, profile, active_extra),
    }
}

fn resolve_marker_variable(
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

fn current_sys_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

fn resolve_host_platform_metadata(
    marker_name: &str,
    profile: &PythonProfile,
    uname_flag: &str,
    env_name: &str,
) -> Result<String> {
    if let Ok(value) = std::env::var(format!("SLOPPY_JOE_{env_name}"))
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    if let Ok(value) = std::env::var(env_name)
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    if profile.target_platform != current_sys_platform()
        || profile.target_arch != std::env::consts::ARCH
    {
        bail!(
            "Python environment marker '{}' requires explicit target metadata; set SLOPPY_JOE_{} for trusted evaluation",
            marker_name,
            env_name
        );
    }
    let detected = detected_host_platform_metadata();
    let value = match uname_flag {
        "-r" => detected.platform_release,
        "-v" => detected.platform_version,
        _ => None,
    };
    value.ok_or_else(|| {
        anyhow::anyhow!(
            "Python environment marker '{}' requires host platform metadata for trusted evaluation",
            marker_name
        )
    })
}

fn poetry_platform_constraint_matches(target_platform: &str, constraint: &str) -> Result<bool> {
    let target = normalize_poetry_platform_token(target_platform)?;
    let allowed = parse_poetry_platform_constraint(constraint)?;
    Ok(allowed.contains(&target))
}

fn parse_poetry_platform_constraint(constraint: &str) -> Result<BTreeSet<String>> {
    let mut allowed = BTreeSet::new();
    for token in constraint
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        allowed.insert(normalize_poetry_platform_token(token)?);
    }
    if allowed.is_empty() {
        bail!("empty Poetry platform shorthand cannot be trusted exactly");
    }
    Ok(allowed)
}

fn normalize_poetry_platform_token(token: &str) -> Result<String> {
    let lowered = token.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        bail!("empty Poetry platform shorthand cannot be trusted exactly");
    }
    if lowered
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
    {
        bail!(
            "Unsupported Poetry platform shorthand '{}'",
            crate::report::sanitize_for_terminal(token)
        );
    }
    Ok(match lowered.as_str() {
        "macos" | "darwin" => "darwin".to_string(),
        "windows" | "win32" => "win32".to_string(),
        "linux" => "linux".to_string(),
        other => other.to_string(),
    })
}

fn compare_marker_values(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    if looks_like_python_version(left) && looks_like_python_version(right) {
        return Some(compare_python_versions(left, right));
    }
    Some(left.cmp(right))
}

fn looks_like_python_version(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ch == '.' || ch == '*')
}

fn compare_python_versions(left: &str, right: &str) -> std::cmp::Ordering {
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

fn parse_version_part(part: &str) -> u64 {
    part.parse::<u64>().unwrap_or(0)
}

fn marker_membership(left: &str, right: &str) -> bool {
    right.contains(left)
}

fn tokenize_marker(marker: &str) -> Result<Vec<MarkerToken>> {
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

struct MarkerParser<'a> {
    tokens: &'a [MarkerToken],
    index: usize,
}

impl MarkerParser<'_> {
    fn parse_expr(&mut self) -> Result<MarkerExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<MarkerExpr> {
        let mut expr = self.parse_and()?;
        while matches!(self.peek(), Some(MarkerToken::Or)) {
            self.index += 1;
            let right = self.parse_and()?;
            expr = MarkerExpr::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<MarkerExpr> {
        let mut expr = self.parse_primary()?;
        while matches!(self.peek(), Some(MarkerToken::And)) {
            self.index += 1;
            let right = self.parse_primary()?;
            expr = MarkerExpr::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<MarkerExpr> {
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

    fn parse_compare(&mut self) -> Result<MarkerExpr> {
        let left = self.parse_value()?;
        let op = self.parse_operator()?;
        let right = self.parse_value()?;
        Ok(MarkerExpr::Compare { left, op, right })
    }

    fn parse_value(&mut self) -> Result<MarkerValue> {
        match self.next() {
            Some(MarkerToken::Ident(value)) => Ok(MarkerValue::Variable(value.to_string())),
            Some(MarkerToken::String(value)) => Ok(MarkerValue::Literal(value.to_string())),
            token => bail!("Unsupported Python environment marker value: {:?}", token),
        }
    }

    fn parse_operator(&mut self) -> Result<MarkerOperator> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_profile_excludes_group_only_dependency() {
        let dep = PythonScopedDependency::group_only("pytest", "==8.1.1", "dev");
        let profile = PythonProfile::runtime_for_current_host();
        assert!(!dep.is_in_scope(&profile).unwrap());
    }

    #[test]
    fn selected_group_includes_group_only_dependency() {
        let dep = PythonScopedDependency::group_only("pytest", "==8.1.1", "dev");
        let profile = PythonProfile::runtime_for_current_host().with_group("dev");
        assert!(dep.is_in_scope(&profile).unwrap());
    }

    #[test]
    fn non_matching_marker_excludes_dependency() {
        let dep = PythonScopedDependency::runtime_with_marker(
            "pywin32",
            "==306",
            r#"sys_platform == "win32""#,
        );
        let profile = PythonProfile::for_target("linux", "3.12");
        assert!(!dep.is_in_scope(&profile).unwrap());
    }

    #[test]
    fn matching_marker_includes_dependency() {
        let dep = PythonScopedDependency::runtime_with_marker(
            "pywin32",
            "==306",
            r#"sys_platform == "win32""#,
        );
        let profile = PythonProfile::for_target("win32", "3.12");
        assert!(dep.is_in_scope(&profile).unwrap());
    }

    #[test]
    fn python_version_marker_uses_numeric_comparison() {
        let dep = PythonScopedDependency::runtime_with_marker(
            "requests",
            "==2.31.0",
            r#"python_version < "3.13""#,
        );
        let profile = PythonProfile::for_target("linux", "3.12");
        assert!(dep.is_in_scope(&profile).unwrap());
    }

    #[test]
    fn marker_in_operator_uses_pep508_substring_semantics() {
        let linux = PythonProfile::for_target("linux", "3.12");
        assert!(evaluate_marker(r#""lin" in sys_platform"#, &linux).unwrap());
        assert!(evaluate_marker(r#"sys_platform in "linux,darwin""#, &linux).unwrap());
        assert!(!evaluate_marker(r#""win" in sys_platform"#, &linux).unwrap());
    }

    #[test]
    fn parse_detected_python_version_output_reads_short_and_full_version() {
        let detected = parse_detected_python_version_output(b"3.12\n3.12.7\n").unwrap();
        assert_eq!(detected.python_version, "3.12");
        assert_eq!(detected.python_full_version, "3.12.7");
    }

    #[test]
    fn platform_machine_marker_uses_selected_target_arch() {
        let profile = PythonProfile::for_target_with_arch("linux", "3.12", "aarch64");
        assert!(evaluate_marker(r#"platform_machine == "aarch64""#, &profile).unwrap());
        assert!(!evaluate_marker(r#"platform_machine == "x86_64""#, &profile).unwrap());
    }

    #[test]
    fn implementation_version_marker_uses_full_python_version() {
        let profile = PythonProfile::for_target("linux", "3.12");
        assert!(evaluate_marker(r#"implementation_version == "3.12.0""#, &profile).unwrap());
    }

    #[test]
    fn platform_release_marker_uses_profile_value() {
        let profile = PythonProfile::runtime_for_current_host();
        assert!(
            resolve_marker_variable("platform_release", &profile, None).is_ok(),
            "platform_release should be a supported marker variable"
        );
    }

    #[test]
    fn platform_version_marker_uses_profile_value() {
        let profile = PythonProfile::runtime_for_current_host();
        assert!(
            resolve_marker_variable("platform_version", &profile, None).is_ok(),
            "platform_version should be a supported marker variable"
        );
    }
}
