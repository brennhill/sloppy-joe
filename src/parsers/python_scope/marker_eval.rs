//! Marker evaluation with three outcomes. `Some(true)` / `Some(false)` are decided; `None` means
//! the evaluator cannot tell: an environment value is unknown, the profile covers every
//! environment, or pip, uv and Poetry would not agree on the comparison. Callers treat `None` as
//! "possibly true", so an undecidable marker never removes a dependency from the scan.
use super::*;

/// Variables whose values are PEP 440 versions.
const VERSION_VARIABLES: [&str; 3] = [
    "python_version",
    "python_full_version",
    "implementation_version",
];

#[cfg(test)]
pub(crate) fn evaluate_marker(marker: &str, profile: &PythonProfile) -> Result<bool> {
    Ok(possibly(parse_marker(marker)?.evaluate(profile, None)))
}

/// Evaluate a project-level marker against the profile's extra selection. When every extra is
/// in scope, the marker matches if it may hold for the base install or for any extra it names.
pub(crate) fn evaluate_marker_for_profile_extras(
    marker: &str,
    profile: &PythonProfile,
) -> Result<bool> {
    if !profile.all_extras {
        return evaluate_marker_for_extras(marker, profile, &profile.selected_extras);
    }
    let expr = parse_marker(marker)?;
    let mut candidates = BTreeSet::from([String::new()]);
    expr.extra_literals(&mut candidates);
    Ok(candidates
        .iter()
        .any(|extra| possibly(expr.evaluate(profile, Some(extra)))))
}

pub(crate) fn evaluate_marker_for_extras(
    marker: &str,
    profile: &PythonProfile,
    active_extras: &BTreeSet<String>,
) -> Result<bool> {
    let expr = parse_marker(marker)?;
    if active_extras.is_empty() {
        return Ok(possibly(expr.evaluate(profile, Some(""))));
    }
    Ok(active_extras
        .iter()
        .any(|extra| possibly(expr.evaluate(profile, Some(extra)))))
}

/// Undecided counts as true: the dependency stays in the scan.
fn possibly(result: Option<bool>) -> bool {
    result != Some(false)
}

impl MarkerExpr {
    pub(crate) fn evaluate(
        &self,
        profile: &PythonProfile,
        active_extra: Option<&str>,
    ) -> Option<bool> {
        match self {
            Self::Compare { left, op, right } => compare(left, *op, right, profile, active_extra),
            Self::And(items) => combine(items, false, profile, active_extra),
            Self::Or(items) => combine(items, true, profile, active_extra),
        }
    }

    /// Literals compared with `extra`, normalized: the extras this marker can select.
    pub(crate) fn extra_literals(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::Compare { left, right, .. } => {
                if let (MarkerValue::Variable(name), MarkerValue::Literal(value))
                | (MarkerValue::Literal(value), MarkerValue::Variable(name)) = (left, right)
                    && name == "extra"
                {
                    out.insert(normalize_scope_name(value));
                }
            }
            Self::And(items) | Self::Or(items) => {
                items.iter().for_each(|item| item.extra_literals(out));
            }
        }
    }
}

/// Kleene logic: `short_circuit` is the value that decides the whole chain (`true` for `or`,
/// `false` for `and`); otherwise an undecided operand leaves the chain undecided.
fn combine(
    items: &[MarkerExpr],
    short_circuit: bool,
    profile: &PythonProfile,
    active_extra: Option<&str>,
) -> Option<bool> {
    let mut undecided = false;
    for item in items {
        match item.evaluate(profile, active_extra) {
            Some(value) if value == short_circuit => return Some(short_circuit),
            Some(_) => {}
            None => undecided = true,
        }
    }
    (!undecided).then_some(!short_circuit)
}

fn variable_name(value: &MarkerValue) -> Option<&str> {
    match value {
        MarkerValue::Variable(name) => Some(name),
        MarkerValue::Literal(_) => None,
    }
}

fn compare(
    left: &MarkerValue,
    op: MarkerOperator,
    right: &MarkerValue,
    profile: &PythonProfile,
    active_extra: Option<&str>,
) -> Option<bool> {
    let names = [variable_name(left), variable_name(right)];
    let lhs = resolve_marker_value(left, profile, active_extra)?;
    let rhs = resolve_marker_value(right, profile, active_extra)?;
    if names.contains(&Some("extra")) {
        // PEP 685: extra names compare normalized (`Foo_Bar` selects `foo-bar`).
        return text_result(&normalize_scope_name(&lhs), op, &normalize_scope_name(&rhs));
    }
    if names
        .iter()
        .flatten()
        .any(|name| VERSION_VARIABLES.contains(name))
    {
        return version_variable_result(&lhs, op, &rhs);
    }
    // `packaging` compares as versions whenever both sides parse; uv compares these as strings.
    // Where the two answers differ, neither is trusted.
    match (text_result(&lhs, op, &rhs), version_result(&lhs, op, &rhs)) {
        (Some(text), Some(version)) if text != version => None,
        (Some(text), _) => Some(text),
        (None, version) => version,
    }
}

/// A version variable compares by PEP 440, prereleases included (as `packaging` does). A
/// specifier that is not valid PEP 440 (`< '3.*'`) has no agreed meaning, so it is undecided.
fn version_variable_result(lhs: &str, op: MarkerOperator, rhs: &str) -> Option<bool> {
    if !matches!(op, MarkerOperator::In | MarkerOperator::NotIn) {
        return version_result(lhs, op, rhs);
    }
    // `packaging` tests substrings; uv tests membership in a whitespace-separated list.
    let substring = rhs.contains(lhs);
    let member = rhs.split_whitespace().any(|item| item == lhs);
    if substring != member {
        return None;
    }
    Some(if op == MarkerOperator::In {
        member
    } else {
        !member
    })
}

fn version_result(lhs: &str, op: MarkerOperator, rhs: &str) -> Option<bool> {
    if matches!(op, MarkerOperator::In | MarkerOperator::NotIn) {
        return None;
    }
    let specifier: pep440_rs::VersionSpecifier =
        format!("{}{}", op.as_str(), rhs.trim()).parse().ok()?;
    let version: pep440_rs::Version = lhs.trim().parse().ok()?;
    let pep440 = crate::parsers::python_version::specifier_contains(&specifier, &version);
    // PEP 440 keeps `3.13.0rc1` out of `< 3.13` (and post-releases out of `>`); a plain ordering,
    // as uv's marker algebra uses, lets it in. Where the two differ, the marker is undecided.
    let bound = specifier.version();
    let ordered = match op {
        MarkerOperator::Lt => version < *bound,
        MarkerOperator::LtEq => version <= *bound,
        MarkerOperator::Gt => version > *bound,
        MarkerOperator::GtEq => version >= *bound,
        _ => pep440,
    };
    (pep440 == ordered).then_some(pep440)
}

fn text_result(lhs: &str, op: MarkerOperator, rhs: &str) -> Option<bool> {
    Some(match op {
        MarkerOperator::Eq => lhs == rhs,
        MarkerOperator::NotEq => lhs != rhs,
        MarkerOperator::Lt => lhs < rhs,
        MarkerOperator::LtEq => lhs <= rhs,
        MarkerOperator::Gt => lhs > rhs,
        MarkerOperator::GtEq => lhs >= rhs,
        MarkerOperator::In => rhs.contains(lhs),
        MarkerOperator::NotIn => !rhs.contains(lhs),
        // No string meaning: only defined between versions.
        MarkerOperator::Compatible | MarkerOperator::ArbitraryEq => return None,
    })
}

pub(crate) fn resolve_marker_value(
    value: &MarkerValue,
    profile: &PythonProfile,
    active_extra: Option<&str>,
) -> Option<String> {
    match value {
        MarkerValue::Literal(value) => Some(value.clone()),
        MarkerValue::Variable(name) => resolve_marker_variable(name, profile, active_extra),
    }
}

/// The value pip would see for `name` in the profile's environment, or `None` when it is not
/// known (or the profile stands for every environment).
pub(crate) fn resolve_marker_variable(
    name: &str,
    profile: &PythonProfile,
    active_extra: Option<&str>,
) -> Option<String> {
    if name == "extra" {
        return Some(active_extra.unwrap_or("").to_string());
    }
    if profile.any_environment {
        return None;
    }
    let platform = profile.target_platform.as_str();
    match name {
        "sys_platform" => Some(profile.target_platform.clone()),
        "os_name" => known(
            platform,
            &[("win32", "nt"), ("darwin", "posix"), ("linux", "posix")],
        ),
        "platform_system" => known(
            platform,
            &[
                ("win32", "Windows"),
                ("darwin", "Darwin"),
                ("linux", "Linux"),
            ],
        ),
        "platform_machine" => python_platform_machine(platform, &profile.target_arch),
        "platform_python_implementation" => Some("CPython".to_string()),
        "implementation_name" => Some("cpython".to_string()),
        "python_version" => profile.python_version.clone(),
        "python_full_version" | "implementation_version" => profile.python_full_version.clone(),
        "platform_release" => host_platform_metadata(profile, "-r", "PLATFORM_RELEASE"),
        "platform_version" => host_platform_metadata(profile, "-v", "PLATFORM_VERSION"),
        _ => None,
    }
}

fn known(platform: &str, table: &[(&str, &str)]) -> Option<String> {
    table
        .iter()
        .find(|(key, _)| *key == platform)
        .map(|(_, value)| value.to_string())
}

/// `platform.machine()` names the same CPU differently per OS: Apple silicon is `arm64` on
/// macOS but `aarch64` on Linux and `ARM64` on Windows; x86-64 is `AMD64` on Windows. The
/// target arch may be given either way (`--python-arch arm64` or Rust's `aarch64`). Pairs this
/// table does not know are undecided.
pub(crate) fn python_platform_machine(platform: &str, arch: &str) -> Option<String> {
    let family = match arch.trim().to_ascii_lowercase().as_str() {
        "aarch64" | "arm64" => "arm64",
        "x86_64" | "amd64" | "x64" => "x86_64",
        other => {
            // Other architectures report the same name everywhere Python runs on Linux.
            return (platform == "linux" && !matches!(other, "x86" | "i386" | "i686" | ""))
                .then(|| other.to_string());
        }
    };
    let machine = match (platform, family) {
        ("darwin", "arm64") => "arm64",
        ("darwin", _) => "x86_64",
        ("linux", "arm64") => "aarch64",
        ("linux", _) => "x86_64",
        ("win32", "arm64") => "ARM64",
        ("win32", _) => "AMD64",
        _ => return None,
    };
    Some(machine.to_string())
}

fn host_platform_metadata(
    profile: &PythonProfile,
    uname_flag: &str,
    env_name: &str,
) -> Option<String> {
    resolve_host_platform_metadata(profile, uname_flag, env_name)
}
