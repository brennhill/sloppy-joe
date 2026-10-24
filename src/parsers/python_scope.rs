mod marker;
pub(crate) use marker::*;
mod host;
use crate::Dependency;
use anyhow::{Result, bail};
pub(crate) use host::*;
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
    /// Declared only in a tool-managed environment table (PDM dev-dependencies, Hatch
    /// environments) that neither uv.lock nor poetry.lock records. Such packages are still
    /// installable, so they are scanned, but without lockfile reconciliation.
    pub unlocked_tool_env: bool,
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
    /// Every declared dependency group is in scope. This is the default: uv and Poetry install
    /// groups without extra flags, so nothing installable may be hidden unless the operator
    /// narrows the selection with `--python-groups`.
    pub all_groups: bool,
    /// Every declared extra is in scope (default). `--python-extras` narrows the selection.
    pub all_extras: bool,
    /// Normalized group names selected with `--python-groups` (used when `all_groups` is false).
    pub selected_groups: BTreeSet<String>,
    /// Normalized extra names selected with `--python-extras` (used when `all_extras` is false).
    pub selected_extras: BTreeSet<String>,
    /// The target environment (platform, arch or Python version) was chosen explicitly.
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
            unlocked_tool_env: false,
        }
    }

    /// Scoped only by environment (markers or Poetry python/platform shorthands), which are
    /// evaluated against the target environment rather than a group/extra selection.
    pub(crate) fn has_environment_scope(&self) -> bool {
        self.marker.is_some()
            || self.python_constraint.is_some()
            || self.platform_constraint.is_some()
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

    pub(crate) fn is_in_scope(&self, profile: &PythonProfile) -> Result<bool> {
        if !self.groups.is_empty()
            && !self
                .groups
                .iter()
                .any(|group| profile.includes_group(group))
        {
            return Ok(false);
        }
        if !self.extras.is_empty()
            && !self
                .extras
                .iter()
                .any(|extra| profile.includes_extra(extra))
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
            if !super::python_version::version_matches_uv_specifier(version, Some(constraint))? {
                return Ok(false);
            }
        }
        if let Some(constraint) = &self.platform_constraint
            && !poetry_platform_constraint_matches(&profile.target_platform, constraint)?
        {
            return Ok(false);
        }
        if let Some(marker) = &self.marker {
            return evaluate_marker_for_profile_extras(marker, profile);
        }
        Ok(true)
    }
}

/// Group and extra names compare after PEP 503/685 normalization.
pub(crate) fn normalize_scope_name(name: &str) -> String {
    crate::parsers::requirements::normalize_distribution_name(name)
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
            all_groups: true,
            all_extras: true,
            selected_groups: BTreeSet::new(),
            selected_extras: BTreeSet::new(),
            explicit_selection: false,
        }
    }

    pub(crate) fn includes_group(&self, group: &str) -> bool {
        self.all_groups || self.selected_groups.contains(&normalize_scope_name(group))
    }

    pub(crate) fn includes_extra(&self, extra: &str) -> bool {
        self.all_extras || self.selected_extras.contains(&normalize_scope_name(extra))
    }

    /// Restrict the scanned groups to `groups` (the `--python-groups` selection).
    pub(crate) fn narrow_groups<'a>(&mut self, groups: impl IntoIterator<Item = &'a String>) {
        self.all_groups = false;
        self.selected_groups
            .extend(groups.into_iter().map(|group| normalize_scope_name(group)));
    }

    /// Restrict the scanned extras to `extras` (the `--python-extras` selection).
    pub(crate) fn narrow_extras<'a>(&mut self, extras: impl IntoIterator<Item = &'a String>) {
        self.all_extras = false;
        self.selected_extras
            .extend(extras.into_iter().map(|extra| normalize_scope_name(extra)));
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
            all_groups: true,
            all_extras: true,
            selected_groups: BTreeSet::new(),
            selected_extras: BTreeSet::new(),
            explicit_selection: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_group(mut self, group: &str) -> Self {
        self.narrow_groups([&group.to_string()]);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_no_groups(mut self) -> Self {
        self.narrow_groups(std::iter::empty());
        self
    }
}

#[cfg(test)]
mod tests;
