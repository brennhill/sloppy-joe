//! The problems `check` would report for each project, gathered with the same discovery, binding,
//! preflight and lockfile stages the scan runs (no network). Used for the plan and, on the
//! candidate tree, to prove the fix left nothing behind.

use crate::ecosystems::fixer::{Problem, planned_issue};
use crate::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The projects of one tree, bound to their package managers.
pub(super) struct Discovered {
    pub(super) root: PathBuf,
    pub(super) specs: Vec<ProjectInputSpec>,
    /// Projects that could not be bound, with the binding error as their problem.
    binding_errors: HashMap<PathBuf, Problem>,
}

pub(super) fn discover(
    root: &Path,
    project_type: Option<&str>,
    config: &config::SloppyJoeConfig,
) -> Result<Discovered> {
    let mut specs = unbound_project_inputs_with_config(root, project_type, config)?;
    let binding_errors = ecosystems::bind(root, &mut specs)
        .into_iter()
        .map(|(path, error)| (path, Problem::from_error(&error)))
        .collect();
    Ok(Discovered {
        root: root.to_path_buf(),
        specs,
        binding_errors,
    })
}

fn scan_options() -> ScanOptions<'static> {
    ScanOptions {
        scan_mode: ScanMode::Full,
        ..Default::default()
    }
}

impl Discovered {
    /// Projects that bound to a package manager.
    pub(super) fn usable_specs(&self) -> Vec<ProjectInputSpec> {
        self.specs
            .iter()
            .filter(|spec| !self.binding_errors.contains_key(&spec.manifest_path))
            .cloned()
            .collect()
    }

    /// The spec whose manifest is `manifest`, if discovered.
    pub(super) fn spec_for(&self, manifest: &Path) -> Option<&ProjectInputSpec> {
        self.specs
            .iter()
            .find(|spec| spec.manifest_path == manifest)
    }

    /// Everything `check` would report as a lockfile problem for `spec`.
    pub(super) fn problems(
        &self,
        spec: &ProjectInputSpec,
        config: &config::SloppyJoeConfig,
    ) -> Vec<Problem> {
        if let Some(problem) = self.binding_errors.get(&spec.manifest_path) {
            return vec![problem.clone()];
        }
        let opts = scan_options();
        let usable = self.usable_specs();
        let warnings = match preflight_selected_project_inputs(
            &self.root,
            &usable,
            std::slice::from_ref(spec),
            config,
            &opts,
        ) {
            Ok(warnings) => warnings,
            Err(error) => return vec![Problem::from_error(&error)],
        };
        let mut problems: Vec<Problem> = warnings
            .iter()
            .filter(|issue| planned_issue(issue))
            .map(Problem::from_issue)
            .collect();
        let projects = match parse_project_inputs_with_options(
            &self.root,
            std::slice::from_ref(spec),
            config,
            &opts,
        ) {
            Ok(projects) => projects,
            Err(error) => {
                problems.push(Problem::from_error(&error));
                return problems;
            }
        };
        for project in &projects {
            match ecosystems::lockfile_data(config, &opts, project, &project.deps) {
                Ok(data) => problems.extend(
                    data.resolution
                        .issues
                        .iter()
                        .filter(|issue| planned_issue(issue))
                        .map(Problem::from_issue),
                ),
                Err(error) => problems.push(Problem::from_error(&error)),
            }
        }
        problems
    }

    /// The preflight context for the fixer's policy check of `spec`.
    pub(super) fn policy_check(
        &self,
        spec: &ProjectInputSpec,
        config: &config::SloppyJoeConfig,
    ) -> Result<()> {
        let opts = scan_options();
        let scan = ecosystems::ScanCtx {
            scan_root: &self.root,
            config,
            opts: &opts,
        };
        let usable = self.usable_specs();
        let ctx = ecosystems::PreflightCtx::new(scan, &usable, std::slice::from_ref(spec))?;
        ecosystems::fix_policy(&ctx, spec)
    }
}
