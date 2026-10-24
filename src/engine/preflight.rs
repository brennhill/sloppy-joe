use crate::*;

#[cfg(test)]
pub(crate) fn preflight_scan_inputs(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
) -> Result<Vec<Issue>> {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(project_dir, project_type, &config)?;
    preflight_project_inputs(project_dir, &specs, &config)
}

#[cfg(test)]
pub(crate) fn preflight_project_inputs(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Issue>> {
    preflight_project_inputs_with_options(scan_root, specs, config, &ScanOptions::default())
}

#[cfg(test)]
pub(crate) fn preflight_project_inputs_with_options(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<Vec<Issue>> {
    preflight_selected_project_inputs(scan_root, specs, specs, config, opts)
}

pub(crate) fn preflight_selected_project_inputs(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    selected: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<Vec<Issue>> {
    let scan = ecosystems::ScanCtx {
        scan_root,
        config,
        opts,
    };
    let ctx = ecosystems::PreflightCtx::new(scan, specs, selected)?;
    let mut warnings = Vec::new();
    for spec in selected {
        warnings.extend(ecosystems::preflight(&ctx, spec)?);
    }
    Ok(warnings)
}
