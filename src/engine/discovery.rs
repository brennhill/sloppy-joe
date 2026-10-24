use crate::*;

#[cfg(test)]
pub(crate) fn detected_project_inputs(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
) -> Result<Vec<ProjectInputSpec>> {
    detected_project_inputs_with_config(
        project_dir,
        project_type,
        &config::SloppyJoeConfig::default(),
    )
}

#[cfg(test)]
pub(crate) fn detected_project_inputs_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<ProjectInputSpec>> {
    let mut specs = unbound_project_inputs_with_config(project_dir, project_type, config)?;
    ecosystems::bind_strict(project_dir, &mut specs)?;
    Ok(specs)
}

pub(crate) fn unbound_project_inputs_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<ProjectInputSpec>> {
    let mut specs = discover_project_inputs(project_dir, &config.ignore_dirs)?;
    specs.retain(|spec| project_type_includes(project_type, spec.kind));
    ecosystems::refine_specs(project_dir, config, &mut specs)?;

    if specs.is_empty()
        && let Some(message) = project_type.and_then(missing_manifest_message_for_type)
    {
        anyhow::bail!("{message}");
    }

    Ok(specs)
}

/// Whether an explicit `--type` selects manifests of `kind` (no type selects everything).
fn project_type_includes(project_type: Option<&str>, kind: ProjectInputKind) -> bool {
    project_type.is_none_or(|selected| kind.descriptor().project_type == selected)
}

pub(crate) use crate::ecosystems::tree::discover_project_inputs;
#[cfg(test)]
pub(crate) use crate::ecosystems::tree::project_input_from_path;
