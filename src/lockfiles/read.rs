use super::*;

/// Read and parse the lockfile from disk (once) with the project's reader.
pub(crate) fn read_lockfile(
    project_dir: &Path,
    kind: LockfileKind,
    lockfile_override: Option<&Path>,
) -> Result<ParsedLockfile> {
    (kind.0)(project_dir, lockfile_override)
}

fn read_npm_lockfile(
    project_dir: &Path,
    lockfile_override: Option<&Path>,
) -> Result<ParsedLockfile> {
    if let Some(path) = lockfile_override {
        if is_pnpm_lockfile_path(path) {
            return read_pnpm_override(project_dir, path);
        }
        if is_bun_lockfile_path(path) {
            return read_bun_override(project_dir, path);
        }
        if is_yarn_lockfile_path(path) {
            return read_yarn_override(project_dir, path);
        }
    }
    read_npm_package_lock(project_dir, lockfile_override)
}

fn read_pnpm_override(project_dir: &Path, path: &Path) -> Result<ParsedLockfile> {
    let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let value: serde_yaml::Value = parse_pnpm_lock_guarded(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse pnpm-lock.yaml: {}", err))?;
    let importer_key = pnpm_importer_key(project_dir, path)?;
    Ok(ParsedLockfile::Pnpm {
        value,
        importer_key,
        path: path.to_path_buf(),
    })
}

fn read_bun_override(project_dir: &Path, path: &Path) -> Result<ParsedLockfile> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bun.lock");
    if file_name == "bun.lockb" {
        anyhow::bail!(
            "Legacy Bun binary lockfile '{}' is not supported yet. Regenerate and commit the text bun.lock.",
            path.display()
        );
    }
    let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let value: serde_json::Value = parse_json5_guarded(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse bun.lock: {}", err))?;
    let importer_key = js_importer_key(project_dir, path)?;
    Ok(ParsedLockfile::Bun {
        value,
        importer_key,
    })
}

fn read_yarn_override(project_dir: &Path, path: &Path) -> Result<ParsedLockfile> {
    let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)?;
    Ok(ParsedLockfile::Yarn(yarn::parse_lockfile(
        &content,
        path.to_path_buf(),
        project_dir,
    )?))
}

fn read_npm_package_lock(
    project_dir: &Path,
    lockfile_override: Option<&Path>,
) -> Result<ParsedLockfile> {
    let Some(path) = lockfile_override
        .map(PathBuf::from)
        .or_else(|| first_existing(project_dir, &["npm-shrinkwrap.json", "package-lock.json"]))
    else {
        return Ok(ParsedLockfile::None);
    };
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("npm-shrinkwrap.json")
        .to_string();
    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", file_name, err))?;
    let version = npm::lockfile_version(&value)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    if version == 1 {
        Ok(ParsedLockfile::NpmLegacy { value, file_name })
    } else {
        Ok(ParsedLockfile::Npm {
            value,
            file_name,
            project_key: js_importer_key(project_dir, &path)?,
        })
    }
}

fn read_cargo_lockfile(
    project_dir: &Path,
    lockfile_override: Option<&Path>,
) -> Result<ParsedLockfile> {
    let path = lockfile_override
        .map(PathBuf::from)
        .unwrap_or_else(|| project_dir.join("Cargo.lock"));
    if !crate::parsers::path_detected(&path)? {
        return Ok(ParsedLockfile::None);
    }
    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let value = toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse Cargo.lock: {}", err))?;
    Ok(ParsedLockfile::Cargo(value))
}

fn read_npm(project_dir: &Path, lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    read_npm_lockfile(project_dir, lockfile_override)
}

fn read_cargo(project_dir: &Path, lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    read_cargo_lockfile(project_dir, lockfile_override)
}

fn read_php(project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(
        composer::read_lockfile(project_dir)?
            .map_or(ParsedLockfile::None, ParsedLockfile::Composer),
    )
}

fn read_jvm(project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(gradle::read_lockfile(project_dir)?.map_or(ParsedLockfile::None, ParsedLockfile::Gradle))
}

fn read_dotnet(project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(dotnet::read_lockfile(project_dir)?.map_or(ParsedLockfile::None, ParsedLockfile::Dotnet))
}

fn read_ruby(project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(ruby::read_lockfile(project_dir)?.map_or(ParsedLockfile::None, ParsedLockfile::Ruby))
}

fn read_pypi(project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(python::read_lockfile(project_dir)?.map_or(ParsedLockfile::None, ParsedLockfile::Python))
}

/// Go records checksums in go.sum, which preflight checks separately.
fn read_go(_project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(ParsedLockfile::None)
}

fn read_uv(project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(uv::read_lockfile(project_dir)?.map_or(ParsedLockfile::None, ParsedLockfile::Uv))
}

fn read_pipfile(project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(pipfile_lock::read_lockfile(project_dir)?
        .map_or(ParsedLockfile::None, ParsedLockfile::Pipfile))
}

/// The project has no lockfile format sloppy-joe reads.
fn read_absent(_project_dir: &Path, _lockfile_override: Option<&Path>) -> Result<ParsedLockfile> {
    Ok(ParsedLockfile::None)
}

#[allow(dead_code)]
impl LockfileKind {
    pub(crate) const NPM: LockfileKind = LockfileKind(read_npm);
    /// Poetry's lockfile for Python.
    pub(crate) const PYPI: LockfileKind = LockfileKind(read_pypi);
    pub(crate) const CARGO: LockfileKind = LockfileKind(read_cargo);
    pub(crate) const GO: LockfileKind = LockfileKind(read_go);
    pub(crate) const RUBY: LockfileKind = LockfileKind(read_ruby);
    pub(crate) const PHP: LockfileKind = LockfileKind(read_php);
    pub(crate) const JVM: LockfileKind = LockfileKind(read_jvm);
    pub(crate) const DOTNET: LockfileKind = LockfileKind(read_dotnet);
    pub(crate) const UV: LockfileKind = LockfileKind(read_uv);
    pub(crate) const PIPFILE: LockfileKind = LockfileKind(read_pipfile);
    pub(crate) const ABSENT: LockfileKind = LockfileKind(read_absent);
}

/// Resolve versions from a pre-parsed lockfile.
pub(crate) fn resolve_from_parsed(
    parsed: &ParsedLockfile,
    deps: &[Dependency],
    mode: ResolutionMode,
    python_profile: Option<&PythonLockfileProfile>,
) -> Result<ResolutionResult> {
    match parsed {
        ParsedLockfile::Npm {
            value,
            file_name,
            project_key,
        } => npm::resolve_from_value(value, deps, file_name, project_key, mode),
        ParsedLockfile::NpmLegacy { value, file_name } => {
            npm::resolve_from_value(value, deps, file_name, "", mode)
        }
        ParsedLockfile::Pnpm {
            value,
            importer_key,
            ..
        } => pnpm::resolve_from_value(value, deps, importer_key, mode),
        ParsedLockfile::Bun {
            value,
            importer_key,
        } => bun::resolve_from_value(value, deps, importer_key),
        ParsedLockfile::Yarn(parsed) => yarn::resolve_from_parsed(parsed, deps, mode),
        ParsedLockfile::Cargo(value) => cargo::resolve_from_value_with_mode(value, deps, mode),
        ParsedLockfile::Composer(value) => {
            composer::resolve_from_value_with_mode(value, deps, mode)
        }
        ParsedLockfile::Dotnet(value) => dotnet::resolve_from_value_with_mode(value, deps, mode),
        ParsedLockfile::Gradle(content) => {
            gradle::resolve_from_content_with_mode(content, deps, mode)
        }
        ParsedLockfile::Python(value) => {
            python::resolve_from_value_with_mode_and_profile(value, deps, mode, python_profile)
        }
        ParsedLockfile::Uv(value) => {
            uv::resolve_from_value_with_mode_and_profile(value, deps, mode, python_profile)
        }
        ParsedLockfile::Pipfile(value) => {
            pipfile_lock::resolve_from_value_with_mode(value, deps, mode)
        }
        ParsedLockfile::Ruby(content) => ruby::resolve_from_content_with_mode(content, deps, mode),
        ParsedLockfile::None => {
            let mut result = ResolutionResult::default();
            add_manifest_exact_fallbacks(&mut result, deps);
            Ok(result)
        }
    }
}

/// Extract all deps from a pre-parsed lockfile.
pub(crate) fn parse_all_from_parsed(parsed: &ParsedLockfile) -> Result<Vec<Dependency>> {
    match parsed {
        ParsedLockfile::Npm { value, .. } => npm::parse_all_from_value(value),
        ParsedLockfile::NpmLegacy { .. } => Ok(vec![]),
        ParsedLockfile::Pnpm { value, .. } => pnpm::parse_all_from_value(value),
        ParsedLockfile::Bun { value, .. } => bun::parse_all_from_value(value),
        ParsedLockfile::Yarn(parsed) => yarn::parse_all_from_parsed(parsed),
        ParsedLockfile::Cargo(value) => cargo::parse_all_from_value(value),
        ParsedLockfile::Composer(value) => composer::parse_all_from_value(value),
        ParsedLockfile::Dotnet(value) => dotnet::parse_all_from_value(value),
        ParsedLockfile::Gradle(content) => gradle::parse_all_from_content(content),
        ParsedLockfile::Python(value) => python::parse_all_from_value(value),
        ParsedLockfile::Uv(value) => uv::parse_all_from_value(value),
        ParsedLockfile::Pipfile(value) => pipfile_lock::parse_all_from_value(value),
        ParsedLockfile::Ruby(content) => ruby::parse_all_from_content(content),
        ParsedLockfile::None => Ok(vec![]),
    }
}

/// Dependencies to scan for a project, plus lockfile-level issues (currently
/// only Yarn's stale orphan-entry warning).
pub(crate) fn parse_all_from_parsed_for_project(
    parsed: &ParsedLockfile,
    direct_deps: &[Dependency],
    project_dir: &Path,
    python_profile: Option<&PythonLockfileProfile>,
) -> Result<(Vec<Dependency>, Vec<Issue>)> {
    if let ParsedLockfile::Yarn(parsed) = parsed {
        return yarn::parse_all_from_parsed_for_project(parsed, direct_deps, project_dir);
    }
    if let ParsedLockfile::Pnpm {
        value,
        importer_key,
        path,
    } = parsed
    {
        return pnpm::parse_for_importer_with_orphans(value, importer_key, path);
    }
    let deps = match parsed {
        ParsedLockfile::Npm {
            value, project_key, ..
        } => npm::parse_transitive_from_value(value, direct_deps, project_key),
        ParsedLockfile::NpmLegacy { .. } => Ok(vec![]),
        ParsedLockfile::Bun {
            value,
            importer_key,
        } => bun::parse_all_from_value_for_importer(value, importer_key),
        ParsedLockfile::Python(value) => {
            python::parse_all_from_value_for_roots(value, direct_deps, python_profile)
        }
        ParsedLockfile::Uv(value) => {
            uv::parse_all_from_value_for_roots(value, direct_deps, python_profile)
        }
        _ => parse_all_from_parsed(parsed),
    }?;
    Ok((deps, Vec::new()))
}

#[cfg(test)]
pub(crate) fn resolve_versions(
    project_dir: &Path,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    let Some(first) = deps.first() else {
        return Ok(ResolutionResult::default());
    };

    match first.ecosystem {
        Ecosystem::Npm => npm::resolve(project_dir, deps),
        Ecosystem::Cargo => cargo::resolve(project_dir, deps),
        Ecosystem::Php => composer::resolve(project_dir, deps),
        Ecosystem::Jvm => gradle::resolve(project_dir, deps),
        Ecosystem::Dotnet => dotnet::resolve(project_dir, deps),
        Ecosystem::Ruby => ruby::resolve(project_dir, deps),
        Ecosystem::PyPI => python::resolve(project_dir, deps),
        _ => {
            let mut result = ResolutionResult::default();
            add_manifest_exact_fallbacks(&mut result, deps);
            Ok(result)
        }
    }
}
