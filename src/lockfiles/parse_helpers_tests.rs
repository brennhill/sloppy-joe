use super::*;

/// Test entry points that infer the lockfile reader when a test names no project kind.
impl LockfileData {
    pub fn parse(project_dir: &Path, direct_deps: &[Dependency]) -> Result<Self> {
        Self::parse_for_kind(project_dir, None, direct_deps)
    }

    #[allow(dead_code)]
    pub fn parse_for_kind(
        project_dir: &Path,
        project_kind: Option<LockfileKind>,
        direct_deps: &[Dependency],
    ) -> Result<Self> {
        Self::parse_for_kind_with_lockfile(project_dir, project_kind, direct_deps, None)
    }

    pub fn parse_for_kind_with_lockfile(
        project_dir: &Path,
        project_kind: Option<LockfileKind>,
        direct_deps: &[Dependency],
        lockfile_override: Option<&Path>,
    ) -> Result<Self> {
        Self::parse_for_kind_with_lockfile_and_profile(
            project_dir,
            project_kind.unwrap_or_else(|| {
                LockfileKind::for_ecosystem(direct_deps.first().map(|d| d.ecosystem))
            }),
            direct_deps,
            lockfile_override,
            None,
        )
    }
}

impl LockfileKind {
    /// The reader of an ecosystem's usual lockfile, taken from the descriptor of the first kind
    /// that requires one; tests that name no project kind use it.
    pub(crate) fn for_ecosystem(ecosystem: Option<Ecosystem>) -> LockfileKind {
        ecosystem
            .and_then(|ecosystem| {
                crate::ProjectInputKind::ALL.into_iter().find(|kind| {
                    let descriptor = kind.descriptor();
                    descriptor.ecosystem == ecosystem
                        && descriptor.lockfile == crate::LockfilePolicy::Required
                })
            })
            .map_or(LockfileKind::ABSENT, |kind| kind.lockfile_kind())
    }
}
