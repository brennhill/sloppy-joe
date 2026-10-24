use super::*;

#[test]
fn all_lists_every_kind_once() {
    // Exhaustive match: adding a variant fails to compile here until ALL is updated.
    for kind in ProjectInputKind::ALL {
        match kind {
            ProjectInputKind::Npm
            | ProjectInputKind::PyProjectPoetry
            | ProjectInputKind::PyProjectUv
            | ProjectInputKind::PyRequirements
            | ProjectInputKind::PyRequirementsTrusted
            | ProjectInputKind::PyProjectLegacy
            | ProjectInputKind::PyPipfile
            | ProjectInputKind::PySetupPy
            | ProjectInputKind::PySetupCfg
            | ProjectInputKind::Cargo
            | ProjectInputKind::Go
            | ProjectInputKind::Ruby
            | ProjectInputKind::Php
            | ProjectInputKind::Gradle
            | ProjectInputKind::Maven
            | ProjectInputKind::Dotnet => {}
        }
    }
    for (index, kind) in ProjectInputKind::ALL.iter().enumerate() {
        assert!(
            !ProjectInputKind::ALL[..index].contains(kind),
            "{kind:?} listed twice in ProjectInputKind::ALL"
        );
    }
}

#[test]
fn every_kind_describes_itself_completely() {
    for kind in ProjectInputKind::ALL {
        let d = kind.descriptor();
        assert!(
            !d.manifest_label.is_empty(),
            "{kind:?} has no manifest label"
        );
        assert_eq!(
            d.manager.is_none(),
            kind == ProjectInputKind::Npm,
            "{kind:?}: only JS binds its package manager per project"
        );
        assert_eq!(
            d.lockfile == LockfilePolicy::Required,
            d.missing_lockfile_help.is_some(),
            "{kind:?}: missing-lockfile help must exist exactly when a lockfile is required"
        );
    }
}

#[test]
fn python_kinds_are_exactly_the_pypi_ones() {
    for kind in ProjectInputKind::ALL {
        assert_eq!(kind.is_python(), kind.ecosystem() == Ecosystem::PyPI);
    }
}

#[test]
fn manifest_file_names_identify_one_kind() {
    for kind in ProjectInputKind::ALL {
        for name in kind.descriptor().manifest_file_names {
            let owners: Vec<_> = ProjectInputKind::ALL
                .iter()
                .filter(|other| other.descriptor().manifest_file_names.contains(name))
                .collect();
            assert_eq!(owners, vec![&kind], "{name} must identify exactly one kind");
        }
    }
}

#[test]
fn named_lockfiles_belong_to_required_lockfile_kinds() {
    for kind in ProjectInputKind::ALL {
        let d = kind.descriptor();
        if d.lockfile_name.is_some() {
            assert_eq!(d.lockfile, LockfilePolicy::Required, "{kind:?}");
        }
        let explicit_type = ["npm", "pypi", "cargo", "go", "ruby", "php", "jvm", "dotnet"];
        assert!(explicit_type.contains(&d.project_type), "{kind:?}");
    }
}
