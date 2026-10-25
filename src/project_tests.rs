use super::*;

#[test]
fn all_lists_every_kind_once() {
    // A kind missing from ALL has no descriptor row either (see
    // descriptor_rows_cover_every_kind_in_order), so it cannot be used: descriptor() panics.
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
            d.missing_lockfile_remedy.is_some(),
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

#[test]
fn descriptor_rows_cover_every_kind_in_order() {
    let rows: Vec<_> = DESCRIPTORS.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(rows, ProjectInputKind::ALL.to_vec());
}

#[test]
fn each_project_type_has_exactly_one_missing_manifest_message() {
    let mut types: Vec<&str> = ProjectInputKind::ALL
        .iter()
        .map(|kind| kind.descriptor().project_type)
        .collect();
    types.sort();
    types.dedup();
    for project_type in types {
        let rows = ProjectInputKind::ALL
            .iter()
            .filter(|kind| {
                let d = kind.descriptor();
                d.project_type == project_type && d.missing_manifest_message.is_some()
            })
            .count();
        assert_eq!(rows, 1, "project type {project_type}");
    }
}
