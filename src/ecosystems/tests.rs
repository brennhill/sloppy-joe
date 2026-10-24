use super::*;

fn spec(kind: ProjectInputKind, manifest: &str) -> ProjectInputSpec {
    ProjectInputSpec {
        kind,
        manifest_path: PathBuf::from("/proj").join(manifest),
        lockfile_path_override: None,
        js_binding: None,
    }
}

#[test]
fn every_kind_is_owned_by_exactly_one_plugin() {
    for kind in ProjectInputKind::ALL {
        let owners = all()
            .iter()
            .filter(|plugin| plugin.kinds().contains(&kind))
            .count();
        assert_eq!(owners, 1, "{kind:?} must be owned by exactly one plugin");
    }
}

#[test]
fn plugins_own_kinds_of_their_own_ecosystem_only() {
    for plugin in all() {
        let kinds = plugin.kinds();
        assert!(!kinds.is_empty());
        let ecosystem = kinds[0].ecosystem();
        for kind in kinds {
            assert_eq!(kind.ecosystem(), ecosystem, "{kind:?}");
        }
    }
}

#[test]
fn default_lockfile_paths_agree_with_the_descriptor() {
    for kind in ProjectInputKind::ALL {
        let manifest = kind.descriptor().manifest_file_names.first().copied();
        let spec = spec(kind, manifest.unwrap_or("manifest"));
        let path = for_kind(kind).default_lockfile_path(&spec);
        if let Some(name) = kind.descriptor().lockfile_name {
            assert_eq!(path, Some(PathBuf::from("/proj").join(name)), "{kind:?}");
        }
        if kind.descriptor().lockfile == LockfilePolicy::Unsupported {
            assert!(
                path.is_none() || kind == ProjectInputKind::PyRequirementsTrusted,
                "{kind:?} declares no lockfile support"
            );
        }
    }
}

#[test]
fn plugins_detect_exactly_the_manifest_names_their_descriptors_list() {
    for kind in ProjectInputKind::ALL {
        for name in kind.descriptor().manifest_file_names {
            // pyproject.toml is classified by content, so it is not in the name table.
            let detected = detect(Path::new("/proj").join(name).as_path())
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(detected, Some(kind), "{name}");
        }
    }
}

#[test]
fn unrelated_files_are_not_projects() {
    for name in ["README.md", "main.rs", "Makefile", "lock.json"] {
        assert_eq!(
            detect(&Path::new("/proj").join(name)).unwrap(),
            None,
            "{name}"
        );
    }
}

#[test]
fn unsupported_bundler_files_block_instead_of_being_skipped() {
    for name in ["gems.rb", "gems.locked"] {
        assert!(detect(&Path::new("/proj").join(name)).is_err(), "{name}");
    }
}
