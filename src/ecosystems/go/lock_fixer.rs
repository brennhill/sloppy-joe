//! `fix-lockfile` for Go (docs/specs/fix-lockfile.md): `go mod download all` records the missing
//! go.sum checksums. Since Go 1.17 a bare `go mod download` no longer writes module content hashes,
//! so `all` is required. The local toolchain only (`GOTOOLCHAIN=local`), the public proxy only, no
//! version-control tools, and the checksum database stays on.

use super::*;
use crate::ecosystems::fixer::{
    EnvValue, FixCtx, FixPlan, LockedPackage, Problem, Recipe, Refusal, Snapshot, literal_env,
};
use crate::remedy::{self, Remedy};

pub(super) fn lockfile_fixer(
    _ctx: &FixCtx<'_>,
    spec: &ProjectInputSpec,
    problems: &[Problem],
) -> Result<FixPlan> {
    let problems = fixer::attach_issue_remedies(problems, &remedy::GO_SUM);
    fixer::plan(&problems, |remedy| recipe(spec, remedy))
}

fn recipe(
    spec: &ProjectInputSpec,
    remedy: &'static Remedy,
) -> Result<std::result::Result<Option<Recipe>, Refusal>> {
    if remedy.id != remedy::GO_SUM.id {
        return Ok(Ok(None));
    }
    let go_mod = crate::untrusted::read_line_file(&spec.manifest_path)?;
    if let Err(refusal) = preconditions(&go_mod) {
        return Ok(Err(refusal));
    }
    let go_sum = common::named_lockfile(spec).expect("Go names go.sum");
    let mut recipe = Recipe::new(remedy.command, spec.project_dir().to_path_buf()).tool(
        "go",
        (1, 21, 0),
        "Go 1.21",
        &["mod", "download", "all"],
    );
    recipe.outputs = vec![go_sum.clone()];
    recipe.snapshot = go_sum_snapshot;
    recipe.pins_must_match = false;
    if let Some(tool) = &mut recipe.tool {
        tool.version_args = &["version"];
    }
    recipe.env = go_env();
    Ok(Ok(Some(
        recipe.inputs_if_present([spec.manifest_path.clone(), go_sum]),
    )))
}

fn go_env() -> Vec<(&'static str, EnvValue)> {
    let mut env = literal_env(&[
        ("GOTOOLCHAIN", "local"),
        ("GOFLAGS", "-modcacherw"),
        ("GOPROXY", "https://proxy.golang.org"),
        ("GOSUMDB", "sum.golang.org"),
        ("GONOSUMDB", ""),
        ("GOPRIVATE", ""),
        ("GONOPROXY", ""),
        ("GOINSECURE", ""),
        ("GOVCS", "*:off"),
        ("GOENV", "off"),
        ("GOWORK", "off"),
        ("CGO_ENABLED", "0"),
    ]);
    env.extend([
        ("GOPATH", EnvValue::ScratchDir("go")),
        ("GOMODCACHE", EnvValue::ScratchDir("go/pkg/mod")),
        ("GOCACHE", EnvValue::ScratchDir("go-build")),
    ]);
    env
}

/// A `toolchain` directive makes Go download and run another toolchain; a local `replace` points
/// at a module the scratch copy does not hold.
fn preconditions(go_mod: &str) -> std::result::Result<(), Refusal> {
    for row in crate::untrusted::rows(go_mod) {
        if row.trim_start().starts_with("toolchain") {
            return Err(
                "go.mod has a toolchain directive, which makes Go download and run another toolchain"
                    .to_string(),
            );
        }
    }
    let local = parsers::go_mod::parse_local_replace_targets(go_mod);
    if !local.is_empty() {
        return Err(format!(
            "go.mod replaces {} with a local directory, which the scratch copy does not hold",
            local.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(())
}

/// go.sum as packages: every `(module, version)` line with its hash; `/go.mod` hashes keep their
/// suffix in the version. Every entry counts as reachable.
fn go_sum_snapshot(spec: &ProjectInputSpec) -> Result<Snapshot> {
    let go_mod = crate::untrusted::read_line_file(&spec.manifest_path)?;
    let direct = parsers::go_mod::parse_requirements(&go_mod);
    let go_sum = common::named_lockfile(spec).expect("Go names go.sum");
    if !parsers::path_detected(&go_sum)? {
        return Ok(Snapshot {
            direct,
            ..Snapshot::default()
        });
    }
    let content = crate::untrusted::read_line_file(&go_sum)?;
    let packages = parsers::go_mod::go_sum_hashes(&content)?
        .into_iter()
        .map(|((name, version), hash)| LockedPackage {
            name,
            version,
            integrity: Some(hash),
            source: None,
        })
        .collect();
    Ok(Snapshot {
        exists: true,
        packages,
        reachable: None,
        direct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_toolchain_directive_or_local_replace_is_refused() {
        assert!(preconditions("module m\n\ngo 1.22\ntoolchain go1.23.1\n").is_err());
        assert!(preconditions("module m\n\ngo 1.22\nreplace a.b/c => ../c\n").is_err());
        assert!(preconditions("module m\n\ngo 1.22\nrequire a.b/c v1.0.0\n").is_ok());
    }

    #[test]
    fn the_go_environment_keeps_the_checksum_database_and_local_toolchain() {
        let env = go_env();
        let get = |name: &str| {
            env.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(get("GOTOOLCHAIN"), Some(EnvValue::Literal("local".into())));
        assert_eq!(
            get("GOSUMDB"),
            Some(EnvValue::Literal("sum.golang.org".into()))
        );
        assert_eq!(get("GOVCS"), Some(EnvValue::Literal("*:off".into())));
        assert!(get("GOFLAGS").is_some_and(|v| v == EnvValue::Literal("-modcacherw".into())));
    }
}
