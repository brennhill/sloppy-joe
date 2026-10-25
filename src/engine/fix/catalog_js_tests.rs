//! The JavaScript rows of the fixability catalog, end to end through the real plugins with a fake
//! package manager (docs/specs/fix-lockfile.md).

use super::report::Outcome;
use super::runner::{ToolCommand, ToolOutput};
use super::tests::*;
use std::collections::HashMap;

const INTEGRITY: &str = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQEgmQkFbyPgDYDTiNU1AmoMo9fEZknKCdQ4IGGqqSdqrMhqA==";
const PACKAGE_JSON: &str =
    r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#;

fn npm_lock_v3() -> String {
    format!(
        r#"{{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{{"":{{"name":"app","version":"1.0.0","dependencies":{{"left-pad":"1.3.0"}}}},"node_modules/left-pad":{{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"{INTEGRITY}"}}}}}}"#
    )
}

fn npm_lock_v1() -> String {
    format!(
        r#"{{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{{"left-pad":{{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"{INTEGRITY}"}}}}}}"#
    )
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn env_of(command: &ToolCommand) -> HashMap<String, String> {
    command.env.iter().cloned().collect()
}

fn first(report: &super::report::FixReport) -> &super::report::ProjectFix {
    &report.projects[0]
}

#[test]
fn a_missing_npm_lockfile_is_generated_with_scripts_off() {
    let dir = project(&[("package.json", PACKAGE_JSON)]);
    let runner = FakeRunner::default().with(
        "npm",
        Some("10.8.2"),
        writes(&[("package-lock.json", leak(npm_lock_v3()))]),
    );
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    let command = &runner.runs()[0];
    assert!(command.args.contains(&"--package-lock-only".to_string()));
    assert!(command.args.contains(&"--ignore-scripts".to_string()));
    let env = env_of(command);
    assert_eq!(env["npm_config_ignore_scripts"], "true");
    assert!(env["npm_config_userconfig"].starts_with(run.scratch_parent.to_str().unwrap()));
    assert_eq!(
        std::fs::read_to_string(dir.join("package-lock.json")).unwrap(),
        npm_lock_v3()
    );
}

#[test]
fn a_legacy_npm_lockfile_is_upgraded_when_every_version_is_kept() {
    let dir = project(&[
        ("package.json", PACKAGE_JSON),
        ("package-lock.json", leak(npm_lock_v1())),
    ]);
    let runner = FakeRunner::default().with(
        "npm",
        Some("10.8.2"),
        writes(&[("package-lock.json", leak(npm_lock_v3()))]),
    );
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.problems[0].name, "npm-lockfile-upgrade");
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    assert!(
        runner.runs()[0]
            .args
            .windows(2)
            .any(|w| w == ["--lockfile-version", "3"])
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("package-lock.json.sloppy-joe.bak")).unwrap(),
        npm_lock_v1()
    );
}

#[test]
fn an_npm_upgrade_that_could_not_fetch_metadata_fails() {
    let dir = project(&[
        ("package.json", PACKAGE_JSON),
        ("package-lock.json", leak(npm_lock_v1())),
    ]);
    let lock = leak(npm_lock_v3());
    let runner = FakeRunner::default().with(
        "npm",
        Some("10.8.2"),
        Box::new(move |command: &ToolCommand| {
            std::fs::write(command.cwd.join("package-lock.json"), lock).unwrap();
            ToolOutput {
                status: Some(0),
                stderr: "npm warn old lockfile Could not fetch metadata for left-pad@1.3.0".into(),
                ..Default::default()
            }
        }),
    );
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Failed, "{project:#?}");
    assert_eq!(
        std::fs::read_to_string(dir.join("package-lock.json")).unwrap(),
        npm_lock_v1()
    );
}

#[test]
fn an_npm_too_old_for_lockfile_version_3_is_refused() {
    let dir = project(&[
        ("package.json", PACKAGE_JSON),
        ("package-lock.json", leak(npm_lock_v1())),
    ]);
    let runner = FakeRunner::default().with("npm", Some("8.1.1"), writes(&[]));
    let run = fix(&dir, false, &runner, &FakeRescan::default());
    let reason = first(&run.report).reason.clone().unwrap();
    assert!(
        reason.contains("too old") && reason.contains("npm 8.1.2"),
        "{reason}"
    );
}

const PNPM_6: &str = "lockfileVersion: '6.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\ndependencies:\n  left-pad:\n    specifier: 1.3.0\n    version: 1.3.0\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQEgmQkFbyPgDYDTiNU1AmoMo9fEZknKCdQ4IGGqqSdqrMhqA==}\n    dev: false\n";
const PNPM_9: &str = "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQEgmQkFbyPgDYDTiNU1AmoMo9fEZknKCdQ4IGGqqSdqrMhqA==}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n";
const PNPM_PACKAGE_JSON: &str = r#"{"name":"app","version":"1.0.0","packageManager":"pnpm@9.15.0","dependencies":{"left-pad":"1.3.0"}}"#;

#[test]
fn an_old_pnpm_lockfile_is_upgraded_to_9_0_keeping_versions() {
    let dir = project(&[
        ("package.json", PNPM_PACKAGE_JSON),
        ("pnpm-lock.yaml", PNPM_6),
    ]);
    let runner = FakeRunner::default().with(
        "pnpm",
        Some("9.15.0"),
        writes(&[("pnpm-lock.yaml", PNPM_9)]),
    );
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.problems[0].name, "pnpm-lockfile");
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    let command = &runner.runs()[0];
    for flag in ["--lockfile-only", "--ignore-scripts", "--ignore-pnpmfile"] {
        assert!(
            command.args.contains(&flag.to_string()),
            "{:?}",
            command.args
        );
    }
    assert_eq!(
        env_of(command)["npm_config_manage_package_manager_versions"],
        "false"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("pnpm-lock.yaml")).unwrap(),
        PNPM_9
    );
}

#[test]
fn a_pnpm_upgrade_that_changes_an_integrity_is_refused() {
    let dir = project(&[
        ("package.json", PNPM_PACKAGE_JSON),
        ("pnpm-lock.yaml", PNPM_6),
    ]);
    let other = leak(PNPM_9.replace("sha512-XI5MPzVNApjAyhQzphX8", "sha512-AAAAPzVNApjAyhQzphX8"));
    let runner =
        FakeRunner::default().with("pnpm", Some("9.15.0"), writes(&[("pnpm-lock.yaml", other)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Refused, "{project:#?}");
    assert!(
        project
            .reason
            .as_deref()
            .unwrap()
            .contains("left-pad@1.3.0 changed")
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("pnpm-lock.yaml")).unwrap(),
        PNPM_6
    );
}

#[test]
fn a_pnpmfile_is_never_run() {
    let dir = project(&[
        ("package.json", PNPM_PACKAGE_JSON),
        ("pnpm-lock.yaml", PNPM_6),
        (".pnpmfile.cjs", "module.exports = { hooks: {} }"),
    ]);
    let runner = FakeRunner::default().with(
        "pnpm",
        Some("9.15.0"),
        writes(&[("pnpm-lock.yaml", PNPM_9)]),
    );
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert!(!project.result.is_success(), "{project:#?}");
    assert!(
        runner.runs().is_empty(),
        "the tool never runs next to a pnpmfile"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("pnpm-lock.yaml")).unwrap(),
        PNPM_6
    );
}

#[test]
fn dependency_rewrites_are_a_human_decision() {
    let manifest = r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"},"overrides":{"left-pad":"1.3.0"}}"#;
    let dir = project(&[
        ("package.json", manifest),
        ("package-lock.json", leak(npm_lock_v3())),
    ]);
    let runner = FakeRunner::default().with("npm", Some("10.8.2"), writes(&[]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Refused, "{project:#?}");
    assert_eq!(project.problems[0].class, "human");
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[test]
fn a_missing_lockfile_next_to_overrides_is_not_regenerated() {
    let manifest = r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"},"overrides":{"left-pad":"1.3.0"}}"#;
    let dir = project(&[("package.json", manifest)]);
    let runner = FakeRunner::default().with(
        "npm",
        Some("10.8.2"),
        writes(&[("package-lock.json", leak(npm_lock_v3()))]),
    );
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert!(!project.result.is_success(), "{project:#?}");
    assert!(
        runner.runs().is_empty(),
        "policy is checked before the tool runs"
    );
    assert!(!dir.join("package-lock.json").exists());
}

#[test]
fn a_manifest_pin_the_lockfile_locks_differently_is_a_decision() {
    let manifest = r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.2.0"}}"#;
    let dir = project(&[
        ("package.json", manifest),
        ("package-lock.json", leak(npm_lock_v3())),
    ]);
    let runner = FakeRunner::default().with("npm", Some("10.8.2"), writes(&[]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Refused, "{project:#?}");
    let reason = project.reason.as_deref().unwrap();
    assert!(
        reason.contains("pins left-pad@1.2.0") && reason.contains("decision"),
        "{reason}"
    );
    assert!(
        runner.runs().is_empty(),
        "the tool never runs to settle a pin"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("package-lock.json")).unwrap(),
        npm_lock_v3()
    );
}

const WORKSPACE_ROOT: &str =
    r#"{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#;
const MEMBER: &str = r#"{"name":"member","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#;

fn workspace_lock() -> String {
    format!(
        r#"{{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{{"":{{"name":"root","version":"1.0.0","workspaces":["packages/*"]}},"node_modules/member":{{"resolved":"packages/member","link":true}},"node_modules/left-pad":{{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"{INTEGRITY}"}},"packages/member":{{"name":"member","version":"1.0.0","dependencies":{{"left-pad":"1.3.0"}}}}}}}}"#
    )
}

#[test]
fn a_shadow_lockfile_under_a_workspace_member_is_moved_aside() {
    let dir = project(&[
        ("package.json", WORKSPACE_ROOT),
        ("package-lock.json", leak(workspace_lock())),
        ("packages/member/package.json", MEMBER),
        ("packages/member/package-lock.json", leak(npm_lock_v3())),
    ]);
    let runner = FakeRunner::default();
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let shadow = run
        .report
        .projects
        .iter()
        .find(|project| project.manifest.ends_with("packages/member/package.json"))
        .unwrap();
    assert_eq!(shadow.problems[0].name, "js-shadow-lockfile", "{shadow:#?}");
    assert_eq!(shadow.result, Outcome::Written, "{shadow:#?}");
    assert!(!dir.join("packages/member/package-lock.json").exists());
    assert!(
        dir.join("packages/member/package-lock.json.sloppy-joe.bak")
            .is_file()
    );
    assert!(
        runner.calls.lock().unwrap().is_empty(),
        "removing a file runs no tool"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("package-lock.json")).unwrap(),
        workspace_lock(),
        "the workspace lockfile is untouched"
    );
}

const BERRY_PACKAGE_JSON: &str =
    r#"{"name":"app","packageManager":"yarn@4.9.2","dependencies":{"left-pad":"1.3.0"}}"#;
const BERRY_LOCK: &str = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n  dependencies:\n    left-pad: \"npm:1.3.0\"\n  languageName: unknown\n  linkType: soft\n\n\"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/abc\n  languageName: node\n  linkType: hard\n";
const BERRY_ORPHAN: &str = "\n\"ghost@npm:^9.0.0\":\n  version: 9.0.0\n  resolution: \"ghost@npm:9.0.0\"\n  checksum: 10c0/def\n  languageName: node\n  linkType: hard\n";

#[test]
fn yarn_berry_orphan_entries_are_pruned() {
    let dir = project(&[
        ("package.json", BERRY_PACKAGE_JSON),
        ("yarn.lock", leak(format!("{BERRY_LOCK}{BERRY_ORPHAN}"))),
    ]);
    let runner =
        FakeRunner::default().with("yarn", Some("4.9.2"), writes(&[("yarn.lock", BERRY_LOCK)]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(
        project.problems[0].name,
        crate::lockfiles::yarn::LOCKFILE_ORPHAN_ENTRIES
    );
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    assert_eq!(
        project.diff.as_ref().unwrap().removed,
        vec!["ghost@9.0.0".to_string()]
    );
    let command = &runner.runs()[0];
    assert_eq!(command.args, ["install", "--mode=update-lockfile"]);
    let env = env_of(command);
    assert_eq!(env["YARN_ENABLE_SCRIPTS"], "0");
    assert_eq!(env["YARN_IGNORE_PATH"], "1");
}

const CLASSIC_LOCK: &str = "# yarn lockfile v1\n\n\nleft-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e\"\n  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQEgmQkFbyPgDYDTiNU1AmoMo9fEZknKCdQ4IGGqqSdqrMhqA==\n";

#[test]
fn yarn_classic_problems_are_guided() {
    let manifest = r#"{"name":"app","packageManager":"yarn@1.22.22","dependencies":{"left-pad":"1.3.0","right-pad":"1.0.1"}}"#;
    let dir = project(&[("package.json", manifest), ("yarn.lock", CLASSIC_LOCK)]);
    let runner = FakeRunner::default().with("yarn", Some("1.22.22"), writes(&[]));
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.result, Outcome::Guided, "{project:#?}");
    assert_eq!(
        project.problems[0].command.as_deref(),
        Some("yarn install --ignore-scripts")
    );
    assert!(runner.calls.lock().unwrap().is_empty());
}

const BUN_PACKAGE_JSON: &str =
    r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#;

fn bun_lock() -> String {
    format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {{\n    \"\": {{\n      \"name\": \"app\",\n      \"dependencies\": {{\n        \"left-pad\": \"1.3.0\",\n      }},\n    }},\n  }},\n  \"packages\": {{\n    \"left-pad\": [\"left-pad@1.3.0\", \"\", {{}}, \"{INTEGRITY}\"],\n  }}\n}}\n"
    )
}

#[test]
fn a_binary_bun_lockfile_is_converted_when_the_printed_lockfile_matches() {
    let dir = project(&[
        ("package.json", BUN_PACKAGE_JSON),
        ("bun.lockb", "\u{1}binary"),
    ]);
    let lock = leak(bun_lock());
    let runner = FakeRunner::default().with(
        "bun",
        Some("1.2.21"),
        Box::new(move |command: &ToolCommand| {
            if command.args == ["bun.lockb"] {
                return ToolOutput {
                    status: Some(0),
                    stdout: CLASSIC_LOCK.replace("registry.yarnpkg.com", "registry.npmjs.org"),
                    ..Default::default()
                };
            }
            std::fs::write(command.cwd.join("bun.lock"), lock).unwrap();
            ToolOutput {
                status: Some(0),
                ..Default::default()
            }
        }),
    );
    let run = fix(&dir, true, &runner, &FakeRescan::default());
    let project = first(&run.report);
    assert_eq!(project.problems[0].name, "bun-binary-lockfile");
    assert_eq!(project.result, Outcome::Written, "{project:#?}");
    let install = runner
        .runs()
        .into_iter()
        .find(|c| c.args[0] == "install")
        .unwrap();
    assert!(install.args.contains(&"--frozen-lockfile".to_string()));
    assert!(install.args.contains(&"--save-text-lockfile".to_string()));
    assert_eq!(
        std::fs::read_to_string(dir.join("bun.lock")).unwrap(),
        bun_lock()
    );
    assert!(!dir.join("bun.lockb").exists());
    assert!(dir.join("bun.lockb.sloppy-joe.bak").is_file());
}
