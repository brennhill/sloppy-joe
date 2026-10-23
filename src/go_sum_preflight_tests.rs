//! Preflight wiring for go.sum content checks.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const HASH: &str = "h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=";

fn project(go_mod: &str, go_sum: &str) -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-go-sum-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("go.mod"), go_mod).unwrap();
    std::fs::write(dir.join("go.sum"), go_sum).unwrap();
    dir
}

const GO_MOD: &str = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgithub.com/evil/pkg v1.0.0\n)\n";

#[test]
fn preflight_blocks_a_require_with_no_go_sum_checksum() {
    let dir = project(
        GO_MOD,
        &format!("github.com/google/uuid v1.6.0/go.mod {HASH}\n"),
    );
    let err = preflight_scan_inputs(&dir, Some("go")).expect_err("missing checksum must block");
    let msg = err.to_string();
    assert!(msg.contains("github.com/evil/pkg"), "{msg}");
    assert!(msg.contains("go.sum"), "{msg}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_a_complete_go_sum() {
    let dir = project(
        GO_MOD,
        &format!(
            "github.com/google/uuid v1.6.0/go.mod {HASH}\ngithub.com/evil/pkg v1.0.0/go.mod {HASH}\n"
        ),
    );
    preflight_scan_inputs(&dir, Some("go")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_skips_the_content_check_for_vendored_modules() {
    let dir = project(
        GO_MOD,
        &format!("github.com/google/uuid v1.6.0/go.mod {HASH}\n"),
    );
    std::fs::create_dir_all(dir.join("vendor")).unwrap();
    std::fs::write(
        dir.join("vendor/modules.txt"),
        "# github.com/google/uuid v1.6.0\n",
    )
    .unwrap();
    preflight_scan_inputs(&dir, Some("go")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
