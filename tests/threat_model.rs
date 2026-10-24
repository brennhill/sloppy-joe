//! Every repository path named in a backtick in `docs/THREAT-MODEL.md` must exist, so the threat
//! model cannot keep citing code that was moved or deleted.

use std::path::Path;

#[test]
fn every_path_in_the_threat_model_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("docs/THREAT-MODEL.md")).unwrap();
    let mut checked = 0;
    for span in text.split('`').skip(1).step_by(2) {
        let looks_like_path = span.contains('/')
            && !span.contains(' ')
            && !span.starts_with("--")
            && [".rs", ".md", ".txt"].iter().any(|ext| span.ends_with(ext));
        if looks_like_path {
            assert!(
                root.join(span).exists(),
                "THREAT-MODEL.md names missing path {span}"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 15,
        "expected the threat model to link its controls, found {checked}"
    );
}
