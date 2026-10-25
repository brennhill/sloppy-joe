use super::*;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write;

/// Minimal zip writer for fixtures: `(name, content, deflate)`.
pub(crate) fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, content, deflate) in entries {
        let (method, body): (u16, Vec<u8>) = if *deflate {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(content).unwrap();
            (8, encoder.finish().unwrap())
        } else {
            (0, content.to_vec())
        };
        let offset = out.len() as u32;
        out.extend(0x0403_4b50u32.to_le_bytes());
        out.extend([20, 0, 0, 0]);
        out.extend(method.to_le_bytes());
        out.extend([0u8; 8]); // time, date, crc
        out.extend((body.len() as u32).to_le_bytes());
        out.extend((content.len() as u32).to_le_bytes());
        out.extend((name.len() as u16).to_le_bytes());
        out.extend([0, 0]);
        out.extend(name.as_bytes());
        out.extend(&body);

        central.extend(0x0201_4b50u32.to_le_bytes());
        central.extend([20, 0, 20, 0, 0, 0]);
        central.extend(method.to_le_bytes());
        central.extend([0u8; 8]);
        central.extend((body.len() as u32).to_le_bytes());
        central.extend((content.len() as u32).to_le_bytes());
        central.extend((name.len() as u16).to_le_bytes());
        central.extend([0u8; 12]); // extra, comment, disk, internal and external attrs
        central.extend(offset.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let directory_offset = out.len() as u32;
    out.extend(&central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(directory_offset.to_le_bytes());
    out.extend([0, 0]);
    out
}

#[test]
fn executable_pth_at_the_wheel_root_is_a_hook() {
    let wheel = zip(&[
        ("pkg/__init__.py", b"", false),
        (
            "pkg-1.0-setup.pth",
            b"import subprocess; subprocess.Popen(['x'])\n",
            true,
        ),
    ]);
    let facts = inspect_wheel(&wheel).unwrap();
    assert_eq!(facts.startup_hooks.len(), 1);
    let hook = &facts.startup_hooks[0];
    assert_eq!(hook.path, "pkg-1.0-setup.pth");
    assert_eq!(hook.kind, HookKind::PthImport);
    assert!(hook.code[0].starts_with("import subprocess"));
}

#[test]
fn stored_and_deflated_entries_are_both_read() {
    for deflate in [false, true] {
        let wheel = zip(&[("a.pth", b"import os\n", deflate)]);
        assert_eq!(inspect_wheel(&wheel).unwrap().startup_hooks.len(), 1);
    }
}

#[test]
fn path_only_pth_is_not_a_hook() {
    let wheel = zip(&[("vendor.pth", b"# comment\n/opt/lib\nimportant_dir\n", false)]);
    assert!(inspect_wheel(&wheel).unwrap().startup_hooks.is_empty());
}

#[test]
fn import_followed_by_tab_counts_and_importlib_prefix_does_not() {
    let wheel = zip(&[
        ("tab.pth", b"import\tos\n", false),
        ("nope.pth", b"importlib_stuff\n", false),
    ]);
    let facts = inspect_wheel(&wheel).unwrap();
    assert_eq!(facts.startup_hooks.len(), 1);
    assert_eq!(facts.startup_hooks[0].path, "tab.pth");
}

#[test]
fn pth_inside_a_package_directory_is_ignored() {
    let wheel = zip(&[("pkg/data/x.pth", b"import os\n", false)]);
    assert!(inspect_wheel(&wheel).unwrap().startup_hooks.is_empty());
}

#[test]
fn data_purelib_and_platlib_files_land_in_site_packages() {
    let wheel = zip(&[
        ("pkg-1.0.data/purelib/evil.pth", b"import os\n", false),
        (
            "pkg-1.0.data/platlib/sitecustomize.py",
            b"print(1)\n",
            false,
        ),
        ("pkg-1.0.data/scripts/evil.pth", b"import os\n", false),
    ]);
    let facts = inspect_wheel(&wheel).unwrap();
    let paths: Vec<_> = facts
        .startup_hooks
        .iter()
        .map(|h| h.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "pkg-1.0.data/purelib/evil.pth",
            "pkg-1.0.data/platlib/sitecustomize.py"
        ]
    );
}

#[test]
fn sitecustomize_and_usercustomize_are_hooks_without_reading_them() {
    let wheel = zip(&[
        ("sitecustomize.py", b"anything", false),
        ("usercustomize.pyc", b"\x00", false),
        ("pkg/sitecustomize.py", b"fine", false),
    ]);
    let facts = inspect_wheel(&wheel).unwrap();
    assert_eq!(facts.startup_hooks.len(), 2);
    assert!(
        facts
            .startup_hooks
            .iter()
            .all(|h| h.kind == HookKind::CustomizeModule)
    );
}

#[test]
fn uppercase_pth_extension_is_still_a_hook() {
    let wheel = zip(&[("X.PTH", b"import os\n", false)]);
    assert_eq!(inspect_wheel(&wheel).unwrap().startup_hooks.len(), 1);
}

#[test]
fn oversize_pth_is_reported_unreadable_not_skipped() {
    let big = vec![b'a'; (MAX_HOOK_BYTES + 1) as usize];
    let wheel = zip(&[("big.pth", &big, false)]);
    let facts = inspect_wheel(&wheel).unwrap();
    assert_eq!(facts.startup_hooks.len(), 1);
    assert!(facts.startup_hooks[0].unreadable.is_some());
}

#[test]
fn long_lines_are_truncated_and_line_count_capped() {
    let content = format!(
        "import {}\nimport b\nimport c\nimport d\nimport e\n",
        "x".repeat(500)
    );
    let wheel = zip(&[("l.pth", content.as_bytes(), false)]);
    let hook = &inspect_wheel(&wheel).unwrap().startup_hooks[0];
    assert_eq!(hook.code.len(), MAX_SHOWN_LINES);
    assert_eq!(hook.code[0].chars().count(), MAX_SHOWN_LINE_CHARS);
}

#[test]
fn garbage_and_truncated_archives_are_errors() {
    assert!(inspect_wheel(b"not a zip").is_err());
    let wheel = zip(&[("a.pth", b"import os\n", false)]);
    assert!(inspect_wheel(&wheel[..wheel.len() - 10]).is_err());
}

#[test]
fn central_directory_pointing_past_the_data_is_an_error() {
    let mut wheel = zip(&[("a.pth", b"import os\n", false)]);
    // Corrupt the central entry's local header offset (last 4 bytes before the name).
    let at = wheel
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
        .unwrap()
        + 42;
    wheel[at..at + 4].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
    let facts = inspect_wheel(&wheel).unwrap();
    // The entry is a hook whose content could not be read: reported, never skipped.
    assert_eq!(facts.startup_hooks.len(), 1);
    assert!(facts.startup_hooks[0].unreadable.is_some());
}

#[test]
fn zip64_markers_are_refused() {
    let mut wheel = zip(&[("a.pth", b"import os\n", false)]);
    let eocd = wheel.len() - 22;
    wheel[eocd + 10..eocd + 12].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let error = inspect_wheel(&wheel).unwrap_err().to_string();
    assert!(error.contains("zip64"));
}

#[test]
fn unknown_compression_method_on_a_pth_is_reported_unreadable() {
    let mut wheel = zip(&[("a.pth", b"import os\n", false)]);
    let at = wheel
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
        .unwrap()
        + 10;
    wheel[at..at + 2].copy_from_slice(&99u16.to_le_bytes());
    let facts = inspect_wheel(&wheel).unwrap();
    assert!(
        facts.startup_hooks[0]
            .unreadable
            .as_deref()
            .unwrap()
            .contains("compression")
    );
}

#[test]
fn clean_wheel_has_no_hooks() {
    let wheel = zip(&[
        ("pkg/__init__.py", b"x = 1", true),
        ("pkg-1.0.dist-info/METADATA", b"Name: pkg", true),
    ]);
    assert!(inspect_wheel(&wheel).unwrap().startup_hooks.is_empty());
}
