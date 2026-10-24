use super::*;
use crate::config_surface::KNOWN_SURFACES;

fn run(text: &str, allows: &[KeyAllow]) -> Result<usize> {
    let value: toml::Value = toml::from_str(text).unwrap();
    check(&value, Path::new(".cargo/config.toml"), allows).map(|applied| applied.len())
}

fn allow(key: &str) -> KeyAllow {
    KeyAllow {
        file: "cargo-config".into(),
        key: key.into(),
    }
}

#[test]
fn the_surface_id_is_known() {
    assert!(KNOWN_SURFACES.contains(&CARGO_CONFIG.id));
}

#[test]
fn ordinary_cargo_config_passes() {
    let text = "[term]\ncolor = \"never\"\n[env]\nRUST_BACKTRACE = \"1\"\n[build]\njobs = 4\nrustflags = [\"-C\", \"target-cpu=native\"]\n[net]\nretry = 3\n[alias]\nb = \"build\"\n[target.x86_64-unknown-linux-gnu]\nrustflags = \"-C target-cpu=native\"\n[profile.release]\nlto = true\n";
    assert_eq!(run(text, &[]).unwrap(), 0);
}

#[test]
fn program_running_and_trust_settings_block_even_when_allowed() {
    for (text, key) in [
        ("include = \"extra.toml\"\n", "include"),
        ("[http]\nproxy = \"http://p.invalid\"\n", "http.proxy"),
        ("[http]\ncainfo = \"c.pem\"\n", "http.cainfo"),
        (
            "[net]\ngit-fetch-with-cli = true\n",
            "net.git-fetch-with-cli",
        ),
        ("[build]\nrustc-wrapper = \"./w\"\n", "build.rustc-wrapper"),
        ("[build]\nrustc = \"./r\"\n", "build.rustc"),
        (
            "[registries.corp]\ncredential-provider = \"./cred\"\n",
            "registries.corp.credential-provider",
        ),
        ("[doc]\nbrowser = \"./open\"\n", "doc.browser"),
        (
            "[target.'cfg(unix)']\nlinker = \"./l\"\n",
            "target.cfg(unix).linker",
        ),
        (
            "[build]\nrustflags = [\"-Clink-arg=-fuse-ld=evil\"]\n",
            "build.rustflags",
        ),
        ("[env]\nCC = \"./cc\"\n", "env.CC"),
    ] {
        assert!(run(text, &[]).is_err(), "{text}");
        assert!(run(text, &[allow(key)]).is_err(), "allowed: {text}");
    }
}

#[test]
fn an_unlisted_setting_blocks_until_the_operator_allows_that_exact_key() {
    let text = "[target.x86_64-unknown-linux-gnu.openssl]\nrustc-link-search = [\"vendor/lib\"]\n";
    let err = run(text, &[]).unwrap_err().to_string();
    assert!(
        err.contains("target.x86_64-unknown-linux-gnu.openssl.rustc-link-search"),
        "{err}"
    );
    let key = "target.x86_64-unknown-linux-gnu.openssl.rustc-link-search";
    assert_eq!(run(text, &[allow(key)]).unwrap(), 1);
}
