use super::*;

const MINIFIED: &str = r#"{"packages":{"psr/log":[
 {"name":"psr/log","version":"3.0.1","version_normalized":"3.0.1.0",
  "source":{"type":"git","url":"https://github.com/php-fig/log.git","reference":"bbb"},
  "dist":{"type":"zip","url":"https://api.github.com/repos/php-fig/log/zipball/bbb","reference":"bbb"}},
 {"version":"3.0.0","version_normalized":"3.0.0.0",
  "source":{"type":"git","url":"https://github.com/php-fig/log.git","reference":"aaa"},
  "dist":{"type":"zip","url":"https://api.github.com/repos/php-fig/log/zipball/aaa","reference":"aaa"}}]}}"#;

fn lock(source_url: &str, dist_url: &str) -> serde_json::Value {
    serde_json::json!({"packages":[{"name":"psr/log","version":"3.0.0",
        "source":{"type":"git","url":source_url,"reference":"aaa"},
        "dist":{"type":"zip","url":dist_url,"reference":"aaa"}}]})
}

#[test]
fn minified_p2_versions_inherit_unchanged_fields() {
    let body: serde_json::Value = serde_json::from_str(MINIFIED).unwrap();
    let found = published_version(&body, "psr/log", "3.0.0").unwrap();
    assert_eq!(found.dist_reference.as_deref(), Some("aaa"));
    assert!(published_version(&body, "psr/log", "9.9.9").is_none());
    let inherited: serde_json::Value = serde_json::from_str(
        r#"{"packages":{"a/b":[{"version":"2.0","source":{"url":"u","reference":"r"}},{"version":"1.0"}]}}"#,
    )
    .unwrap();
    let older = published_version(&inherited, "a/b", "1.0").unwrap();
    assert_eq!(older.source_url.as_deref(), Some("u"));
}

#[test]
fn only_the_published_locations_agree() {
    let body: serde_json::Value = serde_json::from_str(MINIFIED).unwrap();
    let published = published_version(&body, "psr/log", "3.0.0").unwrap();
    let good = lock(
        "https://github.com/php-fig/log.git",
        "https://api.github.com/repos/php-fig/log/zipball/aaa",
    );
    assert_eq!(disagreement(&good["packages"][0], &published), None);
    let evil = lock(
        "https://github.com/attacker/log.git",
        "https://api.github.com/repos/attacker/log/zipball/aaa",
    );
    assert_eq!(
        disagreement(&evil["packages"][0], &published),
        Some("source.url")
    );
}

async fn serve(body: &'static str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer).await;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    origin
}

#[tokio::test]
async fn a_lock_pointing_at_a_foreign_repository_blocks() {
    let origin = serve(MINIFIED).await;
    TEST_PACKAGIST_URL.with(|url| *url.borrow_mut() = Some(origin));
    let dir = std::env::temp_dir().join(format!("sj-packagist-lock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let client = crate::registry::http_client();
    for (source, dist, blocks) in [
        (
            "https://github.com/php-fig/log.git",
            "https://api.github.com/repos/php-fig/log/zipball/aaa",
            false,
        ),
        (
            "https://github.com/attacker/log.git",
            "https://api.github.com/repos/attacker/log/zipball/aaa",
            true,
        ),
    ] {
        let path = dir.join("composer.lock");
        std::fs::write(&path, lock(source, dist).to_string()).unwrap();
        let issues = verify_lock_locations(&client, &path).await.unwrap();
        assert_eq!(!issues.is_empty(), blocks, "{source}");
    }
}
