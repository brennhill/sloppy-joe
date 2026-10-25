use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

async fn serve(throttled: usize) -> (String, Arc<AtomicUsize>) {
    serve_with(throttled, "0").await.0
}

/// Answers the first `throttled` requests with 429 (`Retry-After: retry_after`), then 200.
/// Also records when each request arrived.
async fn serve_with(
    throttled: usize,
    retry_after: &'static str,
) -> ((String, Arc<AtomicUsize>), Arc<Mutex<Vec<Instant>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let arrivals = Arc::new(Mutex::new(Vec::new()));
    let counter = hits.clone();
    let seen = arrivals.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            seen.lock().unwrap().push(Instant::now());
            let number = counter.fetch_add(1, Ordering::SeqCst);
            let reply = if number < throttled {
                format!(
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {retry_after}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
            };
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    ((origin, hits), arrivals)
}

#[tokio::test]
async fn rate_limited_requests_are_repeated_until_the_registry_answers() {
    let (origin, hits) = serve(2).await;
    let response = retry_get(&http_client(), &origin).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn persistent_rate_limiting_is_handed_back_so_callers_fail_closed() {
    let (origin, hits) = serve(usize::MAX).await;
    let response = retry_get(&http_client(), &origin).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        rate_limit::MAX_RATE_LIMIT_ATTEMPTS as usize
    );
}

#[tokio::test]
async fn once_a_host_has_exhausted_its_rate_limit_retries_other_requests_try_once() {
    // The scan is already blocked by the request that gave up; repeating the
    // full backoff for every remaining package would only stall it for longer.
    let (origin, hits) = serve(usize::MAX).await;
    let client = http_client();
    let first = retry_get(&client, &format!("{origin}/a")).await.unwrap();
    assert_eq!(first.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let before = hits.load(Ordering::SeqCst);
    let second = retry_get(&client, &format!("{origin}/b")).await.unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(hits.load(Ordering::SeqCst) - before, 1);
}

#[tokio::test]
async fn a_rate_limited_host_is_left_alone_by_every_request_until_its_wait_is_over() {
    // crates.io answers a burst with 429 for every request in flight; the
    // other requests must not keep hammering it while one of them waits.
    let ((origin, hits), arrivals) = serve_with(1, "1").await;
    let client = http_client();
    let first = {
        let client = client.clone();
        let url = format!("{origin}/a");
        tokio::spawn(async move { retry_get(&client, &url).await.map(|r| r.status()) })
    };
    while hits.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = retry_get(&client, &format!("{origin}/b")).await.unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::OK);
    assert_eq!(first.await.unwrap().unwrap(), reqwest::StatusCode::OK);
    let arrivals = arrivals.lock().unwrap().clone();
    assert_eq!(arrivals.len(), 3);
    for later in &arrivals[1..] {
        assert!(
            later.duration_since(arrivals[0]) >= Duration::from_millis(950),
            "a request reached the host {:?} after it asked for a 1s pause",
            later.duration_since(arrivals[0])
        );
    }
}

#[test]
fn backoff_without_retry_after_outlasts_a_multi_minute_block() {
    // crates.io sends 429 with no Retry-After and keeps the block up for minutes.
    let total: Duration = (0..rate_limit::MAX_RATE_LIMIT_ATTEMPTS - 1)
        .map(|attempt| rate_limit::delay(attempt, None))
        .sum();
    assert!(total >= Duration::from_secs(90), "{total:?}");
    assert!(total <= Duration::from_secs(180), "{total:?}");
}

#[test]
fn an_asked_wait_is_honoured_up_to_a_bound() {
    assert_eq!(
        rate_limit::delay(0, Some(Duration::from_secs(45))),
        Duration::from_secs(45)
    );
    assert_eq!(
        rate_limit::delay(0, Some(Duration::from_secs(3600))),
        Duration::from_secs(60)
    );
    assert_eq!(rate_limit::delay(3, Some(Duration::ZERO)), Duration::ZERO);
}

#[test]
fn jitter_stays_within_a_quarter_of_the_wait() {
    let wait = Duration::from_secs(8);
    for seed in 0..50u32 {
        assert!(rate_limit::jitter(wait, ("url", seed)) <= wait / 4);
    }
    assert_eq!(rate_limit::jitter(Duration::ZERO, 1), Duration::ZERO);
}

#[tokio::test]
async fn a_timeout_is_described_without_the_url() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream); // never answer
        }
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let err = retry_get(&client, &format!("{origin}/secret-path"))
        .await
        .unwrap_err();
    let described = describe_error(&err);
    assert!(described.contains("timed out"), "{described}");
    assert!(described.contains("3 attempts"), "{described}");
    assert!(!described.contains("secret-path"), "{described}");
}

#[tokio::test]
async fn a_refused_connection_is_described_as_a_connect_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let err = retry_get(&http_client(), &origin).await.unwrap_err();
    let described = describe_error(&err);
    assert!(described.contains("could not connect"), "{described}");
}

#[test]
fn a_described_error_keeps_its_message_and_neutralises_control_characters() {
    let err = anyhow::anyhow!("crates.io lookup for 'x' returned HTTP 503 \u{1b}[31mred");
    let described = describe_error(&err);
    assert!(
        described.starts_with("crates.io lookup for 'x' returned HTTP 503"),
        "{described}"
    );
    assert!(!described.contains('\u{1b}'), "{described}");
}

#[test]
fn a_described_error_is_bounded() {
    let err = anyhow::anyhow!("{}", "x".repeat(5000));
    assert!(describe_error(&err).chars().count() <= 400);
}
