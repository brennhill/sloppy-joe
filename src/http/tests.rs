use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn serve(throttled: usize) -> (String, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let seen = counter.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let reply = if seen < throttled {
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            };
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    (origin, hits)
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
    assert_eq!(hits.load(Ordering::SeqCst), MAX_RATE_LIMIT_RETRIES as usize);
}
