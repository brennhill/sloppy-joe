//! HTTP client construction and retrying GETs shared by every registry and parser fetch.
use anyhow::Result;
use std::time::Duration;

/// Maximum number of retry attempts for transient HTTP errors.
pub(crate) const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (doubled each retry).
pub(crate) const RETRY_BASE_DELAY_MS: u64 = 200;

/// Send a GET request with retry on transient failures (5xx, timeouts, connection errors).
/// Returns the response on success, or the last error after exhausting retries.
pub(crate) async fn retry_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
    // A 429 means "slow down", not "failed": wait as the registry asks (bounded) and ask again.
    // Exhausting the attempts hands the 429 to the caller, which fails closed.
    for attempt in 0..MAX_RATE_LIMIT_RETRIES {
        let response = retry_get_once(client, url).await?;
        if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS
            || attempt == MAX_RATE_LIMIT_RETRIES - 1
        {
            return Ok(response);
        }
        let asked = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let wait = asked
            .unwrap_or_else(|| Duration::from_millis(RATE_LIMIT_BASE_DELAY_MS << attempt))
            .min(MAX_RATE_LIMIT_WAIT);
        tokio::time::sleep(wait).await;
    }
    unreachable!("the loop returns on its last attempt")
}

/// Maximum times a rate-limited (HTTP 429) request is repeated.
const MAX_RATE_LIMIT_RETRIES: u32 = 8;
const RATE_LIMIT_BASE_DELAY_MS: u64 = 1000;
const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(15);

async fn retry_get_once(client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
    let mut last_err = None;
    for attempt in 0..MAX_RETRIES {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_server_error() && attempt < MAX_RETRIES - 1 => {
                let delay = RETRY_BASE_DELAY_MS * 2u64.pow(attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                last_err = Some(anyhow::anyhow!(
                    "server error HTTP {} (attempt {}/{})",
                    resp.status(),
                    attempt + 1,
                    MAX_RETRIES
                ));
            }
            Ok(resp) => return Ok(resp),
            Err(e) if attempt < MAX_RETRIES - 1 && is_transient(&e) => {
                let delay = RETRY_BASE_DELAY_MS * 2u64.pow(attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                last_err = Some(e.into());
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("retry exhausted")))
}

/// Check if a reqwest error is transient (worth retrying).
pub(crate) fn is_transient(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("sloppy-joe (https://github.com/brennhill/sloppy-joe)")
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("failed to build HTTP client")
}

#[cfg(test)]
mod tests;
