//! HTTP client construction and retrying GETs shared by every registry and parser fetch.
use anyhow::Result;
use std::time::Duration;

mod rate_limit;

/// Maximum number of retry attempts for transient HTTP errors.
pub(crate) const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (doubled each retry).
pub(crate) const RETRY_BASE_DELAY_MS: u64 = 200;
/// Longest error description put into an issue.
const MAX_DESCRIPTION_CHARS: usize = 300;

/// Send a GET request with retry on transient failures (5xx, timeouts, connection errors).
/// Returns the response on success, or the last error after exhausting retries.
pub(crate) async fn retry_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
    // A 429 means "slow down", not "failed": every request to the host waits as
    // the registry asks (bounded) and then asks again. Exhausting the attempts
    // hands the 429 to the caller, which fails closed.
    let host = rate_limit::host_key(url);
    let attempts = rate_limit::attempts_allowed(&host);
    let mut last_wait = Duration::ZERO;
    for attempt in 0..attempts {
        rate_limit::wait_until_unpaused(&host).await;
        tokio::time::sleep(rate_limit::jitter(last_wait, (url, attempt))).await;
        let response = retry_get_once(client, url).await?;
        if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
            rate_limit::mark_answered(&host);
            return Ok(response);
        }
        if attempt == attempts - 1 {
            rate_limit::mark_exhausted(&host);
            return Ok(response);
        }
        last_wait = rate_limit::delay(attempt, retry_after(&response));
        rate_limit::pause(&host, last_wait);
    }
    unreachable!("the loop returns on its last attempt")
}

fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

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
            Err(e) if is_transient(&e) => {
                return Err(
                    anyhow::Error::new(e).context(format!("gave up after {MAX_RETRIES} attempts"))
                );
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

/// Why a registry request failed, for an issue message: the error chain with
/// each `reqwest` error reduced to its kind (its display names the URL), control
/// characters escaped, bounded in length.
pub(crate) fn describe_error(err: &anyhow::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    for cause in err.chain() {
        let text = match cause.downcast_ref::<reqwest::Error>() {
            Some(err) => reqwest_failure_kind(err).to_string(),
            None => cause.to_string(),
        };
        let text = text.trim().to_string();
        if !text.is_empty() && parts.last() != Some(&text) {
            parts.push(text);
        }
    }
    let joined: String = parts
        .join(": ")
        .chars()
        .flat_map(|ch| {
            let escaped: Vec<char> = if ch.is_control() {
                ch.escape_default().collect()
            } else {
                vec![ch]
            };
            escaped
        })
        .collect();
    if joined.chars().count() <= MAX_DESCRIPTION_CHARS {
        return joined;
    }
    let mut cut: String = joined.chars().take(MAX_DESCRIPTION_CHARS).collect();
    cut.push_str("...");
    cut
}

fn reqwest_failure_kind(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        "request timed out"
    } else if err.is_connect() {
        "could not connect"
    } else if err.is_decode() {
        "could not decode the response body"
    } else if err.is_body() {
        "reading the response body failed"
    } else if err.is_redirect() {
        "redirect failed"
    } else {
        "request failed"
    }
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
