//! Traits for webhooks

#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "public-key")]
pub mod public_key;

/// Try reading the body size from the content length header
fn body_size(headers: &rocket::http::HeaderMap) -> Option<usize> {
    headers
        .get_one("Content-Length")
        .and_then(|len| len.parse().ok())
}
