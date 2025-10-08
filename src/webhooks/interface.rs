//! Traits for webhooks

#[cfg(feature = "hmac")]
mod hmac;
#[cfg(feature = "hmac")]
pub use hmac::WebhookHmac;

#[cfg(feature = "public-key")]
mod public_key;
#[cfg(feature = "public-key")]
pub use public_key::WebhookPublicKey;

use rocket::http::HeaderMap;

/// Try reading the body size from the content length header
fn body_size(headers: &HeaderMap) -> Option<usize> {
    headers
        .get_one("Content-Length")
        .and_then(|len| len.parse().ok())
}
