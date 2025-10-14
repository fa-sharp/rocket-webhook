//! Generic implementations to easily validate custom webhooks

#[cfg(feature = "hmac")]
mod hmac;
#[cfg(feature = "hmac")]
pub use hmac::Hmac256Webhook;
