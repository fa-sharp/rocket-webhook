//! Traits for webhooks

#[cfg(feature = "hmac")]
mod hmac;
mod public_key;

#[cfg(feature = "hmac")]
pub use hmac::WebhookHmac;
pub use public_key::WebhookPublicKey;
