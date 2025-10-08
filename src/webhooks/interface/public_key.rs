use rocket::Request;

use crate::webhooks::Webhook;

/// Trait for webhooks that use asymmetric keys for signatures
pub trait WebhookPublicKey: Webhook {
    /// Get the public key for the webhook signature
    fn public_key<'r>(&self, req: &'r Request<'_>) -> impl Future<Output = Vec<u8>> + Send;
}
