//! Webhook traits and implementations

use hmac::{Mac, digest::KeyInit};
use rocket::{
    Request,
    data::Outcome,
    futures::StreamExt,
    http::{HeaderMap, Status},
    outcome::try_outcome,
    tokio::io::AsyncRead,
};
use tokio_util::io::ReaderStream;

mod github;
mod shopify;
mod slack;
mod stripe;

/// Built-in webhook validators
pub mod built_in {
    pub use super::github::GitHubWebhook;
    pub use super::shopify::ShopifyWebhook;
    pub use super::slack::SlackWebhook;
    pub use super::stripe::StripeWebhook;
}

/// Shared interface for all webhooks
pub trait Webhook {
    /// Name of the webhook
    fn name(&self) -> &'static str;

    /// Read body and validate webhook.
    fn read_body_and_validate<'r>(
        &self,
        req: &'r Request<'_>,
        body_reader: impl AsyncRead + Unpin + Send + Sync,
    ) -> impl Future<Output = Outcome<'_, Vec<u8>, String>> + Send + Sync;

    /// Retrieve a header that's expected for a webhook request. The default
    /// implementation looks for the header and returns an error if it was not provided.
    /// It can also optionally strip a given prefix.
    fn get_header<'r>(
        &self,
        req: &'r Request<'_>,
        name: &str,
        prefix: Option<&str>,
    ) -> Outcome<'_, &'r str, String> {
        match req.headers().get_one(name) {
            Some(value) => match prefix {
                None => Outcome::Success(value),
                Some(prefix) => match value.strip_prefix(prefix) {
                    Some(stripped) => Outcome::Success(stripped),
                    None => Outcome::Error((
                        Status::BadRequest,
                        format!("Header '{name}' doesn't have required prefix: got '{value}'"),
                    )),
                },
            },
            None => Outcome::Error((Status::BadRequest, format!("Missing header '{name}'"))),
        }
    }
}

/// Trait for webhooks that use HMAC signature validation.
pub trait WebhookHmac: Webhook {
    /// MAC algorithm (from the `hmac` crate) used to calculate the signature
    type MAC: Mac + KeyInit + Send;

    /// Get the secret key used to sign the webhook
    fn secret_key(&self) -> &[u8];

    /// Get the expected signature from the request. To obtain required headers,
    /// you can use the `self.get_header()` utility.
    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Vec<u8>, String>;

    /// Read the request body and verify the HMAC signature. The default implementation calculates the HMAC
    /// directly from the raw streamed body (with a prefix if configured). You can provide your own implementation
    /// if the signature is calculated differently.
    fn read_body_and_hmac<'r>(
        &self,
        req: &'r Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
    ) -> impl Future<Output = Outcome<'_, Vec<u8>, String>> + Send + Sync
    where
        Self: Sync,
        Self::MAC: Sync,
    {
        async {
            // Get expected signature from request
            let expected_signature = try_outcome!(self.expected_signature(req));

            // Get secret key and initialize HMAC
            let key = self.secret_key();
            let mut mac = <<Self as WebhookHmac>::MAC as hmac::Mac>::new_from_slice(key)
                .expect("HMAC should take any key length");

            // Update HMAC with prefix if there is one
            if let Some(prefix) = try_outcome!(self.body_prefix(req)) {
                mac.update(&prefix);
            }

            // Read body stream while calculating HMAC
            let mut body_stream = ReaderStream::new(body);
            let mut raw_body = Vec::with_capacity(body_size(req.headers()).unwrap_or(512));
            while let Some(chunk_result) = body_stream.next().await {
                match chunk_result {
                    Ok(chunk_bytes) => {
                        mac.update(&chunk_bytes);
                        raw_body.extend(chunk_bytes);
                    }
                    Err(e) => {
                        return Outcome::Error((
                            Status::BadRequest,
                            format!("Body read error: {e}"),
                        ));
                    }
                }
            }

            // Verify signature
            if let Err(e) = mac.verify_slice(&expected_signature) {
                return Outcome::Error((Status::BadRequest, format!("Invalid signature: {e}")));
            }

            Outcome::Success(raw_body)
        }
    }

    /// An optional prefix to attach to the raw body when calculating the signature
    #[allow(unused_variables)]
    fn body_prefix<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Option<Vec<u8>>, String> {
        Outcome::Success(None)
    }
}

/// Try reading the body size from the content length header
fn body_size(headers: &HeaderMap) -> Option<usize> {
    headers
        .get_one("Content-Length")
        .and_then(|len| len.parse().ok())
}
