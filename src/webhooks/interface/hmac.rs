//! Interface for webhooks that use HMAC signature validation

use hmac::{Mac, digest::KeyInit};
use rocket::{
    Request, data::Outcome, futures::StreamExt, http::Status, outcome::try_outcome,
    tokio::io::AsyncRead,
};
use tokio_util::io::ReaderStream;

use crate::webhooks::{Webhook, interface::body_size};

/// Trait for webhooks that use HMAC signature validation.
pub trait WebhookHmac: Webhook {
    /// MAC algorithm (from the `hmac` crate) used to calculate the signature
    type MAC: Mac + KeyInit + Send;

    /// Get the secret key used to sign the webhook
    fn secret_key(&self) -> &[u8];

    /// Get the expected signature from the request. To obtain required headers,
    /// you can use the `self.get_header()` utility.
    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Vec<u8>, String>;

    /// An optional prefix to attach to the raw body when calculating the signature
    #[allow(unused_variables)]
    fn body_prefix<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Option<Vec<u8>>, String> {
        Outcome::Success(None)
    }

    /// Read the request body and verify the HMAC signature. The default implementation calculates the HMAC
    /// directly from the raw streamed body (with a prefix if configured). You can override the implementation
    /// if the signature is calculated differently - the other trait functions will be ignored.
    fn read_and_verify_with_hmac<'r>(
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
                return Outcome::Error((Status::Unauthorized, format!("Invalid signature: {e}")));
            }

            Outcome::Success(raw_body)
        }
    }
}
