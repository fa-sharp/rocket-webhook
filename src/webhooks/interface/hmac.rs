//! Interface for webhooks that use HMAC signature validation

use hmac::{Mac, digest::KeyInit};
use rocket::{
    Request, data::Outcome, futures::StreamExt, http::Status, outcome::try_outcome,
    tokio::io::AsyncRead,
};
use subtle::ConstantTimeEq;
use tokio_util::io::ReaderStream;

use crate::{
    WebhookError,
    webhooks::{Webhook, utils::body_size},
};

/// Trait for webhooks that use HMAC signature validation.
pub trait WebhookHmac: Webhook {
    /// MAC algorithm (from the `hmac` crate) used to calculate the signature
    type MAC: Mac + KeyInit + Send;

    /// Get the secret key used to sign the webhook
    fn secret_key(&self) -> &[u8];

    /// Get the expected signature(s) from the request. To obtain required headers,
    /// you can use the `self.get_header()` utility.
    fn expected_signatures(&self, req: &Request<'_>) -> Outcome<'_, Vec<Vec<u8>>, WebhookError>;

    /// An optional prefix to attach to the raw body when calculating the signature
    #[allow(unused_variables)]
    fn body_prefix(
        &self,
        req: &Request<'_>,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Option<Vec<u8>>, WebhookError> {
        Outcome::Success(None)
    }

    /// Read the request body and verify the HMAC signature. Calculates the HMAC
    /// directly from the raw streamed body (with a prefix if configured).
    fn validate_with_hmac(
        &self,
        req: &Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> impl Future<Output = Outcome<'_, Vec<u8>, WebhookError>> + Send + Sync
    where
        Self: Sync,
        Self::MAC: Sync,
    {
        async move {
            // Get expected signatures from request
            let expected_signatures = try_outcome!(self.expected_signatures(req));

            // Get secret key and initialize HMAC
            let key = self.secret_key();
            let mut mac = <<Self as WebhookHmac>::MAC as hmac::Mac>::new_from_slice(key)
                .expect("HMAC should take any key length");

            // Update HMAC with prefix if there is one
            if let Some(prefix) = try_outcome!(self.body_prefix(req, time_bounds)) {
                mac.update(&prefix);
            }

            // Read body stream while calculating HMAC
            let mut body_stream = ReaderStream::new(body);
            let mut raw_body = Vec::with_capacity(body_size(req.headers()).unwrap_or(512));
            while let Some(chunk_result) = body_stream.next().await {
                match chunk_result {
                    Ok(chunk_bytes) => {
                        mac.update(&chunk_bytes);
                        raw_body.extend_from_slice(&chunk_bytes);
                    }
                    Err(e) => {
                        return Outcome::Error((Status::BadRequest, WebhookError::Read(e)));
                    }
                }
            }

            // Check HMAC against all provided signatures
            let body_sig = mac.finalize().into_bytes();
            for signature in expected_signatures {
                if body_sig.ct_eq(&signature).into() {
                    return Outcome::Success(raw_body);
                }
            }
            return Outcome::Error((
                Status::Unauthorized,
                WebhookError::Signature("HMAC didn't match any provided signature".into()),
            ));
        }
    }
}
