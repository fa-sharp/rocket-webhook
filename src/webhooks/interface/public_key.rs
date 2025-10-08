//! Interface for webhooks that use asymmetric keys for signatures

use rocket::{
    Request,
    data::Outcome,
    http::Status,
    outcome::try_outcome,
    tokio::io::{AsyncRead, AsyncReadExt},
};
use tokio_util::bytes::Bytes;

use crate::webhooks::{Webhook, interface::body_size};

/// Public key algorithms
pub mod algorithms;

/// Trait for algorithms to use for assymetric key verification
pub trait WebhookPublicKeyAlgorithm {
    fn verify(public_key: &Bytes, message: &[u8], signature: &[u8]) -> Result<(), String>;
}

/// Trait for webhooks that use asymmetric keys for signatures
pub trait WebhookPublicKey: Webhook {
    /// Algorithm used for verification
    type ALG: WebhookPublicKeyAlgorithm;

    /// Get the public key for the webhook signature. This is async in case the public key needs
    /// to be fetched externally. The public key can be cached in Rocket state, accessible via
    /// `req.rocket().state()`.
    ///
    /// Uses the [tokio_util::bytes::Bytes] struct to avoid unnecessary cloning.
    fn public_key<'r>(
        &self,
        req: &'r Request<'_>,
    ) -> impl Future<Output = Outcome<'_, Bytes, String>> + Send + Sync;

    /// Get the expected signature from the request
    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Vec<u8>, String>;

    /// Get the message that needs to be verified. Any adjustments can be made to the body here
    /// before calculating the signature (e.g. prefixes or hashes or other random things that the
    /// provider has decided to do).
    ///
    /// Uses the [tokio_util::bytes::Bytes] struct to avoid unnecessary cloning of the body.
    #[allow(unused_variables)]
    fn message_to_verify<'r>(
        &self,
        req: &'r Request<'_>,
        body: &Bytes,
    ) -> Outcome<'_, Bytes, String> {
        Outcome::Success(body.clone())
    }

    /// Read the raw body and verify with the public key and configured algorithm
    fn read_and_verify_with_public_key<'r>(
        &self,
        req: &'r Request<'_>,
        mut body: impl AsyncRead + Unpin + Send + Sync,
    ) -> impl Future<Output = Outcome<'_, Vec<u8>, String>> + Send + Sync
    where
        Self: Sync,
    {
        async move {
            // Get expected signature from request
            let expected_signature = try_outcome!(self.expected_signature(req));

            // Get public key
            let public_key = try_outcome!(self.public_key(req).await);

            // Read body stream
            let mut raw_body = Vec::with_capacity(body_size(req.headers()).unwrap_or(512));
            if let Err(e) = body.read_to_end(&mut raw_body).await {
                return Outcome::Error((Status::BadRequest, format!("Body read error: {e}")));
            }
            let raw_body = Bytes::from(raw_body);

            // Verify signature with public key
            let message = try_outcome!(self.message_to_verify(req, &raw_body));
            if let Err(e) = Self::ALG::verify(&public_key, &message, &expected_signature) {
                return Outcome::Error((Status::Unauthorized, format!("Invalid signature: {e}")));
            }

            Outcome::Success(raw_body.into())
        }
    }
}
