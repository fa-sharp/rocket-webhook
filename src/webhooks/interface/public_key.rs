use ring::signature::{ED25519, UnparsedPublicKey};
use rocket::{
    Request,
    data::Outcome,
    http::Status,
    outcome::try_outcome,
    tokio::io::{AsyncRead, AsyncReadExt},
};
use tokio_util::bytes::Bytes;

use crate::webhooks::{Webhook, interface::body_size};

/// Trait for webhooks that use asymmetric keys for signatures (default implementation
/// only supports ED25519 for now)
pub trait WebhookPublicKey: Webhook {
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

    /// Any adjustments made to the body before calculating the signature (e.g. prefixes or hashes or
    /// other random things that the provider has decided to do).
    ///
    /// Uses the [tokio_util::bytes::Bytes] struct to avoid unnecessary cloning of the body.
    #[allow(unused_variables)]
    fn finalize_body<'r>(&self, req: &'r Request<'_>, body: &Bytes) -> Outcome<'_, Bytes, String> {
        Outcome::Success(body.clone())
    }

    /// Read the raw body and verify against the public key (default implementation uses ED25519).
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
            let public_key_bytes = try_outcome!(self.public_key(req).await);
            let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes); // TODO other algorithms

            // Read body stream
            let mut raw_body = Vec::with_capacity(body_size(req.headers()).unwrap_or(512));
            if let Err(e) = body.read_to_end(&mut raw_body).await {
                return Outcome::Error((Status::BadRequest, format!("Body read error: {e}")));
            }
            let raw_body = Bytes::from(raw_body);

            // Verify signature with public key
            let body_to_verify = try_outcome!(self.finalize_body(req, &raw_body));
            if let Err(e) = public_key.verify(&body_to_verify, &expected_signature) {
                return Outcome::Error((Status::Unauthorized, format!("Invalid signature: {e}")));
            }

            Outcome::Success(raw_body.into())
        }
    }
}
