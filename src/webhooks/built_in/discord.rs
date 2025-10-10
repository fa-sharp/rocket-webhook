use hex::FromHexError;
use rocket::{data::Outcome, http::Status, outcome::try_outcome, tokio::io::AsyncRead};
use tokio_util::bytes::{Bytes, BytesMut};

use crate::{
    WebhookError,
    webhooks::{
        Webhook,
        interface::public_key::{WebhookPublicKey, algorithms::ed25519::Ed25519},
    },
};

/// # Discord Interactions webhook
///
/// Looks for `X-Signature-Ed25519` and `X-Signature-Timestamp` headers.
/// Signature should be hex Ed25519 signature of `{timestamp}{body}`
///
/// [Discord docs](https://discord.com/developers/docs/interactions/overview#setting-up-an-endpoint-validating-security-request-headers)
pub struct DiscordWebhook {
    public_key: Bytes,
}

impl DiscordWebhook {
    /// Instantiate using the hex public key from Discord
    pub fn with_public_key(public_key: impl AsRef<str>) -> Result<Self, FromHexError> {
        let public_key = Bytes::from(hex::decode(public_key.as_ref())?);
        Ok(Self { public_key })
    }
}

impl Webhook for DiscordWebhook {
    async fn validate_body(
        &self,
        req: &rocket::Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        self.validate_with_public_key(req, body, time_bounds).await
    }
}

impl WebhookPublicKey for DiscordWebhook {
    type ALG = Ed25519;

    async fn public_key(&self, _req: &rocket::Request<'_>) -> Outcome<'_, Bytes, WebhookError> {
        Outcome::Success(self.public_key.clone())
    }

    fn expected_signature(&self, req: &rocket::Request<'_>) -> Outcome<'_, Vec<u8>, WebhookError> {
        let sig_header = try_outcome!(self.get_header(req, "X-Signature-Ed25519", None));
        match hex::decode(sig_header) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "X-Signature-Ed25519 header was not valid hex: '{sig_header}'"
                )),
            )),
        }
    }

    fn message_to_verify(
        &self,
        req: &rocket::Request<'_>,
        body: &Bytes,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Bytes, WebhookError> {
        let timestamp = try_outcome!(self.get_header(req, "X-Signature-Timestamp", None));
        try_outcome!(self.validate_timestamp(timestamp, time_bounds));

        let mut timestamp_and_body = BytesMut::with_capacity(timestamp.len() + body.len());
        timestamp_and_body.extend_from_slice(timestamp.as_bytes());
        timestamp_and_body.extend_from_slice(body);

        Outcome::Success(timestamp_and_body.freeze())
    }
}
