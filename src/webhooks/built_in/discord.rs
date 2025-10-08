use bon::Builder;
use rocket::{data::Outcome, http::Status, outcome::try_outcome};
use tokio_util::bytes::{BufMut, Bytes, BytesMut};

use crate::webhooks::{Webhook, interface::WebhookPublicKey};

/// # Discord Interactions webhook
///
/// Looks for `X-Signature-Ed25519` and `X-Signature-Timestamp` headers.
/// Signature should be hex Ed25519 signature of `{timestamp}{body}`
///
/// [Discord docs](https://discord.com/developers/docs/interactions/overview#setting-up-an-endpoint-validating-security-request-headers)
#[derive(Builder)]
pub struct DiscordWebhook {
    #[builder(default = "Discord webhook")]
    name: &'static str,
    #[builder(with = |public_key: impl Into<Vec<u8>>| Bytes::from(public_key.into()))]
    public_key: Bytes,
}

impl Webhook for DiscordWebhook {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn read_body_and_validate<'r>(
        &self,
        req: &'r rocket::Request<'_>,
        body_reader: impl rocket::tokio::io::AsyncRead + Unpin + Send + Sync,
    ) -> Outcome<'_, Vec<u8>, String> {
        let raw_body = try_outcome!(self.read_and_verify_with_public_key(req, body_reader).await);
        Outcome::Success(raw_body)
    }
}

impl WebhookPublicKey for DiscordWebhook {
    async fn public_key<'r>(&self, _req: &'r rocket::Request<'_>) -> Outcome<'_, Bytes, String> {
        Outcome::Success(self.public_key.clone())
    }

    fn expected_signature<'r>(&self, req: &'r rocket::Request<'_>) -> Outcome<'_, Vec<u8>, String> {
        let sig_header = try_outcome!(self.get_header(req, "X-Signature-Ed25519", None));
        match hex::decode(sig_header) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                format!("X-Signature-Ed25519 header was not valid hex: '{sig_header}'"),
            )),
        }
    }

    fn finalize_body<'r>(
        &self,
        req: &'r rocket::Request<'_>,
        body: &Bytes,
    ) -> Outcome<'_, Bytes, String> {
        let timestamp = try_outcome!(self.get_header(req, "X-Signature-Timestamp", None));
        let mut timestamp_and_body = BytesMut::with_capacity(timestamp.len() + body.len());
        timestamp_and_body.put(timestamp.as_bytes());
        timestamp_and_body.put(body.clone());

        Outcome::Success(timestamp_and_body.freeze())
    }
}
