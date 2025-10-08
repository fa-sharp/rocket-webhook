use base64::{Engine, prelude::BASE64_STANDARD};
use bon::Builder;
use rocket::{data::Outcome, http::Status, outcome::try_outcome};
use tokio_util::bytes::{BufMut, Bytes, BytesMut};

use crate::webhooks::{
    Webhook,
    interface::public_key::{EcdsaP256Asn1, WebhookPublicKey},
};

/// # Sendgrid webhook
///
/// Looks for `X-Twilio-Email-Event-Webhook-Signature` and `X-Twilio-Email-Event-Webhook-Timestamp` headers.
/// Signature header should be base64 ECDSA P256 ASN1 signature of `{timestamp}{body}`
///
/// [SendGrid docs](https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features#verify-the-signature)
#[derive(Builder)]
pub struct SendGridWebhook {
    #[builder(default = "SendGrid webhook")]
    name: &'static str,
    #[builder(with = |public_key: impl Into<Vec<u8>>| Bytes::from(public_key.into()))]
    public_key: Bytes,
}

impl Webhook for SendGridWebhook {
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

impl WebhookPublicKey for SendGridWebhook {
    type ALG = EcdsaP256Asn1;

    async fn public_key<'r>(&self, _req: &'r rocket::Request<'_>) -> Outcome<'_, Bytes, String> {
        Outcome::Success(self.public_key.clone())
    }

    fn expected_signature<'r>(&self, req: &'r rocket::Request<'_>) -> Outcome<'_, Vec<u8>, String> {
        let sig_header =
            try_outcome!(self.get_header(req, "X-Twilio-Email-Event-Webhook-Signature", None));
        match BASE64_STANDARD.decode(sig_header) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                format!(
                    "X-Twilio-Email-Event-Webhook-Signature header was not valid base64: '{sig_header}'"
                ),
            )),
        }
    }

    fn message_to_verify<'r>(
        &self,
        req: &'r rocket::Request<'_>,
        body: &Bytes,
    ) -> Outcome<'_, Bytes, String> {
        let timestamp =
            try_outcome!(self.get_header(req, "X-Twilio-Email-Event-Webhook-Timestamp", None));
        let mut timestamp_and_body = BytesMut::with_capacity(timestamp.len() + body.len());
        timestamp_and_body.put(timestamp.as_bytes());
        timestamp_and_body.put(body.clone());

        Outcome::Success(timestamp_and_body.freeze())
    }
}
