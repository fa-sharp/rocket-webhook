use base64::{Engine, prelude::BASE64_STANDARD};
use rocket::{data::Outcome, http::Status, outcome::try_outcome};
use tokio_util::bytes::{Bytes, BytesMut};

use crate::{
    WebhookError,
    webhooks::{
        Webhook,
        interface::public_key::{WebhookPublicKey, algorithms::p256::EcdsaP256Asn1},
    },
};

/// # Sendgrid webhook
///
/// Looks for `X-Twilio-Email-Event-Webhook-Signature` and `X-Twilio-Email-Event-Webhook-Timestamp` headers.
/// Signature header should be base64 ECDSA P256 ASN1 signature of `{timestamp}{body}`
///
/// [SendGrid docs](https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features#verify-the-signature)
pub struct SendGridWebhook {
    public_key: Bytes,
}

impl SendGridWebhook {
    /// Instantiate using the base64 public key from SendGrid
    pub fn with_public_key(public_key: impl AsRef<str>) -> Result<Self, base64::DecodeError> {
        let public_key = Bytes::from(BASE64_STANDARD.decode(public_key.as_ref())?);
        Ok(Self { public_key })
    }
}

impl Webhook for SendGridWebhook {
    async fn validate_body(
        &self,
        req: &rocket::Request<'_>,
        body: impl rocket::tokio::io::AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        self.validate_with_public_key(req, body, time_bounds).await
    }
}

impl WebhookPublicKey for SendGridWebhook {
    type ALG = EcdsaP256Asn1;

    async fn public_key(&self, _req: &rocket::Request<'_>) -> Outcome<'_, Bytes, WebhookError> {
        Outcome::Success(self.public_key.clone())
    }

    fn expected_signature(&self, req: &rocket::Request<'_>) -> Outcome<'_, Vec<u8>, WebhookError> {
        let sig_header =
            try_outcome!(self.get_header(req, "X-Twilio-Email-Event-Webhook-Signature", None));
        match BASE64_STANDARD.decode(sig_header) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "X-Twilio-Email-Event-Webhook-Signature header was not valid base64: '{sig_header}'"
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
        let timestamp =
            try_outcome!(self.get_header(req, "X-Twilio-Email-Event-Webhook-Timestamp", None));
        try_outcome!(self.validate_timestamp(timestamp, time_bounds));

        let mut timestamp_and_body = BytesMut::with_capacity(timestamp.len() + body.len());
        timestamp_and_body.extend_from_slice(timestamp.as_bytes());
        timestamp_and_body.extend_from_slice(body);

        Outcome::Success(timestamp_and_body.freeze())
    }
}
