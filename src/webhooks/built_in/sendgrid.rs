use base64::{Engine, prelude::BASE64_STANDARD};
use bon::bon;
use rocket::{data::Outcome, http::Status, outcome::try_outcome};
use tokio_util::bytes::{BufMut, Bytes, BytesMut};

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
    name: &'static str,
    public_key: Bytes,
}

#[bon]
impl SendGridWebhook {
    #[builder]
    pub fn new(
        #[builder(default = "SendGrid webhook")] name: &'static str,
        /// The base64 public key from SendGrid
        public_key: impl AsRef<str>,
    ) -> Result<Self, base64::DecodeError> {
        let public_key = Bytes::from(BASE64_STANDARD.decode(public_key.as_ref())?);
        Ok(Self { name, public_key })
    }
}

impl Webhook for SendGridWebhook {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn read_body_and_validate<'r>(
        &self,
        req: &'r rocket::Request<'_>,
        body_reader: impl rocket::tokio::io::AsyncRead + Unpin + Send + Sync,
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        let raw_body = try_outcome!(self.read_and_verify_with_public_key(req, body_reader).await);
        Outcome::Success(raw_body)
    }
}

impl WebhookPublicKey for SendGridWebhook {
    type ALG = EcdsaP256Asn1;

    async fn public_key<'r>(
        &self,
        _req: &'r rocket::Request<'_>,
    ) -> Outcome<'_, Bytes, WebhookError> {
        Outcome::Success(self.public_key.clone())
    }

    fn expected_signature<'r>(
        &self,
        req: &'r rocket::Request<'_>,
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
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

    fn message_to_verify<'r>(
        &self,
        req: &'r rocket::Request<'_>,
        body: &Bytes,
    ) -> Outcome<'_, Bytes, WebhookError> {
        let timestamp =
            try_outcome!(self.get_header(req, "X-Twilio-Email-Event-Webhook-Timestamp", None));
        let mut timestamp_and_body = BytesMut::with_capacity(timestamp.len() + body.len());
        timestamp_and_body.put(timestamp.as_bytes());
        timestamp_and_body.put(body.clone());

        Outcome::Success(timestamp_and_body.freeze())
    }
}
