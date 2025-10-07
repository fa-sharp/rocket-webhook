use bon::bon;
use hmac::Hmac;
use rocket::outcome::try_outcome;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::*;

/// # Slack webhook
/// Looks for hex signature in `X-Slack-Signature` header, with a 'v0=' prefix,
/// as well as the timestamp from `X-Slack-Request-Timestamp`.
///
/// Signature is a digest of `v0:<timestamp>:<body>`
///
/// [Slack docs](https://docs.slack.dev/authentication/verifying-requests-from-slack/#validating-a-request)
pub struct SlackWebhook {
    secret_key: Zeroizing<Vec<u8>>,
}

#[bon]
impl SlackWebhook {
    #[builder]
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
            secret_key: Zeroizing::new(secret_key),
        }
    }
}

impl WebhookSignature for SlackWebhook {
    type MAC = Hmac<Sha256>;

    fn name() -> &'static str {
        "Slack webhook"
    }

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<Vec<u8>, String> {
        let sig_header = try_outcome!(self.get_header(req, "X-Slack-Signature", Some("v0=")));
        match hex::decode(sig_header) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                format!("X-Slack-Signature header was not valid hex: '{sig_header}'"),
            )),
        }
    }

    fn body_prefix<'r>(&self, req: &'r Request<'_>) -> Outcome<Option<Vec<u8>>, String> {
        let timestamp = try_outcome!(self.get_header(req, "X-Slack-Request-Timestamp", None));
        let prefix = [b"v0:", timestamp.as_bytes(), b":"].concat();
        Outcome::Success(Some(prefix))
    }
}
