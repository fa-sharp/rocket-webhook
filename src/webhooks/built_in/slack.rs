use bon::Builder;
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, outcome::try_outcome, tokio::io::AsyncRead};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    WebhookError,
    webhooks::{Webhook, interface::hmac::WebhookHmac},
};

/// # Slack webhook
/// Looks for hex signature in `X-Slack-Signature` header, with a 'v0=' prefix,
/// as well as the timestamp from `X-Slack-Request-Timestamp`.
///
/// Signature is a digest of `v0:<timestamp>:<body>`
///
/// [Slack docs](https://docs.slack.dev/authentication/verifying-requests-from-slack/#validating-a-request)
#[derive(Builder)]
pub struct SlackWebhook {
    #[builder(default = "Slack webhook")]
    name: &'static str,
    #[builder(with = |secret: impl Into<Vec<u8>>| Zeroizing::new(secret.into()))]
    secret_key: Zeroizing<Vec<u8>>,
}

impl Webhook for SlackWebhook {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn validate_body(
        &self,
        req: &Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        let raw_body = try_outcome!(self.validate_with_hmac(req, body, time_bounds).await);
        Outcome::Success(raw_body)
    }
}

impl WebhookHmac for SlackWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signatures(&self, req: &Request<'_>) -> Outcome<'_, Vec<Vec<u8>>, WebhookError> {
        let sig_header = try_outcome!(self.get_header(req, "X-Slack-Signature", Some("v0=")));
        match hex::decode(sig_header) {
            Ok(bytes) => Outcome::Success(vec![bytes]),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "X-Slack-Signature header was not valid hex: '{sig_header}'"
                )),
            )),
        }
    }

    fn body_prefix(
        &self,
        req: &Request<'_>,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Option<Vec<u8>>, WebhookError> {
        let timestamp = try_outcome!(self.get_header(req, "X-Slack-Request-Timestamp", None));
        try_outcome!(self.validate_timestamp(timestamp, time_bounds));

        let prefix = [b"v0:", timestamp.as_bytes(), b":"].concat();
        Outcome::Success(Some(prefix))
    }
}
