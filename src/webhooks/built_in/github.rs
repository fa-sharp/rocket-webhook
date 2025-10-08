use bon::Builder;
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, outcome::try_outcome, tokio::io::AsyncRead};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    WebhookError,
    webhooks::{Webhook, interface::hmac::WebhookHmac},
};

/// # GitHub webhook
/// Looks for hex signature in `X-Hub-Signature-256` header, with a 'sha256=' prefix
///
/// [GitHub docs](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
#[derive(Builder)]
pub struct GitHubWebhook {
    #[builder(default = "GitHub webhook")]
    name: &'static str,
    #[builder(with = |secret: impl Into<Vec<u8>>| Zeroizing::new(secret.into()))]
    secret_key: Zeroizing<Vec<u8>>,
}

impl Webhook for GitHubWebhook {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn read_body_and_validate<'r>(
        &self,
        req: &'r Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        let raw_body = try_outcome!(self.read_and_verify_with_hmac(req, body).await);
        Outcome::Success(raw_body)
    }
}

impl WebhookHmac for GitHubWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Vec<u8>, WebhookError> {
        let sig_header = try_outcome!(self.get_header(req, "X-Hub-Signature-256", Some("sha256=")));
        match hex::decode(sig_header) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "X-Hub-Signature-256 header was not valid hex: '{sig_header}'"
                )),
            )),
        }
    }
}
