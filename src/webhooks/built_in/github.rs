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
pub struct GitHubWebhook {
    secret_key: Zeroizing<Vec<u8>>,
}

impl GitHubWebhook {
    /// Instantiate with the secret key
    pub fn with_secret(secret_key: impl Into<Vec<u8>>) -> Self {
        Self {
            secret_key: Zeroizing::new(secret_key.into()),
        }
    }
}

impl Webhook for GitHubWebhook {
    async fn validate_body(
        &self,
        req: &Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        self.validate_with_hmac(req, body, time_bounds).await
    }
}

impl WebhookHmac for GitHubWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signatures(&self, req: &Request<'_>) -> Outcome<'_, Vec<Vec<u8>>, WebhookError> {
        let sig_header = try_outcome!(self.get_header(req, "X-Hub-Signature-256", Some("sha256=")));
        match hex::decode(sig_header) {
            Ok(bytes) => Outcome::Success(vec![bytes]),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "X-Hub-Signature-256 header was not valid hex: '{sig_header}'"
                )),
            )),
        }
    }
}
