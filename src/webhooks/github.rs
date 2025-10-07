use bon::bon;
use hmac::Hmac;
use rocket::outcome::try_outcome;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::*;

/// # GitHub webhook
/// Looks for hex signature in `X-Hub-Signature-256` header, with a 'sha256=' prefix
///
/// [GitHub docs](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
pub struct GitHubWebhook {
    secret_key: Zeroizing<Vec<u8>>,
}

#[bon]
impl GitHubWebhook {
    #[builder]
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
            secret_key: Zeroizing::new(secret_key),
        }
    }
}

impl Webhook for GitHubWebhook {
    type MAC = Hmac<Sha256>;

    fn name() -> &'static str {
        "GitHub webhook"
    }

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<Vec<u8>, String> {
        let sig_header = try_outcome!(self.get_header(req, "X-Hub-Signature-256", Some("sha256=")));
        match hex::decode(sig_header) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                format!("X-Hub-Signature-256 header was not valid hex: '{sig_header}'"),
            )),
        }
    }
}
