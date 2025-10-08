use bon::Builder;
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, outcome::try_outcome, tokio::io::AsyncRead};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::webhooks::{Webhook, interface::WebhookHmac};

/// # Stripe webhook
/// Looks for the `Stripe-Signature` header, splits it by `,` and then
/// reads `t=<timestamp>` and `v1=<hex signature>`. This currently does not support
/// multiple signatures sent in the request.
///
/// Signature should be a digest of `<timestamp>.<body>`
///
/// [Stripe docs](https://docs.stripe.com/webhooks?verify=verify-manually#verify-manually)
#[derive(Builder)]
pub struct StripeWebhook {
    #[builder(default = "Stripe webhook")]
    name: &'static str,
    #[builder(with = |secret: impl Into<Vec<u8>>| Zeroizing::new(secret.into()))]
    secret_key: Zeroizing<Vec<u8>>,
}

impl StripeWebhook {
    pub fn new(name: &'static str, secret_key: Vec<u8>) -> Self {
        Self {
            name,
            secret_key: Zeroizing::new(secret_key),
        }
    }
}

const SIG_HEADER: &str = "Stripe-Signature";

impl Webhook for StripeWebhook {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn read_body_and_validate<'r>(
        &self,
        req: &'r Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
    ) -> Outcome<'_, Vec<u8>, String> {
        let raw_body = try_outcome!(self.read_and_verify_with_hmac(req, body).await);
        Outcome::Success(raw_body)
    }
}

impl WebhookHmac for StripeWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Vec<u8>, String> {
        let header = try_outcome!(self.get_header(req, SIG_HEADER, None));
        let Some(signature) = header.split(',').find_map(|part| part.strip_prefix("v1=")) else {
            return Outcome::Error((
                Status::BadRequest,
                format!("Did not find signature in header: '{header}'"),
            ));
        };
        match hex::decode(signature) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                format!("{SIG_HEADER} header was not valid hex: '{signature}'"),
            )),
        }
    }

    fn body_prefix<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Option<Vec<u8>>, String> {
        let header = try_outcome!(self.get_header(req, SIG_HEADER, None));
        let Some(time) = header.split(',').find_map(|part| part.strip_prefix("t=")) else {
            return Outcome::Error((
                Status::BadRequest,
                format!("Did not find timestamp in header: '{header}'"),
            ));
        };
        let prefix = [time.as_bytes(), b"."].concat();
        Outcome::Success(Some(prefix))
    }
}
