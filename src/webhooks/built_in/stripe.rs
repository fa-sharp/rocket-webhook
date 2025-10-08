use bon::Builder;
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, outcome::try_outcome, tokio::io::AsyncRead};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    WebhookError,
    webhooks::{Webhook, interface::hmac::WebhookHmac},
};

/// # Stripe webhook
/// Looks for the `Stripe-Signature` header, splits it by `,` and then
/// reads `t=<timestamp>` and `v1=<hex signature>` (multiple signatures supported).
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

const SIG_HEADER: &str = "Stripe-Signature";

impl Webhook for StripeWebhook {
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

impl WebhookHmac for StripeWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signatures<'r>(
        &self,
        req: &'r Request<'_>,
    ) -> Outcome<'_, Vec<Vec<u8>>, WebhookError> {
        let header = try_outcome!(self.get_header(req, SIG_HEADER, None));
        let mut signatures = Vec::new();
        for hex_sig in header.split(',').filter_map(|s| s.strip_prefix("v1=")) {
            match hex::decode(hex_sig) {
                Ok(bytes) => signatures.push(bytes),
                Err(_) => {
                    return Outcome::Error((
                        Status::BadRequest,
                        WebhookError::InvalidHeader(format!(
                            "Signature in {SIG_HEADER} header was not valid hex: '{hex_sig}'"
                        )),
                    ));
                }
            };
        }

        Outcome::Success(signatures)
    }

    fn body_prefix<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Option<Vec<u8>>, WebhookError> {
        let header = try_outcome!(self.get_header(req, SIG_HEADER, None));
        let Some(time) = header.split(',').find_map(|part| part.strip_prefix("t=")) else {
            return Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "Did not find timestamp in header: '{header}'"
                )),
            ));
        };
        let prefix = [time.as_bytes(), b"."].concat();
        Outcome::Success(Some(prefix))
    }
}
