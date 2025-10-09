use base64::{Engine, prelude::BASE64_STANDARD};
use bon::Builder;
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, outcome::try_outcome};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    WebhookError,
    webhooks::{Webhook, interface::hmac::WebhookHmac},
};

/// # Shopify webhook
/// Looks for base64 signature in `X-Shopify-Hmac-Sha256` header
///
/// [Shopify docs](https://shopify.dev/docs/apps/build/webhooks/subscribe/https#step-5-verify-the-webhook)
#[derive(Builder)]
pub struct ShopifyWebhook {
    #[builder(default = "Shopify webhook")]
    name: &'static str,
    #[builder(with = |secret: impl Into<Vec<u8>>| Zeroizing::new(secret.into()))]
    secret_key: Zeroizing<Vec<u8>>,
}

impl Webhook for ShopifyWebhook {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn validate_body(
        &self,
        req: &Request<'_>,
        body: impl rocket::tokio::io::AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        let raw_body = try_outcome!(self.validate_with_hmac(req, body, time_bounds).await);
        Outcome::Success(raw_body)
    }
}

impl WebhookHmac for ShopifyWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signatures(&self, req: &Request<'_>) -> Outcome<'_, Vec<Vec<u8>>, WebhookError> {
        let sig_header = try_outcome!(self.get_header(req, "X-Shopify-Hmac-Sha256", None));
        match BASE64_STANDARD.decode(sig_header) {
            Ok(bytes) => Outcome::Success(vec![bytes]),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "X-Shopify-Hmac-Sha256 header was not valid base64: '{sig_header}'"
                )),
            )),
        }
    }
}
