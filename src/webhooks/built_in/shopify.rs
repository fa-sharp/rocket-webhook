use base64::{Engine, prelude::BASE64_STANDARD};
use bon::Builder;
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, outcome::try_outcome, tokio::io::AsyncRead};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::webhooks::{Webhook, interface::hmac::WebhookHmac};

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

    async fn read_body_and_validate<'r>(
        &self,
        req: &'r Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
    ) -> Outcome<'_, Vec<u8>, String> {
        let raw_body = try_outcome!(self.read_and_verify_with_hmac(req, body).await);
        Outcome::Success(raw_body)
    }
}

impl WebhookHmac for ShopifyWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Vec<u8>, String> {
        let sig_header = try_outcome!(self.get_header(req, "X-Shopify-Hmac-Sha256", None));
        match BASE64_STANDARD.decode(sig_header) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                format!("X-Shopify-Hmac-Sha256 header was not valid base64: '{sig_header}'"),
            )),
        }
    }
}
