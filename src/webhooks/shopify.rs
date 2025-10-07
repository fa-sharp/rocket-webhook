use base64::{Engine, prelude::BASE64_STANDARD};
use bon::bon;
use hmac::Hmac;
use rocket::outcome::try_outcome;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::*;

/// # Shopify webhook
/// Looks for base64 signature in `X-Shopify-Hmac-Sha256` header
///
/// [Shopify docs](https://shopify.dev/docs/apps/build/webhooks/subscribe/https#step-5-verify-the-webhook)
pub struct ShopifyWebhook {
    secret_key: Zeroizing<Vec<u8>>,
}

#[bon]
impl ShopifyWebhook {
    #[builder]
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
            secret_key: Zeroizing::new(secret_key),
        }
    }
}

impl Webhook for ShopifyWebhook {
    type MAC = Hmac<Sha256>;

    fn name() -> &'static str {
        "Shopify webhook"
    }

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<Vec<u8>, String> {
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
