use base64::{Engine, prelude::BASE64_STANDARD};
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, outcome::try_outcome, tokio::io::AsyncRead};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    WebhookError,
    webhooks::{Webhook, interface::hmac::WebhookHmac},
};

/// # Svix webhook
/// Webhook service used by Resend, Clerk, and others.
///
/// Looks for headers `svix-id`, `svix-timestamp`, `svix-signature`
///
/// Signature is base64 HMAC of `<id>.<timestamp>.<body>`
///
/// [Svix docs](https://docs.svix.com/receiving/verifying-payloads/how-manual)
pub struct SvixWebhook {
    secret_key: Zeroizing<Vec<u8>>,
}

impl SvixWebhook {
    /// Instantiate using the secret key from Svix starting with `whsec_`
    pub fn with_secret(secret_key: impl AsRef<str>) -> Result<Self, base64::DecodeError> {
        let stripped_key = secret_key
            .as_ref()
            .strip_prefix("whsec_")
            .unwrap_or(secret_key.as_ref());
        let secret_key = Zeroizing::new(BASE64_STANDARD.decode(stripped_key)?);
        Ok(Self { secret_key })
    }
}

impl Webhook for SvixWebhook {
    async fn validate_body(
        &self,
        req: &Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        self.validate_with_hmac(req, body, time_bounds).await
    }
}

impl WebhookHmac for SvixWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn body_prefix(
        &self,
        req: &Request<'_>,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Option<Vec<u8>>, WebhookError> {
        let id = try_outcome!(self.get_header(req, "svix-id", None));
        let timestamp = try_outcome!(self.get_header(req, "svix-timestamp", None));
        try_outcome!(self.validate_timestamp(timestamp, time_bounds));

        let prefix = [id.as_bytes(), b".", timestamp.as_bytes(), b"."].concat();
        Outcome::Success(Some(prefix))
    }

    /// Multiple space delimited signatures in header, prefixed by `v1,`
    fn expected_signatures(&self, req: &Request<'_>) -> Outcome<'_, Vec<Vec<u8>>, WebhookError> {
        const SIG_HEADER: &str = "svix-signature";

        let header = try_outcome!(self.get_header(req, SIG_HEADER, None));
        let mut signatures = Vec::new();
        for base64_sig in header.split(' ').filter_map(|s| s.strip_prefix("v1,")) {
            match BASE64_STANDARD.decode(base64_sig) {
                Ok(bytes) => signatures.push(bytes),
                Err(_) => {
                    return Outcome::Error((
                        Status::BadRequest,
                        WebhookError::InvalidHeader(format!(
                            "Signature in {SIG_HEADER} header was not valid base64: '{base64_sig}'"
                        )),
                    ));
                }
            }
        }

        Outcome::Success(signatures)
    }
}
