use base64::{Engine, prelude::BASE64_STANDARD};
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, outcome::try_outcome, tokio::io::AsyncRead};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    WebhookError,
    webhooks::{Webhook, interface::hmac::WebhookHmac},
};

const ID_HEADER: &str = "id";
const TIMESTAMP_HEADER: &str = "timestamp";
const SIG_HEADER: &str = "signature";

/// # Standard Webhook
/// **Standard Webhooks** spec used by Svix, Resend, Clerk, and others.
///
/// Looks for headers `webhook-id`, `webhook-timestamp`, `webhook-signature`. (`webhook-` prefix can
/// be configured)
///
/// Signature is base64 HMAC of `<id>.<timestamp>.<body>`
///
/// ## Links
/// - [Standard Webhooks spec](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)
/// - [Svix docs](https://docs.svix.com/receiving/verifying-payloads/how-manual)
pub struct StandardWebhook {
    secret_key: Zeroizing<Vec<u8>>,
    id_header: String,
    time_header: String,
    sig_header: String,
}

impl StandardWebhook {
    /// Instantiate using the secret key starting with `whsec_`. Assumes headers have a prefix
    /// of `webhook-`.
    pub fn with_secret(secret_key: impl AsRef<str>) -> Result<Self, base64::DecodeError> {
        let stripped_key = secret_key
            .as_ref()
            .strip_prefix("whsec_")
            .unwrap_or(secret_key.as_ref());
        let secret_key = Zeroizing::new(BASE64_STANDARD.decode(stripped_key)?);
        Ok(Self {
            secret_key,
            id_header: format!("webhook-{ID_HEADER}"),
            sig_header: format!("webhook-{SIG_HEADER}"),
            time_header: format!("webhook-{TIMESTAMP_HEADER}"),
        })
    }

    /// Instantiate using the secret key starting with `whsec_` and a header prefix (include the
    /// dash when providing the header prefix, e.g. `svix-`).
    pub fn with_secret_and_prefix(
        secret_key: impl AsRef<str>,
        header_prefix: impl AsRef<str>,
    ) -> Result<Self, base64::DecodeError> {
        let stripped_key = secret_key
            .as_ref()
            .strip_prefix("whsec_")
            .unwrap_or(secret_key.as_ref());
        let secret_key = Zeroizing::new(BASE64_STANDARD.decode(stripped_key)?);
        Ok(Self {
            secret_key,
            id_header: format!("{}{ID_HEADER}", header_prefix.as_ref()),
            sig_header: format!("{}{SIG_HEADER}", header_prefix.as_ref()),
            time_header: format!("{}{TIMESTAMP_HEADER}", header_prefix.as_ref()),
        })
    }
}

impl Webhook for StandardWebhook {
    async fn validate_body(
        &self,
        req: &Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        self.validate_with_hmac(req, body, time_bounds).await
    }
}

impl WebhookHmac for StandardWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn body_prefix(
        &self,
        req: &Request<'_>,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Option<Vec<u8>>, WebhookError> {
        let id = try_outcome!(self.get_header(req, &self.id_header, None));
        let timestamp = try_outcome!(self.get_header(req, &self.time_header, None));
        try_outcome!(self.validate_timestamp(timestamp, time_bounds));

        let prefix = [id.as_bytes(), b".", timestamp.as_bytes(), b"."].concat();
        Outcome::Success(Some(prefix))
    }

    /// Multiple space delimited signatures in header, prefixed by `v1,`
    fn expected_signatures(&self, req: &Request<'_>) -> Outcome<'_, Vec<Vec<u8>>, WebhookError> {
        let header = try_outcome!(self.get_header(req, &self.sig_header, None));
        let mut signatures = Vec::new();
        for base64_sig in header.split(' ').filter_map(|s| s.strip_prefix("v1,")) {
            match BASE64_STANDARD.decode(base64_sig) {
                Ok(bytes) => signatures.push(bytes),
                Err(_) => {
                    return Outcome::Error((
                        Status::BadRequest,
                        WebhookError::InvalidHeader(format!(
                            "Signature in '{}' header was not valid base64: got '{base64_sig}'",
                            self.sig_header
                        )),
                    ));
                }
            }
        }

        Outcome::Success(signatures)
    }
}
