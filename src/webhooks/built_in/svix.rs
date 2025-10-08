use base64::{Engine, prelude::BASE64_STANDARD};
use bon::bon;
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
    name: &'static str,
    secret_key: Zeroizing<Vec<u8>>,
}

#[bon]
impl SvixWebhook {
    #[builder]
    pub fn new(
        #[builder(default = "Svix webhook")] name: &'static str,
        secret_key: impl AsRef<str>,
    ) -> Result<Self, base64::DecodeError> {
        let stripped_key = secret_key
            .as_ref()
            .strip_prefix("whsec_")
            .unwrap_or(secret_key.as_ref());
        let secret_key = Zeroizing::new(BASE64_STANDARD.decode(stripped_key)?);
        Ok(Self { name, secret_key })
    }
}

impl Webhook for SvixWebhook {
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

impl WebhookHmac for SvixWebhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn body_prefix<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Option<Vec<u8>>, WebhookError> {
        let id = try_outcome!(self.get_header(req, "svix-id", None));
        let timestamp = try_outcome!(self.get_header(req, "svix-timestamp", None));
        let prefix = [id.as_bytes(), b".", timestamp.as_bytes(), b"."].concat();
        Outcome::Success(Some(prefix))
    }

    /// Multiple space delimited signatures in header, prefixed by `v1,`
    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<'_, Vec<u8>, WebhookError> {
        const SIG_HEADER: &str = "svix-signature";

        let header = try_outcome!(self.get_header(req, SIG_HEADER, None));
        let Some(sig_base64) = header
            .split(' ')
            .find_map(|part| part.split_once(',').map(|p| p.1))
        else {
            return Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "Did not find signature in {SIG_HEADER} header: '{header}'"
                )),
            ));
        };

        match BASE64_STANDARD.decode(sig_base64) {
            Ok(bytes) => Outcome::Success(bytes),
            Err(_) => Outcome::Error((
                Status::BadRequest,
                WebhookError::InvalidHeader(format!(
                    "{SIG_HEADER} header was not valid base64: '{sig_base64}'"
                )),
            )),
        }
    }
}
