use bon::Builder;
use hmac::Hmac;
use rocket::{Request, data::Outcome, http::Status, tokio::io::AsyncRead};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    WebhookError,
    webhooks::{Webhook, interface::hmac::WebhookHmac},
};

/**
A custom webhook builder using HMAC SHA256 verification of the request body.

# Example
This sets up a webhook that expects a hex-encoded signature in the `Signature-SHA256` header, and a
Unix epoch timestamp in the `Timestamp` header that will be attached as a suffix to the body
when calculating the signature:

```
use rocket_webhook::{WebhookError, webhooks::generic::Hmac256Webhook};

let my_webhook = Hmac256Webhook::builder()
    .secret("my-secret")
    .expected_signatures(|req| {
        req.headers()
            .get_one("Signature-SHA256")
            .and_then(|header| hex::decode(header).ok())
            .map(|header| vec![header])
    })
    .body_suffix(|req, (min_time, max_time)| {
        req.headers()
            .get_one("Timestamp")
            .filter(|time| time.parse::<u32>().is_ok_and(|t| t > min_time && t < max_time))
            .map(|time| time.as_bytes().to_vec())
            .ok_or_else(|| WebhookError::Timestamp("Missing/invalid Timestamp header".into()))
    })
    .build();
```
*/
#[derive(Builder)]
pub struct Hmac256Webhook {
    /// The secret used to sign the webhook. If the key is encoded in hex or base64, etc., it
    /// must be decoded to bytes first
    #[builder(with = |secret: impl Into<Vec<u8>>| Zeroizing::new(secret.into()))]
    secret: Zeroizing<Vec<u8>>,
    /// Function to get the expected, decoded signature(s) from the request (typically
    /// derived from one of the request headers).
    /// If `None` is returned, signature is presumed to be missing or invalid.
    expected_signatures: fn(req: &Request<'_>) -> Option<Vec<Vec<u8>>>,
    /// Function to get the prefix to attach to the body when calculating the signature. For replay
    /// prevention, any timestamp should be validated against the given time bounds (in Unix epoch seconds).
    body_prefix:
        Option<fn(req: &Request<'_>, time_bounds: (u32, u32)) -> Result<Vec<u8>, WebhookError>>,
    /// Function to get the suffix to attach to the body when calculating the signature. For replay
    /// prevention, any timestamp should be validated against the given time bounds (in Unix epoch seconds).
    body_suffix:
        Option<fn(req: &Request<'_>, time_bounds: (u32, u32)) -> Result<Vec<u8>, WebhookError>>,
}

impl Webhook for Hmac256Webhook {
    async fn validate_body(
        &self,
        req: &Request<'_>,
        body: impl AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Vec<u8>, WebhookError> {
        self.validate_with_hmac(req, body, time_bounds).await
    }
}

impl WebhookHmac for Hmac256Webhook {
    type MAC = Hmac<Sha256>;

    fn secret_key(&self) -> &[u8] {
        &self.secret
    }

    fn expected_signatures(&self, req: &Request<'_>) -> Outcome<'_, Vec<Vec<u8>>, WebhookError> {
        match (self.expected_signatures)(req) {
            Some(signatures) => Outcome::Success(signatures),
            None => Outcome::Error((
                Status::BadRequest,
                WebhookError::Signature("Valid signature(s) not provided in request".into()),
            )),
        }
    }

    fn body_prefix(
        &self,
        req: &Request<'_>,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Option<Vec<u8>>, WebhookError> {
        if let Some(prefix_fn) = self.body_prefix {
            match (prefix_fn)(req, time_bounds) {
                Ok(prefix) => Outcome::Success(Some(prefix)),
                Err(err) => Outcome::Error((Status::BadRequest, err)),
            }
        } else {
            Outcome::Success(None)
        }
    }

    fn body_suffix(
        &self,
        req: &Request<'_>,
        time_bounds: (u32, u32),
    ) -> Outcome<'_, Option<Vec<u8>>, WebhookError> {
        if let Some(suffix_fn) = self.body_suffix {
            match (suffix_fn)(req, time_bounds) {
                Ok(suffix) => Outcome::Success(Some(suffix)),
                Err(err) => Outcome::Error((Status::BadRequest, err)),
            }
        } else {
            Outcome::Success(None)
        }
    }
}
