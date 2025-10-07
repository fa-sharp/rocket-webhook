//! Webhook traits and implementations

use hmac::{Mac, digest::KeyInit};
use rocket::{
    Request,
    data::{DataStream, Outcome},
    futures::StreamExt,
    http::{HeaderMap, Status},
    outcome::try_outcome,
};
use tokio_util::bytes::{Bytes, BytesMut};
use tokio_util::io::ReaderStream;

mod github;
mod slack;

/// Built-in webhook validators
pub mod built_in {
    pub use super::github::GitHubWebhook;
    pub use super::slack::SlackWebhook;
}

/// Trait that describes how to read and verify a webhook. You can implement this trait
/// to use custom webhooks not included in the crate.
pub trait Webhook {
    /// MAC algorithm (from the `hmac` crate) used to calculate the signature
    type MAC: Mac + KeyInit + Send;

    /// The name of the webhook
    fn name() -> &'static str;

    /// Get the secret key used to sign the webhook
    fn secret_key(&self) -> &[u8];

    /// Get the expected signature from the request. To obtain required headers,
    /// you can use the `self.get_header()` utility.
    fn expected_signature<'r>(&self, req: &'r Request<'_>) -> Outcome<Vec<u8>, String>;

    /// An optional prefix to attach to the raw body when calculating the signature
    #[allow(unused_variables)]
    fn body_prefix<'r>(&self, req: &'r Request<'_>) -> Outcome<Option<Vec<u8>>, String> {
        Outcome::Success(None)
    }

    /// Read the request body and calculate the HMAC signature. The default implementation calculates it
    /// directly from the raw streamed body (with a prefix if configured). You can provide your own implementation
    /// if the signature is calculated differently.
    fn read_body_and_hmac<'r>(
        &self,
        req: &'r Request<'_>,
        mut stream: ReaderStream<DataStream<'r>>,
    ) -> impl Future<Output = Outcome<(Bytes, Self::MAC), String>> + Send + Sync
    where
        Self: Sync,
        Self::MAC: Sync,
    {
        async move {
            let key = self.secret_key();
            let mut mac = <<Self as Webhook>::MAC as hmac::Mac>::new_from_slice(key)
                .expect("HMAC should take any key length");

            // Update HMAC with prefix if there is one
            if let Some(prefix) = try_outcome!(self.body_prefix(req)) {
                mac.update(&prefix);
            }

            // Read body stream while calculating HMAC
            let mut raw_body = BytesMut::with_capacity(body_size(req.headers()).unwrap_or(512));
            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(chunk_bytes) => {
                        mac.update(&chunk_bytes);
                        raw_body.extend(chunk_bytes);
                    }
                    Err(e) => {
                        return Outcome::Error((
                            Status::BadRequest,
                            format!("Body read error: {e}"),
                        ));
                    }
                }
            }

            Outcome::Success((raw_body.freeze(), mac))
        }
    }

    /// Retrieve a header that's expected for a webhook request. The default
    /// implementation looks for the header and returns an error if it was not provided.
    /// It can also optionally strip a given prefix.
    fn get_header<'r>(
        &self,
        req: &'r Request<'_>,
        name: &str,
        prefix: Option<&str>,
    ) -> Outcome<&'r str, String> {
        match req.headers().get_one(name) {
            Some(value) => match prefix {
                None => Outcome::Success(value),
                Some(prefix) => match value.strip_prefix(prefix) {
                    Some(stripped) => Outcome::Success(stripped),
                    None => Outcome::Error((
                        Status::BadRequest,
                        format!("Header '{name}' doesn't have required prefix: got '{value}'"),
                    )),
                },
            },
            None => Outcome::Error((Status::BadRequest, format!("Missing header '{name}'"))),
        }
    }
}

/// Try reading the body size from the content length header
fn body_size(headers: &HeaderMap) -> Option<usize> {
    headers
        .get_one("Content-Length")
        .and_then(|len| len.parse().ok())
}
