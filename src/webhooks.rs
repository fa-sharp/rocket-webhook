//! Webhook traits and implementations

use hmac::{Mac, digest::KeyInit};
use rocket::{Request, data::Outcome, http::Status};

mod github;
mod slack;

/// Built-in webhook validators
pub mod built_in {
    pub use super::github::GitHubWebhook;
    pub use super::slack::SlackWebhook;
}

/// Trait that describes how to derive a webhook signature from the request
pub trait WebhookSignature {
    /// MAC algorithm used to calculate the signature
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

    /// Retrieve a header that's expected for a webhook request. The default
    /// implementation looks for the header and returns an error if it was not provided.
    /// It also optionally strips a given prefix.
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
