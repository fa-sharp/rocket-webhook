//! Webhook traits and implementations

use rocket::{Request, data::Outcome, http::Status, tokio::io::AsyncRead};

use crate::WebhookError;

pub mod built_in;
pub mod interface;

/// Base interface for all webhooks
pub trait Webhook {
    /// Name of the webhook
    fn name(&self) -> &'static str;

    /// Read body and validate webhook.
    fn read_body_and_validate<'r>(
        &self,
        req: &'r Request<'_>,
        body_reader: impl AsyncRead + Unpin + Send + Sync,
    ) -> impl Future<Output = Outcome<'_, Vec<u8>, WebhookError>> + Send + Sync;

    /// Retrieve a header that's expected for a webhook request. The default
    /// implementation looks for the header and returns a Bad Request error if it was not provided.
    /// It can also optionally strip a given prefix.
    fn get_header<'r>(
        &self,
        req: &'r Request<'_>,
        name: &str,
        prefix: Option<&str>,
    ) -> Outcome<'_, &'r str, WebhookError> {
        match req.headers().get_one(name) {
            Some(value) => match prefix {
                None => Outcome::Success(value),
                Some(prefix) => match value.strip_prefix(prefix) {
                    Some(stripped) => Outcome::Success(stripped),
                    None => Outcome::Error((
                        Status::BadRequest,
                        WebhookError::InvalidHeader(format!(
                            "'{name}' is missing prefix '{prefix}': {value}"
                        )),
                    )),
                },
            },
            None => Outcome::Error((Status::BadRequest, WebhookError::MissingHeader(name.into()))),
        }
    }
}
