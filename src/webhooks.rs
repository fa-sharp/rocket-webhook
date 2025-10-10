//! Webhook traits and implementations

use rocket::{Request, data::Outcome, http::Status, tokio::io::AsyncRead};

use crate::WebhookError;

pub mod built_in;
pub mod interface;

mod utils;

/// Base interface for all webhooks
pub trait Webhook {
    /// Read body and validate webhook. If the webhook uses a timestamp, verify that it
    /// is within the expected bounds (bounds are in unix epoch seconds).
    fn validate_body(
        &self,
        req: &Request<'_>,
        body_reader: impl AsyncRead + Unpin + Send + Sync,
        time_bounds: (u32, u32),
    ) -> impl Future<Output = Outcome<'_, Vec<u8>, WebhookError>> + Send + Sync;

    /// Validate a timestamp against the given bounds. The default implementation assumes
    /// that it is in Unix epoch seconds, and returns a Bad Request error if it is invalid.
    fn validate_timestamp(
        &self,
        timestamp: &str,
        (min, max): (u32, u32),
    ) -> Outcome<'_, (), WebhookError> {
        let unix_timestamp = timestamp.parse::<u32>().ok();
        match unix_timestamp.map(|t| t >= min && t <= max) {
            Some(true) => Outcome::Success(()),
            Some(false) | None => Outcome::Error((
                Status::BadRequest,
                WebhookError::Timestamp(timestamp.into()),
            )),
        }
    }

    /// Retrieve a header that's expected for a webhook request. The default
    /// implementation looks for the header and returns a Bad Request error if it was not provided.
    /// It can also optionally strip a given prefix.
    fn get_header<'r>(
        &self,
        req: &'r Request<'_>,
        name: &str,
        prefix: Option<&str>,
    ) -> Outcome<'_, &'r str, WebhookError> {
        let Some(mut header) = req.headers().get_one(name) else {
            return Outcome::Error((Status::BadRequest, WebhookError::MissingHeader(name.into())));
        };
        if let Some(prefix) = prefix {
            let Some(stripped) = header.strip_prefix(prefix) else {
                return Outcome::Error((
                    Status::BadRequest,
                    WebhookError::InvalidHeader(format!(
                        "'{name}' is missing prefix '{prefix}': {header}"
                    )),
                ));
            };
            header = stripped;
        }
        Outcome::Success(header)
    }
}
