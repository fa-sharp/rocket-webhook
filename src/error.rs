use std::{error::Error, fmt::Display};

/// Possible errors when receiving a webhook
#[derive(Debug)]
pub enum WebhookError {
    /// Signature verification failed
    InvalidSignature(String),
    /// Missing required header
    MissingHeader(String),
    /// Invalid required header
    InvalidHeader(String),
    /// Error deserializing webhook payload
    Deserialize(rocket::serde::json::serde_json::Error),
    /// Error while reading the body of the webhook
    ReadError(rocket::tokio::io::Error),
    /// The webhook was not setup properly on the Rocket instance
    NotAttached,
}

impl Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_str = match self {
            WebhookError::InvalidSignature(e) => format!("Failed to validate signature: {e}"),
            WebhookError::MissingHeader(name) => format!("Missing header '{name}'"),
            WebhookError::InvalidHeader(err) => format!("Header has invalid format: {err}"),
            WebhookError::Deserialize(err) => {
                format!("Failed to deserialize webhook payload: {err}")
            }
            WebhookError::ReadError(err) => format!("Failed to read webhook body: {err}"),
            WebhookError::NotAttached => "Webhook of this type is not attached to Rocket".into(),
        };

        f.write_str(&error_str)
    }
}

impl Error for WebhookError {}
