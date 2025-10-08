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
        match self {
            WebhookError::InvalidSignature(e) => write!(f, "Failed to validate signature: {e}"),
            WebhookError::MissingHeader(name) => write!(f, "Missing header '{name}'"),
            WebhookError::InvalidHeader(err) => write!(f, "Header has invalid format: {err}"),
            WebhookError::Deserialize(err) => {
                write!(f, "Failed to deserialize webhook payload: {err}")
            }
            WebhookError::ReadError(err) => write!(f, "Failed to read webhook body: {err}"),
            WebhookError::NotAttached => {
                write!(f, "Webhook of this type is not attached to Rocket")
            }
        }
    }
}

impl Error for WebhookError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            WebhookError::Deserialize(err) => Some(err),
            WebhookError::ReadError(err) => Some(err),
            _ => None,
        }
    }
}
