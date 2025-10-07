use std::marker::PhantomData;

use hmac::Mac;
use rocket::{
    Request, async_trait,
    data::{FromData, Outcome, ToByteUnit},
    http::{HeaderMap, Status},
    outcome::try_outcome,
    serde::{DeserializeOwned, json::serde_json},
};
use tokio_util::io::ReaderStream;

use crate::{RocketWebhook, webhooks::Webhook};

/// Data guard to validate and deserialize the `W` webhook JSON body into the `T` type.
/// The `W` webhook must be attached to Rocket using [RocketWebhook](crate::RocketWebhook).
pub struct WebhookPayload<'r, W, T> {
    /// The deserialized payload data
    pub data: T,
    /// The headers sent with the webhook request
    pub headers: &'r HeaderMap<'r>,
    _marker: PhantomData<W>,
}

#[async_trait]
impl<'r, W, T> FromData<'r> for WebhookPayload<'r, W, T>
where
    T: DeserializeOwned,
    W: Webhook + Send + Sync + 'static,
    W::MAC: Sync,
{
    type Error = String;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config = req
            .rocket()
            .state::<RocketWebhook<W>>()
            .expect("the webhook was not found in Rocket's state");

        // Get expected signature from request
        let expected_signature = try_outcome!(config.webhook.expected_signature(req));

        // Read body stream while calculating HMAC
        let body_stream = ReaderStream::new(data.open(config.max_body_size.bytes()));
        let (body, mac) = try_outcome!(config.webhook.read_body_and_hmac(req, body_stream).await);

        // Verify signature
        if let Err(e) = mac.verify_slice(&expected_signature) {
            return Outcome::Error((Status::BadRequest, format!("Invalid signature: {e}")));
        }

        // Deserialize JSON body
        match serde_json::from_slice(&body) {
            Ok(data) => Outcome::Success(Self {
                data,
                headers: req.headers(),
                _marker: PhantomData,
            }),
            Err(e) => Outcome::Error((Status::BadRequest, format!("Deserialize error: {e}"))),
        }
    }
}

/// Data guard to validate a webhook and get the raw body.
/// The `W` webhook must be attached to Rocket using [RocketWebhook](crate::RocketWebhook).
pub struct WebhookPayloadRaw<'r, W> {
    /// The raw payload data
    pub data: Vec<u8>,
    /// The headers sent with the webhook request
    pub headers: &'r HeaderMap<'r>,
    _marker: PhantomData<W>,
}

#[async_trait]
impl<'r, W> FromData<'r> for WebhookPayloadRaw<'r, W>
where
    W: Webhook + Send + Sync + 'static,
    W::MAC: Sync,
{
    type Error = String;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config: &RocketWebhook<W> = try_outcome!(get_webhook_from_state(req));

        // Get expected signature from request
        let expected_signature = try_outcome!(config.webhook.expected_signature(req));

        // Read body stream while calculating HMAC
        let body_stream = ReaderStream::new(data.open(config.max_body_size.bytes()));
        let (body, mac) = try_outcome!(config.webhook.read_body_and_hmac(req, body_stream).await);

        // Verify signature
        if let Err(e) = mac.verify_slice(&expected_signature) {
            return Outcome::Error((Status::BadRequest, format!("Invalid signature: {e}")));
        }

        Outcome::Success(Self {
            data: body.into(),
            headers: req.headers(),
            _marker: PhantomData,
        })
    }
}

fn get_webhook_from_state<'r, W>(req: &'r Request) -> Outcome<'r, &'r RocketWebhook<W>, String>
where
    W: Webhook + Send + Sync + 'static,
{
    match req.rocket().state::<RocketWebhook<W>>() {
        Some(config) => Outcome::Success(config),
        None => {
            return Outcome::Error((
                Status::InternalServerError,
                format!("the {} webhook is not attached to Rocket", W::name()),
            ));
        }
    }
}
