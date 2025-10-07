use std::marker::PhantomData;

use rocket::{
    Request, async_trait,
    data::{FromData, Outcome, ToByteUnit},
    http::{HeaderMap, Status},
    outcome::try_outcome,
    serde::{DeserializeOwned, json::serde_json},
};

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
{
    type Error = String;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config: &RocketWebhook<W> = try_outcome!(get_webhook_from_state(req));
        let body = data.open(config.max_body_size.bytes());
        let validated_body = try_outcome!(config.webhook.read_body_and_validate(req, body).await);

        match serde_json::from_slice(&validated_body) {
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
{
    type Error = String;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config: &RocketWebhook<W> = try_outcome!(get_webhook_from_state(req));
        let body = data.open(config.max_body_size.bytes());
        let validated_body = try_outcome!(config.webhook.read_body_and_validate(req, body).await);

        Outcome::Success(Self {
            data: validated_body,
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
