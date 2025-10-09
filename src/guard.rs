use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use rocket::{
    Request, async_trait,
    data::{FromData, Outcome, ToByteUnit},
    http::{HeaderMap, Status},
    outcome::try_outcome,
    serde::{DeserializeOwned, json::serde_json},
};

use crate::{RocketWebhook, WebhookError, webhooks::Webhook};

/**
 Data guard to validate and deserialize the JSON body of webhook type `W` into the `T` type.
 The `W` webhook type must be attached to Rocket using [RocketWebhookRegister](crate::RocketWebhookRegister).
```
use rocket::{post, serde::{Serialize, Deserialize}};
use rocket_webhook::{WebhookPayload, webhooks::built_in::{GitHubWebhook}};

/// Payload to deserialize
#[derive(Debug, Serialize, Deserialize)]
struct GithubPayload {
    action: String,
}

// Use in a route handler as the data guard, passing in the payload and webhook type
#[post("/api/webhooks/github", data = "<payload>")]
async fn github_route(
    payload: WebhookPayload<'_, GithubPayload, GitHubWebhook>,
) -> &'static str {
    payload.data; // access the validated webhook payload
    payload.headers; // access the webhook headers

    "OK"
}
```
*/
pub struct WebhookPayload<'r, T, W, D = W> {
    /// The deserialized payload data
    pub data: T,
    /// The headers sent with the webhook request
    pub headers: &'r HeaderMap<'r>,
    _marker: PhantomData<W>,
    _discriminator: PhantomData<D>,
}

#[async_trait]
impl<'r, T, W, D> FromData<'r> for WebhookPayload<'r, T, W, D>
where
    T: DeserializeOwned,
    W: Webhook + Send + Sync + 'static,
    D: Send + Sync + 'static,
{
    type Error = WebhookError;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config: &RocketWebhook<W, D> = try_outcome!(get_webhook_from_state(req));
        let body = data.open(config.max_body_size.bytes());
        let time_bounds = get_timestamp_bounds(config.timestamp_tolerance);
        let validated_body =
            try_outcome!(config.webhook.validate_body(req, body, time_bounds).await);

        match serde_json::from_slice(&validated_body) {
            Ok(data) => Outcome::Success(Self {
                data,
                headers: req.headers(),
                _marker: PhantomData,
                _discriminator: PhantomData,
            }),
            Err(e) => Outcome::Error((Status::BadRequest, WebhookError::Deserialize(e))),
        }
    }
}

/**
Data guard to validate a webhook and get the raw body.
The `W` webhook must be attached to Rocket using [RocketWebhookRegister](crate::RocketWebhookRegister).
```
use rocket::{post, serde::{Serialize, Deserialize}};
use rocket_webhook::{WebhookPayloadRaw, webhooks::built_in::{GitHubWebhook}};


// Use in a route handler as the data guard, passing in the webhook type
#[post("/api/webhooks/github", data = "<payload>")]
async fn github_route(
    payload: WebhookPayloadRaw<'_, GitHubWebhook>,
) -> &'static str {
    payload.data; // access the raw webhook payload (Vec<u8>)
    payload.headers; // access the webhook headers

    "OK"
}
```
*/
pub struct WebhookPayloadRaw<'r, W, D = W> {
    /// The raw payload data
    pub data: Vec<u8>,
    /// The headers sent with the webhook request
    pub headers: &'r HeaderMap<'r>,
    _marker: PhantomData<W>,
    _discriminator: PhantomData<D>,
}

#[async_trait]
impl<'r, W, D> FromData<'r> for WebhookPayloadRaw<'r, W, D>
where
    W: Webhook + Send + Sync + 'static,
    D: Send + Sync + 'static,
{
    type Error = WebhookError;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config: &RocketWebhook<W, D> = try_outcome!(get_webhook_from_state(req));
        let body = data.open(config.max_body_size.bytes());
        let time_bounds = get_timestamp_bounds(config.timestamp_tolerance);
        let validated_body =
            try_outcome!(config.webhook.validate_body(req, body, time_bounds).await);

        Outcome::Success(Self {
            data: validated_body,
            headers: req.headers(),
            _marker: PhantomData,
            _discriminator: PhantomData,
        })
    }
}

fn get_webhook_from_state<'r, W, D>(
    req: &'r Request,
) -> Outcome<'r, &'r RocketWebhook<W, D>, WebhookError>
where
    W: Webhook + Send + Sync + 'static,
    D: Send + Sync + 'static,
{
    match req.rocket().state::<RocketWebhook<W, D>>() {
        Some(config) => Outcome::Success(config),
        None => {
            return Outcome::Error((Status::InternalServerError, WebhookError::NotAttached));
        }
    }
}

fn get_timestamp_bounds((past_secs, future_secs): (u32, u32)) -> (u32, u32) {
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32; // Safe to use u32 until 2106
    (unix_time - past_secs, unix_time + future_secs)
}
