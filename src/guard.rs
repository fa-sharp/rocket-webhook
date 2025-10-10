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
 The `W` webhook configuration must be in Rocket state using [RocketWebhook].
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
pub struct WebhookPayload<'r, T, W, M = W> {
    /// The deserialized payload data
    pub data: T,
    /// The headers sent with the webhook request
    pub headers: &'r HeaderMap<'r>,
    _webhook: PhantomData<W>,
    _marker: PhantomData<M>,
}

#[async_trait]
impl<'r, T, W, M> FromData<'r> for WebhookPayload<'r, T, W, M>
where
    T: DeserializeOwned,
    W: Webhook + Send + Sync + 'static,
    M: Send + Sync + 'static,
{
    type Error = WebhookError;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config: &RocketWebhook<W, M> = try_outcome!(get_webhook_from_state(req));
        let body = data.open(config.max_body_size.bytes());
        let time_bounds = get_timestamp_bounds(config.timestamp_tolerance);
        let validated_body =
            try_outcome!(config.webhook.validate_body(req, body, time_bounds).await);

        match serde_json::from_slice(&validated_body) {
            Ok(data) => Outcome::Success(Self {
                data,
                headers: req.headers(),
                _webhook: PhantomData,
                _marker: PhantomData,
            }),
            Err(e) => Outcome::Error((Status::BadRequest, WebhookError::Deserialize(e))),
        }
    }
}

/**
Data guard to validate a webhook and get the raw body.
The `W` webhook configuration must be in Rocket state using [RocketWebhook].
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
pub struct WebhookPayloadRaw<'r, W, M = W> {
    /// The raw payload data
    pub data: Vec<u8>,
    /// The headers sent with the webhook request
    pub headers: &'r HeaderMap<'r>,
    _webhook: PhantomData<W>,
    _marker: PhantomData<M>,
}

#[async_trait]
impl<'r, W, M> FromData<'r> for WebhookPayloadRaw<'r, W, M>
where
    W: Webhook + Send + Sync + 'static,
    M: Send + Sync + 'static,
{
    type Error = WebhookError;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config: &RocketWebhook<W, M> = try_outcome!(get_webhook_from_state(req));
        let body = data.open(config.max_body_size.bytes());
        let time_bounds = get_timestamp_bounds(config.timestamp_tolerance);
        let validated_body =
            try_outcome!(config.webhook.validate_body(req, body, time_bounds).await);

        Outcome::Success(Self {
            data: validated_body,
            headers: req.headers(),
            _webhook: PhantomData,
            _marker: PhantomData,
        })
    }
}

fn get_webhook_from_state<'r, W, M>(
    req: &'r Request,
) -> Outcome<'r, &'r RocketWebhook<W, M>, WebhookError>
where
    W: Webhook + Send + Sync + 'static,
    M: Send + Sync + 'static,
{
    match req.rocket().state::<RocketWebhook<W, M>>() {
        Some(config) => Outcome::Success(config),
        None => {
            return Outcome::Error((Status::InternalServerError, WebhookError::NotAttached));
        }
    }
}

/// Get the timestamp bounds based on the current unix epoch time in seconds
fn get_timestamp_bounds((past_secs, future_secs): (u32, u32)) -> (u32, u32) {
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32; // Safe to use u32 until 2106
    let lower_bound = {
        if past_secs > unix_time {
            0
        } else {
            unix_time - past_secs
        }
    };
    let upper_bound = unix_time + future_secs;

    (lower_bound, upper_bound)
}
