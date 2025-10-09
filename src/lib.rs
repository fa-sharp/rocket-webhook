#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/*!
# Overview

Utilities for working with webhooks in Rocket applications.

- Automatically validate and deserialize webhook JSON payloads using the [WebhookPayload] data guard. You can also
get the raw body using [WebhookPayloadRaw].
- [Common webhooks](webhooks::built_in) included (GitHub, Slack, Stripe)
- Custom webhook validation possible by implementing the [Webhook] trait.

# Usage

```rust
use rocket::{routes, post, serde::{Serialize, Deserialize}};
use rocket_webhook::{
    RocketWebhook, RocketWebhookRegister, WebhookPayload,
    webhooks::built_in::{GitHubWebhook, SlackWebhook},
};


#[rocket::launch]
fn rocket() -> _ {
    let github_webhook = RocketWebhook::builder()
        .webhook(GitHubWebhook::builder().secret_key(b"my-github-secret").build())
        .build();
    let slack_webhook = RocketWebhook::builder()
        .webhook(SlackWebhook::builder().secret_key(b"my-slack-secret").build())
        .build();

    let rocket = rocket::build().mount("/", routes![github_route]);
    let rocket = RocketWebhookRegister::new(rocket)
        .add(github_webhook)
        .add(slack_webhook)
        .register();

    rocket
}

// use the `WebhookPayload` data guard in a route handler
#[post("/api/webhooks/github", data = "<payload>")]
async fn github_route(
    payload: WebhookPayload<'_, GithubPayload, GitHubWebhook>,
) -> &'static str {
    payload.data; // access the validated webhook payload
    payload.headers; // access the webhook headers

    "OK"
}

/// Payload to deserialize
#[derive(Debug, Serialize, Deserialize)]
struct GithubPayload {
    action: String,
}

```


# Handling errors
By default, the webhook data guards will return Bad Request (400) for invalid requests (e.g. missing headers) and
Unauthorized (401) for signature validation failures. Rocket's error handlers can be overridden using
[catchers](https://rocket.rs/guide/v0.5/requests/#error-catchers) scoped to a specific path.

If you need more control over how to
process and respond to webhook errors, you can wrap the data guards with a Result, using
the [WebhookError] as the Error type. You can then match on the result and handle the response as desired.

```
use rocket::{routes, post, serde::{Serialize, Deserialize}};
use rocket::http::Status;
use rocket_webhook::{
    WebhookError, WebhookPayload,
    webhooks::built_in::{GitHubWebhook},
};

#[post("/api/webhooks/github", data = "<payload_result>")]
async fn github_route(
    payload_result: Result<WebhookPayload<'_, GithubPayload, GitHubWebhook>, WebhookError>,
) -> (Status, &'static str) {
    match payload_result {
        Ok(payload) => (Status::Ok, "Yay!"),
        Err(err) => match err {
            WebhookError::InvalidSignature(_) => (Status::Unauthorized, "Yikes!"),
            _ => (Status::UnprocessableEntity, "Oof!")
        }
    }
}

/// Payload to deserialize
#[derive(Debug, Serialize, Deserialize)]
struct GithubPayload {
    action: String,
}
```

# Multiple with same provider
If you want to receive webhooks using multiple accounts/keys from the same provider, you'll need to pass
in a marker struct when building the webhooks and using the data guards. This is needed to distinguish
between the two webhooks in Rocket's internal state.

```
use rocket::{get, routes};
use rocket_webhook::{
    RocketWebhook, RocketWebhookRegister, WebhookPayloadRaw, webhooks::built_in::SlackWebhook,
};

// Create a marker struct for each account/key
struct SlackAccount1;
struct SlackAccount2;

#[test]
fn two_slack_accounts() {
    let slack_1 = SlackWebhook::builder().secret_key("slack-1-secret").build();
    let webhook_1 = RocketWebhook::builder()
        .webhook(slack_1)
        .marker(SlackAccount1) // pass in the marker here
        .build();
    let slack_2 = SlackWebhook::builder().secret_key("slack-2-secret").build();
    let webhook_2 = RocketWebhook::builder()
        .webhook(slack_2)
        .marker(SlackAccount2) // pass in the marker here
        .build();

    let rocket = RocketWebhookRegister::new(rocket::build())
        .add_with_marker(webhook_1)
        .add_with_marker(webhook_2)
        .register()
        .mount("/", routes![slack1_route, slack2_route]);
}

// Use the marker as the last type parameter in the data guard:

#[get("/slack-1", data = "<payload>")]
async fn slack1_route(payload: WebhookPayloadRaw<'_, SlackWebhook, SlackAccount1>) -> Vec<u8> {
    payload.data
}

#[get("/slack-2", data = "<payload>")]
async fn slack2_route(payload: WebhookPayloadRaw<'_, SlackWebhook, SlackAccount2>) -> Vec<u8> {
    payload.data
}
```
*/

use std::marker::PhantomData;

use bon::Builder;
use rocket::{Build, Rocket, async_trait, fairing};

mod error;
mod guard;
pub mod webhooks;
pub use error::WebhookError;
pub use guard::{WebhookPayload, WebhookPayloadRaw};

use crate::webhooks::Webhook;

/**
Webhook configuration stored in Rocket state.

# Example

```
use rocket::{Rocket, Build};
use rocket_webhook::{
    RocketWebhook, RocketWebhookRegister,
    webhooks::built_in::{GitHubWebhook},
};

fn setup_webhooks(rocket: Rocket<Build>) -> Rocket<Build> {
    let github_webhook = RocketWebhook::builder()
        .webhook(GitHubWebhook::builder().secret_key(b"my-github-secret").build())
        .max_body_size(1024 * 10)
        .build();
    let rocket = RocketWebhookRegister::new(rocket).add(github_webhook).register();

    rocket
}
```
*/
#[derive(Builder)]
pub struct RocketWebhook<W, D = W> {
    /// The webhook to validate
    webhook: W,
    /// The max body size of the webhook request in bytes (default: 64 KB)
    #[builder(default = 1024 * 64)]
    max_body_size: u32,
    /// For webhooks that use a timestamp, how many seconds in the past and future is allowed to be valid
    /// (default: 5 minutes in past, 15 seconds in future)
    #[builder(default = (5 * 60, 15))]
    timestamp_tolerance: (u32, u32),
    /// A marker to distinguish between webhooks of the same type
    #[builder(default, with = |d: D| PhantomData)]
    _marker: PhantomData<D>,
}

/**
Utility to register webhooks with the Rocket instance

# Example
```
use rocket::{Rocket, Build};
use rocket_webhook::{
    RocketWebhook, RocketWebhookRegister,
    webhooks::built_in::{GitHubWebhook},
};

let rocket = rocket::build();
let github_webhook = RocketWebhook::builder()
    .webhook(GitHubWebhook::builder().secret_key(b"my-github-secret").build())
    .build();
let rocket = RocketWebhookRegister::new(rocket).add(github_webhook).register();
```
*/
pub struct RocketWebhookRegister {
    rocket: Rocket<Build>,
}

impl RocketWebhookRegister {
    pub fn new(rocket: Rocket<Build>) -> Self {
        Self { rocket }
    }

    /// Add a webhook
    pub fn add<W>(mut self, webhook: RocketWebhook<W>) -> Self
    where
        W: Webhook + Send + Sync + 'static,
    {
        self.rocket = self
            .rocket
            .attach(RocketWebhookFairing {
                name: webhook.webhook.name(),
            })
            .manage(webhook);
        self
    }

    /// Add a webhook with a type marker (for using multiple webhooks of the same type)
    pub fn add_with_marker<W, D>(mut self, webhook: RocketWebhook<W, D>) -> Self
    where
        W: Webhook + Send + Sync + 'static,
        D: Send + Sync + 'static,
    {
        self.rocket = self
            .rocket
            .attach(RocketWebhookFairing {
                name: webhook.webhook.name(),
            })
            .manage(webhook);
        self
    }

    /// Finalize and return the Rocket instance
    pub fn register(self) -> Rocket<Build> {
        self.rocket
    }
}

#[derive(Debug)]
struct RocketWebhookFairing {
    name: &'static str,
}

#[async_trait]
impl fairing::Fairing for RocketWebhookFairing {
    fn info(&self) -> fairing::Info {
        fairing::Info {
            name: self.name,
            kind: fairing::Kind::Ignite,
        }
    }
}
