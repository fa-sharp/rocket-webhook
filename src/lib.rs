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
        .webhook(GitHubWebhook::new("GitHub webhook", b"my-github-secret".to_vec()))
        .build();
    let slack_webhook = RocketWebhook::builder()
        .webhook(SlackWebhook::new("Slack webhook", b"my-slack-secret".to_vec()))
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


*/

use std::marker::PhantomData;

use bon::Builder;
use rocket::{Build, Rocket, async_trait, fairing};

mod guard;
pub mod webhooks;
pub use guard::{WebhookPayload, WebhookPayloadRaw};
pub use hmac;

use crate::webhooks::Webhook;

/**
Webhook configuration stored in Rocket state.

# Example

```
use rocket::{Rocket, Build};
use rocket_webhook::{
    RocketWebhook, RocketWebhookRegister,
    webhooks::built_in::{GitHubWebhook, SlackWebhook},
};

fn setup_webhooks(rocket: Rocket<Build>) -> Rocket<Build> {
    let github_webhook = RocketWebhook::builder()
        .webhook(GitHubWebhook::new("GitHub webhook", b"my-github-secret".to_vec()))
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
    .webhook(GitHubWebhook::new("GitHub webhook", b"my-github-secret".to_vec()))
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
            kind: fairing::Kind::Ignite | fairing::Kind::Singleton,
        }
    }
}
