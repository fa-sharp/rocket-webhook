/*!
# Overview

Utilities for working with webhooks in Rocket applications.

- Automatically validate and deserialize webhook JSON payloads using the [WebhookPayload] data guard. You can also
get the raw body using [WebhookPayloadRaw].
- Common webhook validators included (GitHub, Slack)
- Custom webhook validation possible via implementing the [Webhook] trait.

# Usage

```rust
use rocket::{routes, post, serde::{Serialize, Deserialize}};
use rocket_webhook::{
    RocketWebhook, WebhookPayload,
    webhooks::built_in::{GitHubWebhook},
};


#[rocket::launch]
fn rocket() -> _ {
    let github_webhook = GitHubWebhook::builder()
        .secret_key(b"my-github-secret".to_vec())
        .build();
    let rocket_webhook = RocketWebhook::builder().webhook(github_webhook).build();

    let rocket = rocket::build().mount("/", routes![github_route]);

    rocket_webhook.register_with(rocket)
}

// use the `WebhookPayload` data guard in a route handler
#[post("/api/webhooks/github", data = "<payload>")]
async fn github_route(
    payload: WebhookPayload<'_, GitHubWebhook, GithubPayload>,
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

use bon::Builder;
use rocket::{Build, Rocket, async_trait, fairing};

mod guard;
pub mod webhooks;
pub use guard::{WebhookPayload, WebhookPayloadRaw};

use crate::webhooks::Webhook;

/**
A webhook managed by Rocket. When registered with the Rocket server, you can use
the [WebhookPayload] and [WebhookPayloadRaw] data guards in your routes to automatically
validate and retrieve the webhook data.

# Example

```
use rocket::{Rocket, Build};
use rocket_webhook::{
    RocketWebhook,
    webhooks::built_in::{GitHubWebhook, SlackWebhook},
};

fn setup_webhooks(rocket: Rocket<Build>) -> Rocket<Build> {
    let github_webhook = GitHubWebhook::builder()
        .secret_key(b"my-github-secret".to_vec())
        .build();
    let rocket_webhook = RocketWebhook::builder().webhook(github_webhook).build();

    rocket_webhook.register_with(rocket)
}
```
*/
#[derive(Debug, Builder)]
pub struct RocketWebhook<W>
where
    W: Webhook + Send + Sync + 'static,
{
    /// The webhook to validate
    webhook: W,
    /// The max body size of the webhook request in bytes (default: 10 KB)
    #[builder(default = 1024 * 10)]
    max_body_size: u32,
}

impl<W> RocketWebhook<W>
where
    W: Webhook + Send + Sync + 'static,
{
    /// Register this webhook with the Rocket server
    pub fn register_with(self, rocket: Rocket<Build>) -> Rocket<Build> {
        rocket
            .attach(RocketWebhookFairing { name: W::name() })
            .manage(self)
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
