#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/*!
⚠️ This crate is in development and may not work as expected yet.
# Overview

Streamlined webhook validation in Rocket applications.

- Automatically validate and deserialize webhook JSON payloads using the [WebhookPayload] data guard. You can also
get the raw body using [WebhookPayloadRaw].
- [Common webhooks](webhooks::built_in) included (GitHub, Slack, Stripe, Standard)
- Easily validate custom webhooks with one of the generic builders

# Usage

```
use rocket::{routes, post, serde::{Serialize, Deserialize}};
use rocket_webhook::{
    RocketWebhook, WebhookPayload,
    webhooks::built_in::{GitHubWebhook, SlackWebhook},
};

#[rocket::launch]
fn rocket() -> _ {
    // Build the webhook(s)
    let github_webhook = RocketWebhook::builder()
        .webhook(GitHubWebhook::with_secret(b"my-github-secret"))
        .build();
    let slack_webhook = RocketWebhook::builder()
        .webhook(SlackWebhook::with_secret(b"my-slack-secret"))
        .build();

    // Store the webhook(s) in Rocket state
    let rocket = rocket::build()
        .manage(github_webhook)
        .manage(slack_webhook)
        .mount("/", routes![github_route]);

    rocket
}

/// JSON payload to deserialize
#[derive(Debug, Serialize, Deserialize)]
struct GithubPayload {
    action: String,
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


```

# Custom webhooks
If you're using a webhook provider that is not built-in, there are two ways to integrate them:

## Use generic builder
This is the preferred (and simpler) approach - use one of [the generic webhook builders](webhooks::generic) to build a webhook
for your provider/service. For example, here is a custom webhook that expects a hex-encoded HMAC SHA256 signature
in the `Foo-Signature-256` header.

```
use rocket_webhook::{WebhookError, webhooks::generic::Hmac256Webhook};

let my_webhook = Hmac256Webhook::builder()
    .secret("my-secret")
    .expected_signatures(|req| {
        req.headers()
            .get_one("Foo-Signature-256")
            .and_then(|header| hex::decode(header).ok())
            .map(|header| vec![header])
    })
    .build();
```

## Implement webhook traits
If a generic builder is not available, you can directly implement one of the [signature traits](webhooks::interface)
along with the [Webhook](src/webhooks.rs) trait. See the implementations in [webhooks::built_in] for examples.

# Handling errors
By default, the webhook data guards will return Bad Request (400) for invalid requests (e.g. missing headers) and
Unauthorized (401) for signature validation failures. Rocket's error responses can be overridden using
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
            WebhookError::Signature(_) => (Status::Unauthorized, "Yikes!"),
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

# Multiple with same type
If you want to receive webhooks using multiple accounts/keys from the same built-in or generic webhook, you'll need to pass
in a marker struct when building the webhooks and using the data guards. This is needed to distinguish
between the two webhooks in Rocket's internal state.

```
use rocket::{get, routes};
use rocket_webhook::{
    RocketWebhook, WebhookPayloadRaw, webhooks::built_in::SlackWebhook,
};

// Create a marker struct for each account/key
struct SlackAccount1;
struct SlackAccount2;

fn two_slack_accounts() {
    // Use the `builder_with_marker` function
    let slack_1 = RocketWebhook::builder_with_marker()
        .webhook(SlackWebhook::with_secret("slack-1-secret"))
        .marker(SlackAccount1) // pass in the marker here
        .build();
    let slack_2 = RocketWebhook::builder_with_marker()
        .webhook(SlackWebhook::with_secret("slack-2-secret"))
        .marker(SlackAccount2) // pass in the marker here
        .build();

    let rocket = rocket::build()
        .manage(slack_1)
        .manage(slack_2)
        .mount("/", routes![slack1_route, slack2_route]);
}

// Use the marker struct as the last type parameter in the data guard:

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

mod error;
mod guard;
mod state;

pub mod webhooks;
pub use error::WebhookError;
pub use guard::{WebhookPayload, WebhookPayloadRaw};
pub use state::RocketWebhook;
