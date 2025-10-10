# Rocket Webhook
[![CI](https://github.com/fa-sharp/rocket-webhook/actions/workflows/ci.yml/badge.svg)](https://github.com/fa-sharp/rocket-webhook/actions/workflows/ci.yml)
[![Crates.io Version](https://img.shields.io/crates/v/rocket-webhook)](https://crates.io/crates/rocket-webhook)


⚠️ **This crate is in alpha and may not work as expected yet.**

Streamlined webhook validation for Rocket applications, with built-in support for popular providers.

## Features

- Automatic signature validation for webhook requests
- Easy Rocket integration using `.manage()` and data guards
- Deserialize JSON payloads or work with the raw responses
- Built-in support for popular webhook providers and signatures
- Automatic timestamp validation for replay attack prevention

## Supported Webhooks
- GitHub, Stripe, Slack, Shopify, Discord, SendGrid, Svix

You can also easily add your own webhook by implementing one of the signature traits ([WebhookHmac](src/webhooks/interface/hmac.rs) or [WebhookPublicKey](src/webhooks/interface/public_key.rs)) and the [Webhook](src/webhooks.rs) trait. See the `src/webhooks/built_in` folder for examples.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
rocket-webhook = { version = "0.1.0-alpha", features = ["github", "slack"] } # Enable provider(s) you want to use
serde = { version = "1.0", features = ["derive"] }
```

```rust
use rocket::{post, routes, serde::{Deserialize, Serialize}};
use rocket_webhook::{RocketWebhook, WebhookPayload, webhooks::built_in::GitHubWebhook};

#[derive(Deserialize, Serialize)]
struct GitHubPayload {
    action: String,
}

#[post("/webhooks/github", data = "<payload>")]
async fn github_webhook(
    payload: WebhookPayload<'_, GitHubPayload, GitHubWebhook>,
) -> &'static str {
    println!("Received GitHub action: {}", payload.data.action);
    "OK"
}

#[rocket::launch]
fn rocket() -> _ {
    let github_webhook = RocketWebhook::builder()
        .webhook(GitHubWebhook::with_secret(b"your-webhook-secret"))
        .build();

    rocket::build()
        .manage(github_webhook)
        .mount("/", routes![github_webhook])
}
```
