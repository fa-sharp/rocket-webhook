# Rocket Webhook
[![CI](https://github.com/fa-sharp/rocket-flex-session/actions/workflows/lib.yml/badge.svg)](https://github.com/fa-sharp/rocket-flex-session/actions/workflows/lib.yml)
[![Crates.io Version](https://img.shields.io/crates/v/rocket_flex_session)](https://crates.io/crates/rocket_flex_session)

⚠️ **This crate is in alpha and may not work as expected yet.**

Streamlined webhook validation for Rocket applications, with built-in support for popular providers.

## Features

- Automatic signature validation for webhook requests
- Easy Rocket integration using `.manage()` and data guards
- Deserialize JSON payloads or work with the raw responses
- Built-in support for popular webhook providers
- Automatic timestamp validation for replay attack prevention
- Streaming HMAC validation for memory efficiency
- Multiple authentication methods (HMAC, Ed25519, ECDSA)

## Supported Webhooks
- GitHub, Stripe, Slack, Shopify, Discord, SendGrid, Svix

You can also easily add your own webhook by implementing the Webhook trait and one of the authentication traits (HMAC or Public Key).

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
