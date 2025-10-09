#![allow(unused)]

//! Stripe webhook example. You can test this locally with the Stripe CLI:
//!
//! ```stripe listen -f http://localhost:8000/api/webhook/stripe```
//! ```STRIPE_SECRET=xxxxx cargo run --features stripe --example stripe```

use std::env;

use rocket::{launch, post, routes, serde::json::Value};
use rocket_webhook::{
    RocketWebhook, RocketWebhookRegister, WebhookPayload, webhooks::built_in::StripeWebhook,
};
use serde::Deserialize;

#[launch]
fn rocket() -> _ {
    let webhook_secret = env::var("STRIPE_SECRET").expect("Env var STRIPE_SECRET is not set");
    let webhook = RocketWebhook::builder()
        .webhook(StripeWebhook::builder().secret_key(webhook_secret).build())
        .max_body_size(10 * 1024)
        .build();

    let rocket = RocketWebhookRegister::new(rocket::build())
        .add(webhook)
        .register();

    rocket.mount("/api", routes![stripe_endpoint])
}

#[derive(Debug, Deserialize)]
pub struct StripeEvent {
    data: Value,
    #[serde(rename = "type")]
    type_: String,
}

#[post("/webhook/stripe", data = "<payload>")]
async fn stripe_endpoint(payload: WebhookPayload<'_, StripeEvent, StripeWebhook>) {
    rocket::info!("Received event type: {:?}", payload.data.type_);
}
