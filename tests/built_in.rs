use rocket::{
    get,
    http::{Header, Status},
    local::blocking::Client,
    routes,
    serde::json::{Json, json},
};
use rocket_webhook::{
    RocketWebhook, RocketWebhookRegister, WebhookPayload, WebhookPayloadRaw,
    webhooks::built_in::{GitHubWebhook, ShopifyWebhook, SlackWebhook, StripeWebhook},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct GithubPayload {
    action: String,
}

#[get("/github", data = "<payload>")]
async fn github_route(
    payload: WebhookPayload<'_, GithubPayload, GitHubWebhook>,
) -> Json<GithubPayload> {
    Json(payload.data)
}

#[test]
fn github() {
    let github_webhook = RocketWebhook::builder()
        .webhook(GitHubWebhook::new(
            "GitHub webhook",
            b"test-secret".to_vec(),
        ))
        .build();

    let rocket = rocket::build().mount("/", routes![github_route]);
    let rocket = RocketWebhookRegister::new(rocket)
        .add(github_webhook)
        .register();

    let client = Client::tracked(rocket).unwrap();
    let payload = json!({"action": "opened"});
    let signature = "sha256=6e939b5b3d3e8eba83ff81dde0030a8f2190d965e8bec7a17842863e979c4d7d";
    let response = client
        .get("/github")
        .header(Header::new("X-Hub-Signature-256", signature))
        .json(&payload)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.into_json(),
        Some(GithubPayload {
            action: "opened".into()
        })
    );

    let wrong_signature = "sha256=6e939b5b3d3e8eba83ff81dde0030a8f2190d965e8bec7a17842863e979c4d7e";
    let response = client
        .get("/github")
        .header(Header::new("X-Hub-Signature-256", wrong_signature))
        .json(&payload)
        .dispatch();

    assert_eq!(response.status(), Status::BadRequest);
}

#[get("/slack", data = "<payload>")]
async fn slack_route(payload: WebhookPayloadRaw<'_, SlackWebhook>) -> Vec<u8> {
    payload.data
}

#[test]
fn slack() {
    let slack_webhook = SlackWebhook::builder()
        .secret_key(b"8f742231b10e8888abcd99yyyzzz85a5".to_vec())
        .build();
    let webhook = RocketWebhook::builder().webhook(slack_webhook).build();
    let rocket = RocketWebhookRegister::new(rocket::build())
        .add(webhook)
        .register()
        .mount("/", routes![slack_route]);

    let client = Client::tracked(rocket).unwrap();
    let payload = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    let signature = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
    let timestamp = "1531420618";
    let response = client
        .get("/slack")
        .header(Header::new("x-slack-signature", signature))
        .header(Header::new("X-Slack-Request-Timestamp", timestamp))
        .body(payload)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some(payload.into()));

    let wrong_signature = "v0=a3114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
    let response = client
        .get("/slack")
        .header(Header::new("x-slack-signature", wrong_signature))
        .header(Header::new("X-Slack-Request-Timestamp", timestamp))
        .json(&payload)
        .dispatch();

    assert_eq!(response.status(), Status::BadRequest);

    // missing timestamp header
    let response = client
        .get("/slack")
        .header(Header::new("x-slack-signature", signature))
        .body(payload)
        .dispatch();

    assert_eq!(response.status(), Status::BadRequest);
}

#[get("/shopify", data = "<payload>")]
async fn shopify_route(payload: WebhookPayloadRaw<'_, ShopifyWebhook>) -> Vec<u8> {
    payload.data
}

#[test]
fn shopify() {
    let shopify_webhook = ShopifyWebhook::builder()
        .secret_key(b"test-secret".to_vec())
        .build();
    let webhook = RocketWebhook::builder().webhook(shopify_webhook).build();
    let rocket = rocket::build().mount("/", routes![shopify_route]);
    let rocket = RocketWebhookRegister::new(rocket).add(webhook).register();

    let client = Client::tracked(rocket).unwrap();
    let payload = "hello shopify";
    let signature = "l9ww1bSzk5iGBGdGlyeaPPokoYvxPHgk0w4reAA+jLc=";
    let response = client
        .get("/shopify")
        .header(Header::new("X-Shopify-Hmac-Sha256", signature))
        .body(payload)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some(payload.into()));
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct StripePayload {
    id: String,
    object: String,
}

#[get("/stripe", data = "<payload>")]
async fn stripe_route(
    payload: WebhookPayload<'_, StripePayload, StripeWebhook>,
) -> Json<StripePayload> {
    Json(payload.data)
}

#[test]
fn stripe() {
    let stripe_webhook = StripeWebhook::builder()
        .secret_key(b"test-secret".to_vec())
        .build();
    let webhook = RocketWebhook::builder().webhook(stripe_webhook).build();
    let rocket = rocket::build().mount("/", routes![stripe_route]);
    let rocket = RocketWebhookRegister::new(rocket).add(webhook).register();

    let client = Client::tracked(rocket).unwrap();
    let payload = json!({
        "id": "evt_12345",
        "object": "event"
    });
    let timestamp = "1492774577";
    let signature = "d08311034a9d558256d1ca3700a3a7f9b22f7ec03e52cca53c5632dcea29b8e7";
    let header = format!("t={timestamp},v1={signature}");
    let response = client
        .get("/stripe")
        .header(Header::new("Stripe-Signature", header))
        .json(&payload)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.into_json(),
        Some(StripePayload {
            id: "evt_12345".into(),
            object: "event".into()
        })
    );
}
