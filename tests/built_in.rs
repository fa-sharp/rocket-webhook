//! Tests for built-in webhooks

use rocket::{
    get,
    http::{Header, Status},
    local::blocking::Client,
    post, routes,
    serde::json::{Json, json},
};
use rocket_webhook::{
    RocketWebhook, WebhookPayload, WebhookPayloadRaw,
    webhooks::built_in::{
        DiscordWebhook, GitHubWebhook, SendGridWebhook, ShopifyWebhook, SlackWebhook,
        StandardWebhook, StripeWebhook,
    },
};
use serde::{Deserialize, Serialize};

const IGNORE_TIMESTAMP: u32 = u32::MAX;

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
        .webhook(GitHubWebhook::with_secret(b"test-secret"))
        .build();

    let rocket = rocket::build()
        .manage(github_webhook)
        .mount("/", routes![github_route]);

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

    assert_eq!(response.status(), Status::Unauthorized);
}

#[get("/slack", data = "<payload>")]
async fn slack_route(payload: WebhookPayloadRaw<'_, SlackWebhook>) -> Vec<u8> {
    payload.data
}

#[test]
fn slack() {
    let webhook = RocketWebhook::builder()
        .webhook(SlackWebhook::with_secret(
            b"8f742231b10e8888abcd99yyyzzz85a5",
        ))
        .timestamp_tolerance(IGNORE_TIMESTAMP, 0)
        .build();
    let rocket = rocket::build()
        .manage(webhook)
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

    assert_eq!(response.status(), Status::Unauthorized);

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
    let webhook = RocketWebhook::builder()
        .webhook(ShopifyWebhook::with_secret("test-secret"))
        .build();
    let rocket = rocket::build()
        .manage(webhook)
        .mount("/", routes![shopify_route]);

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
    let webhook = RocketWebhook::builder()
        .timestamp_tolerance(IGNORE_TIMESTAMP, 0)
        .webhook(StripeWebhook::with_secret("test-secret"))
        .build();
    let rocket = rocket::build()
        .manage(webhook)
        .mount("/", routes![stripe_route]);

    let client = Client::tracked(rocket).unwrap();
    let payload = json!({
        "id": "evt_12345",
        "object": "event"
    });
    let timestamp = "1492774577";
    let signature_1 = "d08311034a9d558256d1ca3700a3a7f9b22f7ec03e52cca53c5632dcea29b8d7";
    let signature_2 = "d08311034a9d558256d1ca3700a3a7f9b22f7ec03e52cca53c5632dcea29b8e7";
    let header = format!("t={timestamp},v1={signature_1},v1={signature_2}");
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

#[get("/discord", data = "<payload>")]
async fn discord_route(payload: WebhookPayloadRaw<'_, DiscordWebhook>) -> Vec<u8> {
    payload.data
}

#[test]
fn discord() {
    let public_key = "25B573092C76A64F7588FDDF76CD7C53774099C163A53A039D314C0EBD323C92";
    let webhook = RocketWebhook::builder()
        .timestamp_tolerance(IGNORE_TIMESTAMP, 0)
        .webhook(DiscordWebhook::with_public_key(public_key).expect("should be valid hex"))
        .build();
    let rocket = rocket::build()
        .manage(webhook)
        .mount("/", routes![discord_route]);

    let client = Client::tracked(rocket).unwrap();
    let payload = "hello discord";
    let timestamp = "1759897407";
    let signature = "85E8E58CD6B8385F6E8BDB00E614AF8315037B90F97F2E25D340B78A38EDD586B048BDD3DA7E89F0CC53FFF2C4D78A42DB1A070A0AE3234A590EF2A49C654106";
    let response = client
        .get("/discord")
        .header(Header::new("X-Signature-Ed25519", signature))
        .header(Header::new("X-Signature-Timestamp", timestamp))
        .body(payload)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some(payload.into()));
}

#[get("/sendgrid", data = "<payload>")]
fn sendgrid_route(payload: WebhookPayloadRaw<'_, SendGridWebhook>) -> Vec<u8> {
    payload.data
}

#[test]
fn sendgrid() {
    let public_key =
        "BP2InNqs4PwaKQTVLNqebVaY+KApaBF6y2bQhtFLadUpBMLOgkYEwLXML5TkGE80EHJyH3uNd2K2pdRaQbFqFE0=";
    let webhook = RocketWebhook::builder()
        .timestamp_tolerance(IGNORE_TIMESTAMP, 0)
        .webhook(SendGridWebhook::with_public_key(public_key).expect("is base64"))
        .build();
    let rocket = rocket::build()
        .manage(webhook)
        .mount("/", routes![sendgrid_route]);

    let client = Client::tracked(rocket).unwrap();
    let payload = "hello sendgrid";
    let timestamp = "1759897407";
    let signature = "MEQCIC+OAVQZEB8+qlkIM2BbPvSKbpRQZwJe/4emHZoNRKsIAiAtxFtWiNzpMhYkrFROz72r6xLsnTiNigvlg+SWIJrvCw==";
    let response = client
        .get("/sendgrid")
        .header(Header::new(
            "X-Twilio-Email-Event-Webhook-Signature",
            signature,
        ))
        .header(Header::new(
            "X-Twilio-Email-Event-Webhook-Timestamp",
            timestamp,
        ))
        .body(payload)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some(payload.into()));
}

#[post("/standard", data = "<payload>")]
async fn standard_route(
    payload: WebhookPayload<'_, StandardPayload, StandardWebhook>,
) -> Json<StandardPayload> {
    Json(payload.data)
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct StandardPayload {
    event_type: String,
    success: bool,
}

#[test]
fn standard() {
    let standard_webhook = RocketWebhook::builder()
        .timestamp_tolerance(IGNORE_TIMESTAMP, 0)
        .webhook(StandardWebhook::with_secret("whsec_x9J8mHVs08bY9qRsE3un7nW8").expect("is base64"))
        .build();
    let rocket = rocket::build()
        .manage(standard_webhook)
        .mount("/", routes![standard_route]);

    let client = Client::tracked(rocket).unwrap();
    let payload = json!({ "event_type":"ping", "success":true});
    let id = "msg_CGEWVFV0jBkqRIfP";
    let timestamp = "1759933695";
    let signature = "v1,vaXhsxOg6d11zKvCs7dg/PxN9dXETpdbalU1o3J66K4= v1,waXhsxOg6d11zKvCs7dg/PxN9dXETpdbalU1o3J66K4=";
    let response = client
        .post("/standard")
        .header(Header::new("Webhook-Id", id))
        .header(Header::new("Webhook-Timestamp", timestamp))
        .header(Header::new("Webhook-Signature", signature))
        .json(&payload)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.into_json(),
        Some(StandardPayload {
            event_type: "ping".into(),
            success: true
        })
    );
}
