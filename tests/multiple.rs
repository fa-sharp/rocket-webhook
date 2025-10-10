//! Test for multiple webhooks of the same type

use rocket::{get, http::Header, local::blocking::Client, routes};
use rocket_webhook::{RocketWebhook, WebhookPayloadRaw, webhooks::built_in::SlackWebhook};

const IGNORE_TIMESTAMP: (u32, u32) = (u32::MAX, 0);

struct SlackAccount1;
struct SlackAccount2;

#[test]
fn two_slack_accounts() {
    let webhook_1 = RocketWebhook::builder_with_marker()
        .webhook(SlackWebhook::with_secret("slack-1-secret"))
        .marker(SlackAccount1)
        .timestamp_tolerance(IGNORE_TIMESTAMP)
        .build();
    let webhook_2 = RocketWebhook::builder_with_marker()
        .webhook(SlackWebhook::with_secret("slack-2-secret"))
        .marker(SlackAccount2)
        .timestamp_tolerance(IGNORE_TIMESTAMP)
        .build();

    let rocket = rocket::build()
        .manage(webhook_1)
        .manage(webhook_2)
        .mount("/", routes![slack1_route, slack2_route]);

    let client = Client::tracked(rocket).unwrap();
    let timestamp = "1531420618";
    let slack_1_message = "hello slack one";
    let response = client
        .get("/slack-1")
        .header(Header::new(
            "x-slack-signature",
            "v0=ca5491f4d63a3dd79b5330c3e77cc8e228f1051b5f0b87475c8ed678e769bb97",
        ))
        .header(Header::new("X-Slack-Request-Timestamp", timestamp))
        .body(slack_1_message)
        .dispatch();
    assert_eq!(slack_1_message, response.into_string().unwrap());

    let slack_2_message = "hello slack two";
    let response = client
        .get("/slack-2")
        .header(Header::new(
            "x-slack-signature",
            "v0=620cd89448b19d54de30064b9230550eeef3c44daf119c5cc77adbb6f8248195",
        ))
        .header(Header::new("X-Slack-Request-Timestamp", timestamp))
        .body(slack_2_message)
        .dispatch();
    assert_eq!(slack_2_message, response.into_string().unwrap());
}

#[get("/slack-1", data = "<payload>")]
async fn slack1_route(payload: WebhookPayloadRaw<'_, SlackWebhook, SlackAccount1>) -> Vec<u8> {
    payload.data
}

#[get("/slack-2", data = "<payload>")]
async fn slack2_route(payload: WebhookPayloadRaw<'_, SlackWebhook, SlackAccount2>) -> Vec<u8> {
    payload.data
}
