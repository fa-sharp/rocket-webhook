//! Tests for building generic webhooks

use rocket::{
    http::{Header, Status},
    local::blocking::Client,
    post, routes,
};
use rocket_webhook::{
    RocketWebhook, WebhookError, WebhookPayloadRaw, webhooks::generic::Hmac256Webhook,
};

#[post("/hmac", data = "<payload>")]
async fn hmac_route(payload: WebhookPayloadRaw<'_, Hmac256Webhook>) -> Vec<u8> {
    payload.data
}

#[test]
fn hmac() {
    let custom_hmac = Hmac256Webhook::builder()
        .secret("my-custom-hmac-secret")
        .expected_signatures(|req| {
            req.headers()
                .get_one("Signature-SHA256")
                .and_then(|header| hex::decode(header).ok())
                .map(|header| vec![header])
        })
        .body_suffix(|req, (min_t, max_t)| {
            req.headers()
                .get_one("Timestamp")
                .filter(|time| time.parse::<u32>().is_ok_and(|t| t > min_t && t < max_t))
                .map(|time| time.as_bytes().to_vec())
                .ok_or_else(|| WebhookError::Timestamp("Missing/invalid timestamp".into()))
        })
        .build();
    let webhook = RocketWebhook::builder()
        .webhook(custom_hmac)
        .timestamp_tolerance(u32::MAX, 0)
        .build();

    let rocket = rocket::build()
        .mount("/", routes![hmac_route])
        .manage(webhook);
    let client = Client::tracked(rocket).unwrap();

    let body = "Hello custom HMAC";
    let timestamp = "1760414077";
    let signature = "83fbbe9119392db8d86a318ff31bf799d54d8abf91562e06109fedfd57a6df4e";

    let response = client
        .post("/hmac")
        .header(Header::new("Signature-Sha256", signature))
        .header(Header::new("Timestamp", timestamp))
        .body(body)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().as_deref(), Some(body));

    // Invalid signature
    let response = client
        .post("/hmac")
        .header(Header::new(
            "Signature-Sha256",
            "84fbbe9119392db8d86a318ff31bf799d54d8abf91562e06109fedfd57a6df4e",
        ))
        .header(Header::new("Timestamp", timestamp))
        .body(body)
        .dispatch();
    assert_eq!(response.status(), Status::Unauthorized);

    // Missing timestamp
    let response = client
        .post("/hmac")
        .header(Header::new("Signature-Sha256", signature))
        .body(body)
        .dispatch();
    assert_eq!(response.status(), Status::BadRequest);
}
