use std::marker::PhantomData;

use hmac::Mac;
use rocket::{
    Request, async_trait,
    data::{FromData, Outcome, ToByteUnit},
    futures::{Stream, StreamExt},
    http::{HeaderMap, Status},
    outcome::try_outcome,
    serde::{DeserializeOwned, json::serde_json},
};
use tokio_util::{
    bytes::{Bytes, BytesMut},
    io::ReaderStream,
};

use crate::{RocketWebhook, webhooks::WebhookSignature};

/// Data guard to validate and deserialize the `W` webhook JSON body into the `T` type.
/// The `W` webhook must be attached to Rocket using [RocketWebhook](crate::RocketWebhook).
pub struct WebhookPayload<'r, W, T> {
    /// The deserialized payload data
    pub data: T,
    /// The headers sent with the webhook request
    pub headers: &'r HeaderMap<'r>,
    _marker: PhantomData<W>,
}

#[async_trait]
impl<'r, W, T> FromData<'r> for WebhookPayload<'r, W, T>
where
    T: DeserializeOwned,
    W: WebhookSignature + Send + Sync + 'static,
{
    type Error = String;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config = req
            .rocket()
            .state::<RocketWebhook<W>>()
            .expect("the webhook was not found in Rocket's state");
        let headers = req.headers();

        // Get expected signature from request
        let expected_signature = try_outcome!(config.webhook.expected_signature(req));

        // Initialize HMAC with secret key from webhook
        let key = config.webhook.secret_key();
        let mut mac = W::MAC::new_from_slice(key).expect("HMAC should take any key length");

        // Update HMAC with prefix if there is one
        if let Some(prefix) = try_outcome!(config.webhook.body_prefix(req)) {
            mac.update(&prefix);
        }

        // Read body stream while calculating HMAC
        let body_stream = ReaderStream::new(data.open(config.max_body_size.bytes()));
        let raw_body = match read_body_and_hmac(body_stream, &mut mac, body_size(headers)).await {
            Ok(bytes) => bytes,
            Err(e) => return Outcome::Error((Status::BadRequest, format!("Body read error: {e}"))),
        };

        // Verify signature
        if let Err(e) = mac.verify_slice(&expected_signature) {
            return Outcome::Error((Status::BadRequest, format!("Invalid signature: {e}")));
        }

        // Deserialize JSON body
        match serde_json::from_slice(&raw_body) {
            Ok(data) => Outcome::Success(Self {
                data,
                headers,
                _marker: PhantomData,
            }),
            Err(e) => Outcome::Error((Status::BadRequest, format!("Deserialize error: {e}"))),
        }
    }
}

/// Data guard to validate a webhook and get the raw body.
/// The `W` webhook must be attached to Rocket using [RocketWebhook](crate::RocketWebhook).
pub struct WebhookPayloadRaw<'r, W> {
    /// The raw payload data
    pub data: Vec<u8>,
    /// The headers sent with the webhook request
    pub headers: &'r HeaderMap<'r>,
    _marker: PhantomData<W>,
}

#[async_trait]
impl<'r, W> FromData<'r> for WebhookPayloadRaw<'r, W>
where
    W: WebhookSignature + Send + Sync + 'static,
{
    type Error = String;

    async fn from_data(
        req: &'r Request<'_>,
        data: rocket::Data<'r>,
    ) -> Outcome<'r, Self, Self::Error> {
        let config = req
            .rocket()
            .state::<RocketWebhook<W>>()
            .expect("the webhook was not found in Rocket's state");
        let headers = req.headers();

        // Get expected signature from request
        let expected_signature = try_outcome!(config.webhook.expected_signature(req));

        // Initialize HMAC with secret key from webhook
        let key = config.webhook.secret_key();
        let mut mac = W::MAC::new_from_slice(key).expect("HMAC should take any key length");

        // Update HMAC with prefix if there is one
        if let Some(prefix) = try_outcome!(config.webhook.body_prefix(req)) {
            mac.update(&prefix);
        }

        // Read body stream while calculating HMAC
        let body_stream = ReaderStream::new(data.open(config.max_body_size.bytes()));
        let raw_body = match read_body_and_hmac(body_stream, &mut mac, body_size(headers)).await {
            Ok(bytes) => bytes,
            Err(e) => return Outcome::Error((Status::BadRequest, format!("Body read error: {e}"))),
        };

        // Verify signature
        if let Err(e) = mac.verify_slice(&expected_signature) {
            return Outcome::Error((Status::BadRequest, format!("Invalid signature: {e}")));
        }

        Outcome::Success(Self {
            data: raw_body.into(),
            headers,
            _marker: PhantomData,
        })
    }
}

async fn read_body_and_hmac<M>(
    mut stream: impl Stream<Item = Result<Bytes, rocket::tokio::io::Error>> + Unpin,
    mac: &mut M,
    init_size: Option<usize>,
) -> Result<Bytes, rocket::tokio::io::Error>
where
    M: Mac,
{
    let mut raw_body = BytesMut::with_capacity(init_size.unwrap_or(512));
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk_bytes) => {
                mac.update(&chunk_bytes);
                raw_body.extend(chunk_bytes);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(raw_body.freeze())
}

fn body_size(headers: &HeaderMap) -> Option<usize> {
    headers
        .get_one("Content-Length")
        .and_then(|len| len.parse().ok())
}
