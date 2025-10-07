use bon::Builder;
use rocket::{Build, Rocket, async_trait, fairing};

mod guard;
pub mod webhooks;
pub use guard::{WebhookPayload, WebhookPayloadRaw};

use crate::webhooks::WebhookSignature;

/**
A webhook managed by Rocket. When registered with the Rocket server, you can use
the [WebhookPayload] and [WebhookPayloadRaw] data guards in your routes to automatically
validate and retrieve the webhook data.

# Example
*/
#[derive(Debug, Builder)]
pub struct RocketWebhook<W>
where
    W: WebhookSignature + Send + Sync + 'static,
{
    /// The webhook to validate
    webhook: W,
    /// The max body size of the webhook request in bytes (default: 10 KB)
    #[builder(default = 1024 * 10)]
    max_body_size: u32,
}

impl<W> RocketWebhook<W>
where
    W: WebhookSignature + Send + Sync + 'static,
{
    /// Register this webhook with the Rocket server
    pub fn register(self, rocket: Rocket<Build>) -> Rocket<Build> {
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
