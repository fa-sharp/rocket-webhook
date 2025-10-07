//! Built-in webhooks

use super::*;

mod github;
mod shopify;
mod slack;
mod stripe;

pub use github::GitHubWebhook;
pub use shopify::ShopifyWebhook;
pub use slack::SlackWebhook;
pub use stripe::StripeWebhook;
