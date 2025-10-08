//! Built-in webhooks

#[cfg(feature = "github")]
mod github;
#[cfg(feature = "shopify")]
mod shopify;
#[cfg(feature = "slack")]
mod slack;
#[cfg(feature = "stripe")]
mod stripe;

#[cfg(feature = "github")]
pub use github::GitHubWebhook;
#[cfg(feature = "shopify")]
pub use shopify::ShopifyWebhook;
#[cfg(feature = "slack")]
pub use slack::SlackWebhook;
#[cfg(feature = "stripe")]
pub use stripe::StripeWebhook;
