//! Built-in webhooks

#[cfg(feature = "discord")]
mod discord;
#[cfg(feature = "discord")]
pub use discord::DiscordWebhook;

#[cfg(feature = "github")]
mod github;
#[cfg(feature = "github")]
pub use github::GitHubWebhook;

#[cfg(feature = "sendgrid")]
mod sendgrid;
#[cfg(feature = "sendgrid")]
pub use sendgrid::SendGridWebhook;

#[cfg(feature = "shopify")]
mod shopify;
#[cfg(feature = "shopify")]
pub use shopify::ShopifyWebhook;

#[cfg(feature = "slack")]
mod slack;
#[cfg(feature = "slack")]
pub use slack::SlackWebhook;

#[cfg(feature = "stripe")]
mod stripe;
#[cfg(feature = "stripe")]
pub use stripe::StripeWebhook;

#[cfg(feature = "svix")]
mod svix;
#[cfg(feature = "svix")]
pub use svix::SvixWebhook;
