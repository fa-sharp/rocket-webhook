use std::marker::PhantomData;

use bon::bon;

use crate::webhooks::Webhook;

/**
Webhook configuration stored in Rocket state.

# Example

```
use rocket::{Rocket, Build};
use rocket_webhook::{
    RocketWebhook,
    webhooks::built_in::{GitHubWebhook},
};

fn setup_webhooks(rocket: Rocket<Build>) -> Rocket<Build> {
    let github_webhook = RocketWebhook::builder()
        .webhook(GitHubWebhook::with_secret(b"my-github-secret"))
        .max_body_size(1024 * 10)
        .build();

    rocket.manage(github_webhook)
}
```
*/
pub struct RocketWebhook<W, M = W>
where
    W: Webhook,
{
    pub(crate) webhook: W,
    pub(crate) max_body_size: u32,
    pub(crate) timestamp_tolerance: (u32, u32),
    marker: PhantomData<M>,
}

#[bon]
impl<W> RocketWebhook<W, W>
where
    W: Webhook,
{
    /// Build a webhook configuration
    #[builder]
    pub fn new(
        /// The webhook to validate
        webhook: W,
        /// The maximum allowed body size of the webhook request in bytes (default: 64 KB)
        #[builder(default = 64 * 1024)]
        max_body_size: u32,
        /// For webhooks that use a timestamp, how many seconds in the past and future is allowed to be valid
        /// (default: 5 minutes in past, 15 seconds in future)
        #[builder(default = (5 * 60, 15), with = |past_secs: u32, future_secs: u32| (past_secs, future_secs))]
        timestamp_tolerance: (u32, u32),
    ) -> RocketWebhook<W, W> {
        RocketWebhook {
            webhook,
            max_body_size,
            timestamp_tolerance,
            marker: PhantomData::<W>,
        }
    }
}

#[bon]
impl<W, M> RocketWebhook<W, M>
where
    W: Webhook,
{
    /**
    Build a webhook configuration with a given marker type, to distingiush between multiple
    webhooks of the same type (e.g. multiple GitHub webhooks with different secret keys).

    # Example

    ```
    use rocket_webhook::{
        RocketWebhook,
        webhooks::built_in::{GitHubWebhook},
    };

    struct GithubPR;
    struct GithubIssue;

    let webhook_1 = RocketWebhook::builder_with_marker()
        .webhook(GitHubWebhook::with_secret("secret-1"))
        .marker(GithubPR) // pass in marker here
        .build();
    let webhook_2 = RocketWebhook::builder_with_marker()
        .webhook(GitHubWebhook::with_secret("secret-2"))
        .marker(GithubIssue) // pass in marker here
        .build();
    ```
    */
    #[builder(start_fn(name = builder_with_marker, vis = "pub"), finish_fn = build, builder_type(vis = "pub"))]
    fn with_marker(
        /// The webhook to validate
        webhook: W,
        /// A marker struct to distinguish this webhook from other webhooks of the same type
        #[builder(with = |marker: M| PhantomData)]
        marker: PhantomData<M>,
        /// The maximum allowed body size of the webhook request in bytes (default: 64 KB)
        #[builder(default = 64 * 1024)]
        max_body_size: u32,
        /// For webhooks that use a timestamp, how many seconds in the past and future is allowed to be valid
        /// (default: 5 minutes in past, 15 seconds in future)
        #[builder(default = (5 * 60, 15), with = |past_secs: u32, future_secs: u32| (past_secs, future_secs))]
        timestamp_tolerance: (u32, u32),
    ) -> RocketWebhook<W, M> {
        RocketWebhook {
            webhook,
            marker,
            max_body_size,
            timestamp_tolerance,
        }
    }
}
