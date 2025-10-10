#![allow(unused)]

//! GitHub webhook example - a bot that receives GitHub star events and posts to a Discord channel.
//!
//! You can use the smee client to test this, as outlined in the
//! [GitHub docs](https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/testing-webhooks)
//!
//! ```smee --url <SMEE_URL> --path /api/webhook/github --port 8000```
//! ```GITHUB_SECRET=xxxxx DISCORD_URL=xxxxx cargo run --features github --example github```

use std::{collections::HashMap, env};

use reqwest::Client;
use rocket::{launch, post, routes};
use rocket_webhook::{RocketWebhook, WebhookPayload, webhooks::built_in::GitHubWebhook};
use serde::Deserialize;

#[launch]
fn rocket() -> _ {
    let key = env::var("GITHUB_SECRET").expect("Env var GITHUB_WEBHOOK_SECRET is not set");
    let webhook = RocketWebhook::builder()
        .webhook(GitHubWebhook::with_secret(key))
        .max_body_size(10 * 1024)
        .build();

    rocket::build()
        .manage(webhook)
        .mount("/api", routes![github_endpoint])
}

#[post("/webhook/github", data = "<payload>")]
async fn github_endpoint(payload: WebhookPayload<'_, StarEvent, GitHubWebhook>) {
    let StarEvent {
        action,
        sender,
        repository,
        starred_at,
    } = payload.data;

    let mut discord_post = String::new();
    discord_post.push_str(match action {
        StarAction::Created => "## 🌟 Repo starred!",
        StarAction::Deleted => "## 🥺 Repo unstarred!",
    });
    discord_post.push_str(&format!("\n**Repository**: {}", repository.full_name));
    if let Some(user) = sender {
        discord_post.push_str(&format!("\n**User**: [{}]({})", user.login, user.html_url));
    }
    if let Some(starred_at) = starred_at {
        discord_post.push_str(&format!("\n**Starred at**: {starred_at}"));
    }

    match env::var("DISCORD_URL") {
        Err(_) => rocket::info!("DISCORD_URL was not set. Discord post: {discord_post}"),
        Ok(url) => {
            let data = HashMap::from([("content", discord_post)]);
            let discord_result = Client::new().post(url).form(&data).send().await;
            match discord_result {
                Err(e) => rocket::error!("Error sending request: {e}"),
                Ok(res) => {
                    if !res.status().is_success() {
                        rocket::warn!("Error from Discord: {:?}", res.text().await)
                    }
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct StarEvent {
    action: StarAction,
    starred_at: Option<String>,
    sender: Option<GitHubUser>,
    repository: GitHubRepository,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StarAction {
    Created,
    Deleted,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    html_url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRepository {
    id: u64,
    name: String,
    full_name: String,
}
