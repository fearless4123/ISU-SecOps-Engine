use anyhow::Result;
use reqwest::StatusCode;
use futures::{stream, StreamExt};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub path: String,
    pub status: StatusCode,
    pub url: String,
}

pub async fn fuzz_url(base_url: &str) -> Result<Vec<FuzzResult>> {
    let client = reqwest::Client::builder()
        .user_agent("SecOps-Fuzzer/0.1.0")
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::limited(2))
        .build()?;

    let wordlist = vec![
        "admin", "login", "config", ".env", ".git", ".htaccess", "wp-admin", 
        "api", "v1", "v2", "backup", "old", "test", "shell", "cmd", "ssh", 
        "private", "secrets", "uploads", "downloads", "images", "assets"
    ];

    let mut found = Vec::new();
    let base_url = base_url.trim_end_matches('/');

    let mut stream = stream::iter(wordlist)
        .map(|path| {
            let client = client.clone();
            let target = format!("{}/{}", base_url, path);
            async move {
                match client.get(&target).send().await {
                    Ok(res) => {
                        let status = res.status();
                        if status.is_success() || status == StatusCode::FORBIDDEN || status.is_redirection() {
                            Some(FuzzResult { path: path.to_string(), status, url: target })
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(10);

    while let Some(res) = stream.next().await {
        if let Some(item) = res {
            found.push(item);
        }
    }

    Ok(found)
}
