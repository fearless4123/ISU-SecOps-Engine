use anyhow::{anyhow, Result};
use reqwest::header::HeaderMap;

#[derive(Debug, Clone)]
pub struct HeaderStatus {
    pub name: String,
    pub status: String, // "PRESENT", "MISSING", "INFO_LEAK"
    pub value: Option<String>,
    pub recommendation: Option<String>,
}

pub struct HeaderAnalysis {
    pub url: String,
    pub headers: Vec<HeaderStatus>,
}

pub async fn check_headers(url: &str) -> Result<HeaderAnalysis> {
    let client = reqwest::Client::builder()
        .user_agent("SecOps-Engine/0.1.0")
        .build()?;
    
    let res = client.get(url).send().await?;
    let headers = res.headers();
    
    let mut analysis = HeaderAnalysis {
        url: url.to_string(),
        headers: Vec::new(),
    };

    let security_headers = vec![
        ("Content-Security-Policy", "Defines which resources the browser is allowed to load."),
        ("Strict-Transport-Security", "Ensures all communication is over HTTPS."),
        ("X-Frame-Options", "Prevents clickjacking by controlling framing."),
        ("X-Content-Type-Options", "Prevents MIME sniffing."),
        ("Referrer-Policy", "Controls how much referrer information is sent."),
        ("Permissions-Policy", "Controls which browser features can be used."),
    ];

    for (name, rec) in security_headers {
        analysis.headers.push(evaluate_header(headers, name, rec, false));
    }

    let leak_headers = vec!["Server", "X-Powered-By", "X-AspNet-Version"];
    for name in leak_headers {
        analysis.headers.push(evaluate_header(headers, name, "Should be hidden to prevent version disclosure.", true));
    }

    Ok(analysis)
}

fn evaluate_header(headers: &HeaderMap, name: &str, rec: &str, is_leak: bool) -> HeaderStatus {
    match headers.get(name) {
        Some(val) => {
            let val_str = val.to_str().unwrap_or("[Invalid UTF-8]").to_string();
            HeaderStatus {
                name: name.to_string(),
                status: if is_leak { "INFO_LEAK" } else { "PRESENT" }.to_string(),
                value: Some(val_str),
                recommendation: if is_leak { Some(rec.to_string()) } else { None },
            }
        }
        None => {
            HeaderStatus {
                name: name.to_string(),
                status: if is_leak { "GOOD" } else { "MISSING" }.to_string(),
                value: None,
                recommendation: if is_leak { None } else { Some(rec.to_string()) },
            }
        }
    }
}
