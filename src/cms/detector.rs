use anyhow::Result;
use reqwest::header::HeaderMap;

#[derive(Debug, Clone)]
pub struct CmsResult {
    pub name: String,
    pub version: Option<String>,
    pub confidence: String, // "High", "Medium", "Low"
}

pub async fn detect_cms(url: &str) -> Result<Option<CmsResult>> {
    let client = reqwest::Client::builder()
        .user_agent("SecOps-CMS-Detector/0.1.0")
        .build()?;
    
    let res = client.get(url).send().await?;
    let headers = res.headers().clone();
    let body = res.text().await?.to_lowercase();

    // 1. WordPress
    if body.contains("wp-content") || body.contains("wp-includes") {
        let version = extract_version(&body, "wordpress");
        return Ok(Some(CmsResult { name: "WordPress".to_string(), version, confidence: "High".to_string() }));
    }

    // 2. Joomla
    if body.contains("joomla") || body.contains("administrator/") {
        let version = extract_version(&body, "joomla");
        return Ok(Some(CmsResult { name: "Joomla".to_string(), version, confidence: "High".to_string() }));
    }

    // 3. Drupal
    if body.contains("drupal") || body.contains("sites/all") || headers.get("X-Generator").map(|v| v.to_str().unwrap_or("")).unwrap_or("").contains("Drupal") {
        let version = extract_version(&body, "drupal");
        return Ok(Some(CmsResult { name: "Drupal".to_string(), version, confidence: "High".to_string() }));
    }

    // 4. Ghost
    if body.contains("ghost-frontend") {
        return Ok(Some(CmsResult { name: "Ghost".to_string(), version: None, confidence: "Medium".to_string() }));
    }

    Ok(None)
}

fn extract_version(body: &str, cms_name: &str) -> Option<String> {
    // Basic search for <meta name="generator" content="[CMS] [Version]">
    let meta_tag = format!("name=\"generator\" content=\"{}", cms_name);
    if let Some(pos) = body.find(&meta_tag) {
        let start = pos + meta_tag.len();
        let end = body[start..].find('"').unwrap_or(0);
        return Some(body[start..start+end].trim().to_string());
    }
    None
}
