use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GeoInfo {
    pub status: String,
    pub country: Option<String>,
    pub regionName: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub query: Option<String>, // The IP address
}

pub struct ReconResult {
    pub domain: String,
    pub geo: Option<GeoInfo>,
    pub whois: Option<String>,
}

pub async fn run_recon(target: &str) -> Result<ReconResult> {
    let mut result = ReconResult {
        domain: target.to_string(),
        geo: None,
        whois: None,
    };

    // 1. Fetch Geolocation
    result.geo = fetch_geo_info(target).await.ok();

    // 2. Fetch WHOIS (Basic)
    result.whois = fetch_whois_info(target).await.ok();

    Ok(result)
}

async fn fetch_geo_info(host: &str) -> Result<GeoInfo> {
    let client = reqwest::Client::new();
    let url = format!("http://ip-api.com/json/{}", host);
    let info = client.get(url).send().await?.json::<GeoInfo>().await?;
    
    if info.status == "fail" {
        return Err(anyhow!("Failed to fetch GEO info"));
    }
    
    Ok(info)
}

async fn fetch_whois_info(domain: &str) -> Result<String> {
    let mut stream = TcpStream::connect("whois.iana.org:43").await?;
    let query = format!("{}\r\n", domain);
    stream.write_all(query.as_bytes()).await?;
    
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    
    // IANA usually refers to the actual TLD WHOIS server
    if let Some(pos) = response.find("whois:") {
        let sub_server_line = response[pos..].split('\n').next().unwrap_or("");
        let sub_server = sub_server_line.replace("whois:", "").trim().to_string();
        
        if !sub_server.is_empty() {
            // Re-query the actual server
            let mut sub_stream = TcpStream::connect(format!("{}:43", sub_server)).await?;
            sub_stream.write_all(query.as_bytes()).await?;
            let mut sub_response = String::new();
            sub_stream.read_to_string(&mut sub_response).await?;
            return Ok(sub_response);
        }
    }
    
    Ok(response)
}
