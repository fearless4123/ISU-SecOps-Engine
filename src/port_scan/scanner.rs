use anyhow::{Result, anyhow};
use futures::{stream, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct OpenPort {
    pub port: u16,
    pub service: String,
}

pub async fn scan_ports(host: &str, ports: Vec<u16>) -> Result<Vec<OpenPort>> {
    let mut found = Vec::new();
    
    let mut stream = stream::iter(ports)
        .map(|port| {
            let host = host.to_string();
            async move {
                match check_port(&host, port).await {
                    true => Some(OpenPort { port, service: get_service_name(port) }),
                    false => None,
                }
            }
        })
        .buffer_unordered(50);

    while let Some(res) = stream.next().await {
        if let Some(item) = res {
            found.push(item);
        }
    }

    found.sort_by_key(|p| p.port);
    Ok(found)
}

async fn check_port(host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    match addr.parse::<SocketAddr>() {
        Ok(socket_addr) => {
            match timeout(Duration::from_millis(1500), TcpStream::connect(&socket_addr)).await {
                Ok(Ok(_)) => true,
                _ => false,
            }
        }
        Err(_) => {
            // If it's a domain name, we might need lookup_host, but for simplicity let's handle it
            let target = format!("{}:{}", host, port);
            match timeout(Duration::from_millis(1500), TcpStream::connect(target)).await {
                Ok(Ok(_)) => true,
                _ => false,
            }
        }
    }
}

fn get_service_name(port: u16) -> String {
    match port {
        21 => "FTP".into(),
        22 => "SSH".into(),
        23 => "Telnet".into(),
        25 => "SMTP".into(),
        53 => "DNS".into(),
        80 => "HTTP".into(),
        110 => "POP3".into(),
        143 => "IMAP".into(),
        443 => "HTTPS".into(),
        445 => "SMB".into(),
        3306 => "MySQL".into(),
        3389 => "RDP".into(),
        5432 => "PostgreSQL".into(),
        6379 => "Redis".into(),
        8080 => "HTTP-Proxy".into(),
        _ => "Unknown".into(),
    }
}

pub fn get_top_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 
        3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443
    ]
}
