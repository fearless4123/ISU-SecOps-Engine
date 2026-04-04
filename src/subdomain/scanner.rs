use anyhow::Result;
use futures::{stream, StreamExt};
use std::sync::Arc;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

pub struct SubdomainResult {
    pub subdomain: String,
    pub ip_addresses: Vec<String>,
}

pub async fn scan_subdomains(domain: &str) -> Result<Vec<SubdomainResult>> {
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));

    let wordlist = vec![
        "www", "mail", "api", "dev", "staging", "test", "webmail", "blog", "shop", 
        "portal", "admin", "vpn", "m", "remote", "support", "secure", "static"
    ];

    let mut found = Vec::new();
    
    let mut stream = stream::iter(wordlist)
        .map(|sub| {
            let resolver = Arc::clone(&resolver);
            let target = format!("{}.{}", sub, domain);
            async move {
                match resolver.lookup_ip(target.clone()).await {
                    Ok(lookup) => {
                        let ips = lookup.iter().map(|ip| ip.to_string()).collect();
                        Some(SubdomainResult { subdomain: target, ip_addresses: ips })
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(20);

    while let Some(res) = stream.next().await {
        if let Some(item) = res {
            found.push(item);
        }
    }

    Ok(found)
}
