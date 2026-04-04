use anyhow::Result;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

#[derive(Debug, Clone)]
pub struct MailAuditResult {
    pub domain: String,
    pub spf_record: Option<String>,
    pub dmarc_record: Option<String>,
    pub is_spf_strong: bool,
    pub is_dmarc_strong: bool,
    pub recommendation: Vec<String>,
}

pub async fn audit_email_security(domain: &str) -> Result<MailAuditResult> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let mut result = MailAuditResult {
        domain: domain.to_string(),
        spf_record: None,
        dmarc_record: None,
        is_spf_strong: false,
        is_dmarc_strong: false,
        recommendation: Vec::new(),
    };

    // 1. Check SPF
    if let Ok(lookup) = resolver.txt_lookup(domain).await {
        for txt in lookup.iter() {
            let record = txt.to_string();
            if record.starts_with("v=spf1") {
                result.spf_record = Some(record.clone());
                if record.ends_with("-all") {
                    result.is_spf_strong = true;
                } else if record.ends_with("~all") {
                    result.recommendation.push("SPF set to SoftFail (~all). Consider using HardFail (-all) for strict enforcement.".to_string());
                } else {
                    result.recommendation.push("SPF record has weak ending (missing -all/~all).".to_string());
                }
                break;
            }
        }
    }

    if result.spf_record.is_none() {
        result.recommendation.push("Missing SPF record! Anyone can spoof emails from this domain.".to_string());
    }

    // 2. Check DMARC
    let dmarc_domain = format!("_dmarc.{}", domain);
    if let Ok(lookup) = resolver.txt_lookup(dmarc_domain).await {
        for txt in lookup.iter() {
            let record = txt.to_string();
            if record.starts_with("v=DMARC1") {
                result.dmarc_record = Some(record.clone());
                if record.contains("p=reject") {
                    result.is_dmarc_strong = true;
                } else if record.contains("p=quarantine") {
                    result.recommendation.push("DMARC policy set to 'quarantine'. Consider moving to 'reject'.".to_string());
                } else {
                    result.recommendation.push("DMARC policy set to 'none'. This provides no protection against spoofing.".to_string());
                }
                break;
            }
        }
    }

    if result.dmarc_record.is_none() {
        result.recommendation.push("Missing DMARC record! Recommended for email security.".to_string());
    }

    Ok(result)
}
