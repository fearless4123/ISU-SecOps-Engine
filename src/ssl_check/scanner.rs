use crate::ssl_check::models::{CertInfo, SslAnalysis, TlsVersionInfo};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use std::net::TcpStream;
use x509_parser::prelude::*;

pub async fn perform_analysis(host: &str) -> Result<SslAnalysis> {
    let mut analysis = SslAnalysis {
        host: host.to_string(),
        certificate: None,
        tls_versions: Vec::new(),
        grade: "F".to_string(),
    };

    // 1. Probe TLS Versions
    let versions = [
        (SslVersion::TLS1, "TLS 1.0"),
        (SslVersion::TLS1_1, "TLS 1.1"),
        (SslVersion::TLS1_2, "TLS 1.2"),
        (SslVersion::TLS1_3, "TLS 1.3"),
    ];

    for (ver, name) in versions {
        let supported = probe_version(host, ver).is_ok();
        analysis.tls_versions.push(TlsVersionInfo {
            version: name.to_string(),
            supported,
        });
    }

    // 2. Extract Certificate and Chain validation
    // First attempt to get cert with verification
    let (cert, chain_valid) = match get_certificate(host, true) {
        Ok(c) => (Some(c), true),
        Err(_) => {
            // If it failed, try without verification to at least see what's there
            match get_certificate(host, false) {
                Ok(c) => (Some(c), false),
                Err(_) => (None, false),
            }
        }
    };

    if let Some(mut c) = cert {
        c.is_valid = c.is_valid && chain_valid;
        analysis.certificate = Some(c);
    }

    // 3. Calculate Grade
    analysis.grade = calculate_grade(&analysis);

    Ok(analysis)
}

fn probe_version(host: &str, version: SslVersion) -> Result<()> {
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_min_proto_version(Some(version))?;
    connector.set_max_proto_version(Some(version))?;
    connector.set_verify(SslVerifyMode::NONE);
    
    let connector = connector.build();
    let stream = TcpStream::connect(format!("{}:443", host))?;
    connector.connect(host, stream).map_err(|e| anyhow!("Handshake failed: {}", e))?;
    
    Ok(())
}

fn get_certificate(host: &str, verify: bool) -> Result<CertInfo> {
    let mut connector_builder = SslConnector::builder(SslMethod::tls())?;
    if !verify {
        connector_builder.set_verify(SslVerifyMode::NONE);
    }
    
    let connector = connector_builder.build();
    let stream = TcpStream::connect(format!("{}:443", host))?;
    let ssl_stream = connector.connect(host, stream).map_err(|e| anyhow!("Handshake failed: {}", e))?;
    
    let cert = ssl_stream.ssl().peer_certificate()
        .ok_or_else(|| anyhow!("No certificate found"))?;
    
    let der = cert.to_der()?;
    let (_, x509) = X509Certificate::from_der(&der)
        .map_err(|_| anyhow!("Failed to parse certificate"))?;

    let subject = x509.subject();
    let common_name = subject.iter_common_name()
        .next()
        .map(|attr| attr.as_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let issuer = x509.issuer().iter_common_name()
        .next()
        .map(|attr| attr.as_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let mut san = Vec::new();
    if let Ok(Some(ext)) = x509.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => san.push(d.to_string()),
                _ => {}
            }
        }
    }

    let now = Utc::now();
    let not_before = x509.validity().not_before.to_datetime();
    let not_after = x509.validity().not_after.to_datetime();
    
    let is_valid = now >= DateTime::<Utc>::from_naive_utc_and_offset(not_before, Utc) 
                   && now <= DateTime::<Utc>::from_naive_utc_and_offset(not_after, Utc);

    Ok(CertInfo {
        common_name,
        subject_alt_names: san,
        issuer,
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        is_valid,
    })
}

fn calculate_grade(analysis: &SslAnalysis) -> String {
    let has_tls13 = analysis.tls_versions.iter().any(|v| v.version == "TLS 1.3" && v.supported);
    let has_tls12 = analysis.tls_versions.iter().any(|v| v.version == "TLS 1.2" && v.supported);
    let has_legacy = analysis.tls_versions.iter().any(|v| (v.version == "TLS 1.0" || v.version == "TLS 1.1") && v.supported);
    
    let cert_valid = analysis.certificate.as_ref().map(|c| c.is_valid).unwrap_or(false);

    if !cert_valid {
        return "F (Ceriticate Chain / Validity Issue)".to_string();
    }

    if has_tls13 && !has_legacy { return "A+".to_string(); }
    if has_tls12 && !has_legacy { return "A".to_string(); }
    if has_legacy { return "B- or C (Legacy TLS enabled)".to_string(); }

    "F".to_string()
}
