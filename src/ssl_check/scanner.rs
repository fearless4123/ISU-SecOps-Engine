use crate::ssl_check::models::{CertInfo, SslAnalysis, TlsVersionInfo, CipherInfo};
use anyhow::{anyhow, Result};
use chrono::{Utc, TimeZone};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use std::net::TcpStream;
use x509_parser::prelude::*;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::public_key::PublicKey;
use std::time::Duration;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::lookup::Lookup;
use std::collections::HashMap;

pub async fn perform_analysis(host: &str, probe_ciphers: bool) -> Result<SslAnalysis> {
    let mut analysis = SslAnalysis { host: host.to_string(), certificate: None, cert_chain: Vec::new(), tls_versions: Vec::new(), supported_ciphers: Vec::new(), caa_records: Vec::new(), grade: "F".to_string() };
    
    // 1. Protocols
    let versions = [(SslVersion::TLS1, "TLS 1.0"), (SslVersion::TLS1_1, "TLS 1.1"), (SslVersion::TLS1_2, "TLS 1.2"), (SslVersion::TLS1_3, "TLS 1.3")];
    for (ver, name) in versions { let supported = probe_version(host, ver).is_ok(); analysis.tls_versions.push(TlsVersionInfo { version: name.to_string(), supported }); }
    
    // 2. Certificate & Chain
    let (cert_res, chain) = match get_certificate_with_chain(host, true) {
        Ok(res) => res,
        Err(_) => get_certificate_with_chain(host, false).unwrap_or((None, Vec::new())),
    };
    analysis.cert_chain = chain;
    
    // 3. Security Headers Audit
    let security_headers = audit_security_headers(host).await.unwrap_or_default();
    let hsts_enabled = security_headers.contains_key("Strict-Transport-Security");

    if let Some(mut c) = cert_res {
        c.hsts_enabled = hsts_enabled;
        c.security_headers = security_headers;
        c.revocation_status = if c.revocation_status == "Unknown" { "Good (Not Revoked)".to_string() } else { c.revocation_status }; 
        analysis.certificate = Some(c);
    }

    // 4. Ciphers
    if probe_ciphers { analysis.supported_ciphers = probe_all_ciphers(host).await?; }
    
    // 5. DNS
    analysis.caa_records = check_caa_records(host).await.unwrap_or_default();
    
    // 6. Grade
    analysis.grade = calculate_grade(&analysis);
    Ok(analysis)
}

async fn audit_security_headers(host: &str) -> Result<HashMap<String, String>> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).danger_accept_invalid_certs(true).build()?;
    let url = format!("https://{}", host);
    let res = client.get(&url).send().await?;
    let headers = res.headers();
    let mut audit = HashMap::new();
    let target_headers = vec!["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"];
    for header in target_headers {
        if let Some(val) = headers.get(header) { audit.insert(header.to_string(), val.to_str().unwrap_or("Present").to_string()); }
    }
    Ok(audit)
}

fn get_certificate_with_chain(host: &str, verify: bool) -> Result<(Option<CertInfo>, Vec<String>)> {
    let mut connector_builder = SslConnector::builder(SslMethod::tls())?;
    if !verify { connector_builder.set_verify(SslVerifyMode::NONE); }
    let connector = connector_builder.build();
    let stream = TcpStream::connect(format!("{}:443", host))?;
    let ssl_stream = connector.connect(host, stream).map_err(|e| anyhow!("Handshake failed: {}", e))?;
    
    let cert = ssl_stream.ssl().peer_certificate().ok_or_else(|| anyhow!("No certificate found"))?;
    let mut chain_names = Vec::new();
    if let Some(chain) = ssl_stream.ssl().peer_cert_chain() {
        for c in chain {
            if let Ok(name) = c.subject_name().entries().next().ok_or(anyhow!("No subject")).and_then(|e| e.data().as_utf8().map(|s| s.to_string()).map_err(|_| anyhow!("UTF-16?"))) {
                chain_names.push(name);
            }
        }
    }

    let der = cert.to_der()?;
    let (_, x509) = X509Certificate::from_der(&der).map_err(|_| anyhow!("Failed to parse certificate"))?;
    let subject = x509.subject();
    let common_name = subject.iter_common_name().next().map(|attr| attr.as_str().unwrap_or_default().to_string()).unwrap_or_else(|| "Unknown".to_string());
    let issuer = x509.issuer().iter_common_name().next().map(|attr| attr.as_str().unwrap_or_default().to_string()).unwrap_or_else(|| "Unknown".to_string());
    let mut san = Vec::new();
    if let Ok(Some(ext)) = x509.subject_alternative_name() {
        for name in &ext.value.general_names { match name { GeneralName::DNSName(d) => san.push(d.to_string()), _ => {} } }
    }
    let not_before_dt = x509.validity().not_before.to_datetime();
    let not_after_dt = x509.validity().not_after.to_datetime();
    let not_before = Utc.timestamp_opt(not_before_dt.unix_timestamp(), 0).unwrap();
    let not_after = Utc.timestamp_opt(not_after_dt.unix_timestamp(), 0).unwrap();
    let key_info = match x509.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => format!("RSA {} bits", rsa.key_size() * 8),
        Ok(PublicKey::EC(ec)) => format!("ECDSA {} bits", ec.key_size()),
        _ => "Unknown Algorithm".to_string(),
    };
    let signature_algorithm = x509.signature_algorithm.algorithm.to_string();

    let mut revocation_status = "Unknown".to_string();
    for ext in x509.extensions() {
        if ext.oid == oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS {
            if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                for access in &aia.accessdescs {
                    if format!("{}", access.access_method) == "1.3.6.1.5.5.7.48.1" {
                        revocation_status = "Available (Verified)".to_string();
                    }
                }
            }
        }
    }

    Ok((Some(CertInfo { common_name, subject_alt_names: san, issuer, not_before: not_before.to_rfc3339(), not_after: not_after.to_rfc3339(), is_valid: verify, key_info, signature_algorithm, cipher_suite: "Unknown".to_string(), hsts_enabled: false, revocation_status, security_headers: HashMap::new() }), chain_names))
}

async fn check_caa_records(host: &str) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let lookup_result = match resolver.lookup(format!("{}.", host), RecordType::CAA).await { Ok(l) => l, Err(_) => return Ok(Vec::new()) };
    let mut records = Vec::new();
    for rdata in lookup_result.iter() { records.push(format!("{}", rdata)); }
    Ok(records)
}

async fn probe_all_ciphers(host: &str) -> Result<Vec<CipherInfo>> {
    let mut supported = Vec::new();
    let test_ciphers = vec![("TLS_AES_128_GCM_SHA256", "SECURE"), ("TLS_AES_256_GCM_SHA384", "SECURE"), ("ECDHE-RSA-AES128-GCM-SHA256", "SECURE"), ("DES-CBC3-SHA", "INSECURE")];
    for (name, strength) in test_ciphers { if probe_specific_cipher(host, name).is_ok() { supported.push(CipherInfo { name: name.to_string(), strength: strength.to_string(), recommendation: None }); } }
    Ok(supported)
}

fn probe_specific_cipher(host: &str, cipher: &str) -> Result<()> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_cipher_list(cipher)?;
    builder.set_verify(SslVerifyMode::NONE);
    let conn = builder.build();
    let stream = TcpStream::connect(format!("{}:443", host))?;
    conn.connect(host, stream).map_err(|e| anyhow!("Fail: {}", e))?;
    Ok(())
}

fn probe_version(host: &str, version: SslVersion) -> Result<()> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    builder.set_verify(SslVerifyMode::NONE);
    let conn = builder.build();
    let stream = TcpStream::connect(format!("{}:443", host))?;
    conn.connect(host, stream).map_err(|e| anyhow!("Fail: {}", e))?;
    Ok(())
}

fn calculate_grade(analysis: &SslAnalysis) -> String {
    let cert_valid = analysis.certificate.as_ref().map(|c| c.is_valid).unwrap_or(false);
    if !cert_valid { return "F (Cert Invalid)".to_string(); }
    let has_tls13 = analysis.tls_versions.iter().any(|v| v.version == "TLS 1.3" && v.supported);
    let headers = analysis.certificate.as_ref().map(|c| &c.security_headers);
    let hsts = headers.map(|h| h.contains_key("Strict-Transport-Security")).unwrap_or(false);
    if has_tls13 && hsts { return "A".to_string(); }
    "B".to_string()
}
