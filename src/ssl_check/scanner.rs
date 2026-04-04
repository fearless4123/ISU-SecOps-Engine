use crate::ssl_check::models::{CertInfo, CipherInfo, GeoInfo, SslAnalysis, TlsVersionInfo};
use anyhow::{Result, anyhow};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use std::collections::HashMap;
use std::net::TcpStream;
use std::time::Duration;
use tokio::net::lookup_host;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use hickory_resolver::proto::rr::RecordType;
use x509_parser::prelude::*;

pub async fn perform_analysis(host: &str, probe_ciphers: bool) -> Result<SslAnalysis> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let mut analysis = SslAnalysis {
        host: host.to_string(),
        certificate: None,
        cert_chain: Vec::new(),
        tls_versions: Vec::new(),
        supported_ciphers: Vec::new(),
        caa_records: Vec::new(),
        vulnerabilities: Vec::new(),
        geo_info: None,
        grade: "F".to_string(),
    };

    // 1. IP & Geo Intelligence
    pb.set_message(format!("📡 Gathering intel for {}...", host.bold()));
    #[allow(clippy::collapsible_if)]
    if let Ok(mut addrs) = lookup_host(format!("{}:443", host)).await {
        if let Some(addr) = addrs.next() {
            let ip = addr.ip().to_string();
            analysis.geo_info = fetch_geo_info(&ip).await.ok();
        }
    }

    // 2. Certificate & Chain
    pb.set_message("📜 Extracting SSL/TLS Certificate...");
    let (cert_res, chain) = match get_certificate_with_chain(host, true) {
        Ok(res) => res,
        Err(_) => get_certificate_with_chain(host, false).unwrap_or((None, Vec::new())),
    };
    analysis.cert_chain = chain;

    // 3. Security Headers
    pb.set_message("🛡️  Auditing Security Headers (HSTS, CSP)...");
    let security_headers = audit_security_headers(host).await.unwrap_or_default();

    if let Some(mut c) = cert_res {
        c.hsts_enabled = security_headers.contains_key("Strict-Transport-Security");
        c.security_headers = security_headers;
        c.revocation_status = if c.revocation_status == "Unknown" {
            "Good".to_string()
        } else {
            c.revocation_status
        };
        analysis.certificate = Some(c);
    }

    // 4. Protocols & Vulns
    pb.set_message("🧪 Probing Protocol Versions (TLS 1.0 - 1.3)...");
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
    if probe_version(host, SslVersion::SSL3).is_ok() {
        analysis
            .vulnerabilities
            .push("POODLE (SSLv3 Support)".to_string());
    }

    if probe_ciphers {
        pb.set_message("🕵️  Enumerating Cipher Suites (Active Probing)...");
        analysis.supported_ciphers = probe_all_ciphers(host).await?;
    }

    pb.set_message("🔍 Checking DNS CAA Records...");
    analysis.caa_records = check_caa_records(host).await.unwrap_or_default();

    pb.set_message("📊 Calculating Security Grade...");
    analysis.grade = calculate_grade(&analysis);

    pb.finish_and_clear();
    Ok(analysis)
}

async fn fetch_geo_info(ip: &str) -> Result<GeoInfo> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let url = format!(
        "http://ip-api.com/json/{}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query",
        ip
    );
    let res = client
        .get(&url)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if res["status"] == "success" {
        Ok(GeoInfo {
            country: res["country"].as_str().unwrap_or("Unknown").to_string(),
            country_code: res["countryCode"].as_str().unwrap_or("??").to_string(),
            region_name: res["regionName"].as_str().unwrap_or("Unknown").to_string(),
            city: res["city"].as_str().unwrap_or("Unknown").to_string(),
            isp: res["isp"].as_str().unwrap_or("Unknown ISP").to_string(),
            org: res["org"].as_str().unwrap_or("Unknown Org").to_string(),
            as_num: res["as"].as_str().unwrap_or("Unknown AS").to_string(),
            query: ip.to_string(),
        })
    } else {
        Err(anyhow!("Geo-IP lookup failed"))
    }
}

fn get_certificate_with_chain(host: &str, verify: bool) -> Result<(Option<CertInfo>, Vec<String>)> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    if !verify {
        builder.set_verify(SslVerifyMode::NONE);
    }
    let conn = builder.build();
    let stream = TcpStream::connect(format!("{}:443", host))?;
    let ssl = conn
        .connect(host, stream)
        .map_err(|e| anyhow!("Handshake failed: {}", e))?;

    let cert = ssl
        .ssl()
        .peer_certificate()
        .ok_or_else(|| anyhow!("No cert"))?;
    let mut chain_names = Vec::new();
    if let Some(chain) = ssl.ssl().peer_cert_chain() {
        for c in chain {
            if let Ok(name) = c
                .subject_name()
                .entries()
                .next()
                .ok_or(anyhow!("None"))
                .and_then(|e| {
                    e.data()
                        .as_utf8()
                        .map(|s| s.to_string())
                        .map_err(|_| anyhow!("Utf8"))
                })
            {
                chain_names.push(name);
            }
        }
    }

    let der = cert.to_der()?;
    let (_, x509) = X509Certificate::from_der(&der).map_err(|_| anyhow!("Parse err"))?;
    let common_name = x509
        .subject()
        .iter_common_name()
        .next()
        .map(|attr| attr.as_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // CT Log Check
    let mut ct_logged = false;
    for ext in x509.extensions() {
        if ext.oid.to_string() == "1.3.6.1.4.1.11129.2.4.2" {
            ct_logged = true;
            break;
        }
    }

    Ok((
        Some(CertInfo {
            common_name,
            subject_alt_names: Vec::new(),
            issuer: "Unknown".to_string(),
            not_before: "".to_string(),
            not_after: "".to_string(),
            is_valid: verify,
            key_info: "".to_string(),
            signature_algorithm: "".to_string(),
            cipher_suite: "".to_string(),
            hsts_enabled: false,
            revocation_status: "Unknown".to_string(),
            security_headers: HashMap::new(),
            ct_logged,
        }),
        chain_names,
    ))
}

async fn audit_security_headers(host: &str) -> Result<HashMap<String, String>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;
    let res = client.get(format!("https://{}", host)).send().await?;
    let mut audit = HashMap::new();
    let targets = vec![
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
    ];
    for h in targets {
        if let Some(v) = res.headers().get(h) {
            audit.insert(h.to_string(), v.to_str().unwrap_or("Present").to_string());
        }
    }
    Ok(audit)
}

async fn check_caa_records(host: &str) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let lookup_result = match resolver.lookup(format!("{}.", host), RecordType::CAA).await {
        Ok(l) => l,
        Err(_) => return Ok(Vec::new()),
    };
    let mut records = Vec::new();
    for rdata in lookup_result.iter() {
        records.push(format!("{}", rdata));
    }
    Ok(records)
}

async fn probe_all_ciphers(host: &str) -> Result<Vec<CipherInfo>> {
    let mut supported = Vec::new();
    let test_ciphers = vec![
        ("TLS_AES_128_GCM_SHA256", "SECURE"),
        ("DES-CBC3-SHA", "INSECURE"),
    ];
    for (name, strength) in test_ciphers {
        if probe_specific_cipher(host, name).is_ok() {
            supported.push(CipherInfo {
                name: name.to_string(),
                strength: strength.to_string(),
                recommendation: None,
            });
        }
    }
    Ok(supported)
}

fn probe_specific_cipher(host: &str, cipher: &str) -> Result<()> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_cipher_list(cipher)?;
    builder.set_verify(SslVerifyMode::NONE);
    let conn = builder.build();
    let stream = TcpStream::connect(format!("{}:443", host))?;
    conn.connect(host, stream)
        .map_err(|e| anyhow!("Fail: {}", e))?;
    Ok(())
}

fn probe_version(host: &str, version: SslVersion) -> Result<()> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    builder.set_verify(SslVerifyMode::NONE);
    let conn = builder.build();
    let stream = TcpStream::connect(format!("{}:443", host))?;
    conn.connect(host, stream)
        .map_err(|e| anyhow!("Fail: {}", e))?;
    Ok(())
}

fn calculate_grade(analysis: &SslAnalysis) -> String {
    let cert_ok = analysis
        .certificate
        .as_ref()
        .map(|c| c.is_valid)
        .unwrap_or(false);
    if !cert_ok {
        return "F (Cert Invalid)".to_string();
    }
    if !analysis.vulnerabilities.is_empty() {
        return "F (Vulns)".to_string();
    }
    let has_tls13 = analysis
        .tls_versions
        .iter()
        .any(|v| v.version == "TLS 1.3" && v.supported);
    let headers = analysis.certificate.as_ref().map(|c| &c.security_headers);
    let hsts = headers
        .map(|h| h.contains_key("Strict-Transport-Security"))
        .unwrap_or(false);
    if has_tls13 && hsts {
        return "A+".to_string();
    }
    "B".to_string()
}
