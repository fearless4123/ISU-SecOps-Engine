use crate::ssl_check::scanner::perform_analysis;
use colored::*;
use anyhow::Result;
use std::fs::File;
use std::io::Write;

pub mod models;
pub mod scanner;

pub async fn run_analysis(host: &str, show_grade: bool, probe_ciphers: bool, json_path: Option<String>) -> Result<()> {
    match perform_analysis(host, probe_ciphers).await {
        Ok(analysis) => {
            // 1. Terminal Output
            println!("\n{}", "--- Certificate Information ---".bold().cyan());
            if let Some(ref cert) = analysis.certificate {
                println!("{:<20}: {}", "Common Name".yellow(), cert.common_name);
                println!("{:<20}: {}", "Issuer".yellow(), cert.issuer);
                println!("{:<20}: {}", "Key Info".yellow(), cert.key_info);
                println!("{:<20}: {}", "Signature Alg.".yellow(), cert.signature_algorithm);
                println!("{:<20}: {}", "Not Before".yellow(), cert.not_before);
                println!("{:<20}: {}", "Not After".yellow(), cert.not_after);
                
                let hsts = if cert.hsts_enabled { "ENABLED".green().bold() } else { "DISABLED".red() };
                println!("{:<20}: {}", "HSTS".yellow(), hsts);

                let revocation = if cert.revocation_status.contains("Good") || cert.revocation_status.contains("Available") {
                    cert.revocation_status.green().bold()
                } else {
                    cert.revocation_status.yellow()
                };
                println!("{:<20}: {}", "Revocation (OCSP)".yellow(), revocation);

                let validity = if cert.is_valid {
                    "VALID".green().bold()
                } else {
                    "EXPIRED/INVALID".red().bold()
                };
                println!("{:<20}: {}", "Status".yellow(), validity);
            }

            println!("\n{}", "--- Certificate Chain (Trust Path) ---".bold().cyan());
            if analysis.cert_chain.is_empty() {
                println!("{}", "  No chain information available.".red());
            } else {
                for (i, node) in analysis.cert_chain.iter().enumerate() {
                    let indent = "  ".repeat(i);
                    let prefix = if i == 0 { "●" } else { "┗━" };
                    let color_node = if i == 0 { node.white().bold() } else if i == analysis.cert_chain.len() - 1 { node.green().bold() } else { node.yellow() };
                    println!("{}{}{}", indent, prefix.dimmed(), color_node);
                }
            }

            println!("\n{}", "--- Security Headers Audit ---".bold().cyan());
            if let Some(ref cert) = analysis.certificate {
                let target_headers = vec!["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"];
                for header in target_headers {
                    let status = if let Some(val) = cert.security_headers.get(header) {
                        format!("{} ({})", "PRESENT".green().bold(), val.dimmed())
                    } else {
                        "MISSING".red().to_string()
                    };
                    println!("{:<25}: {}", header.yellow(), status);
                }
            }

            println!("\n{}", "--- DNS Security & Compliance ---".bold().cyan());
            if analysis.caa_records.is_empty() {
                println!("{:<20}: {}", "CAA Records".yellow(), "NONE".red());
            } else {
                println!("{:<20}:", "CAA Records".yellow());
                for caa in &analysis.caa_records {
                    println!("  ┗━ {}", caa.green());
                }
            }

            println!("\n{}", "--- TLS Protocol Support ---".bold().cyan());
            for tv in &analysis.tls_versions {
                let status = if tv.supported { "SUPPORTED".green().bold() } else { "NOT SUPPORTED".red() };
                println!("{:<20}: {}", tv.version.yellow(), status);
            }

            if show_grade {
                println!("\n{}", "--- Security Grade ---".bold().cyan());
                println!("Grade: {}", analysis.grade.green().bold());
            }

            if let Some(path) = json_path {
                let json_data = serde_json::to_string_pretty(&analysis)?;
                let mut file = File::create(&path)?;
                file.write_all(json_data.as_bytes())?;
                println!("\n{} Analysis report successfully exported to: {}", "✔".green(), path.bold().cyan());
            }
        }
        Err(e) => {
            eprintln!("{} Analysis failed for {}: {}", "✖".red(), host, e);
        }
    }

    Ok(())
}
