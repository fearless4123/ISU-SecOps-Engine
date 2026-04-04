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
                let validity = if cert.is_valid { "VALID".green().bold() } else { "EXPIRED/INVALID".red().bold() };
                println!("{:<20}: {}", "Status".yellow(), validity);
            }

            println!("\n{}", "--- Vulnerability Assessment ---".bold().cyan());
            if analysis.vulnerabilities.is_empty() {
                println!("  {} No common handshake vulnerabilities detected.", "✔".green());
            } else {
                for vuln in &analysis.vulnerabilities {
                    println!("  {} {}", "✖".red().bold(), vuln.red().bold());
                }
            }

            println!("\n{}", "--- Certificate Chain (Trust Path) ---".bold().cyan());
            for (i, node) in analysis.cert_chain.iter().enumerate() {
                let indent = "  ".repeat(i);
                let prefix = if i == 0 { "●" } else { "┗━" };
                println!("{}{}{}", indent, prefix.dimmed(), node.white());
            }

            println!("\n{}", "--- Security Headers Audit ---".bold().cyan());
            if let Some(ref cert) = analysis.certificate {
                let target_headers = vec!["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"];
                for header in target_headers {
                    let status = if cert.security_headers.contains_key(header) { "PRESENT".green() } else { "MISSING".red() };
                    println!("{:<25}: {}", header.yellow(), status);
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
