use crate::ssl_check::scanner::perform_analysis;
use colored::*;
use anyhow::Result;

pub mod models;
pub mod scanner;

pub async fn run_analysis(host: &str, show_grade: bool, probe_ciphers: bool) -> Result<()> {
    match perform_analysis(host, probe_ciphers).await {
        Ok(analysis) => {
            println!("\n{}", "--- Certificate Information ---".bold().cyan());
            if let Some(cert) = analysis.certificate {
                println!("{:<20}: {}", "Common Name".yellow(), cert.common_name);
                println!("{:<20}: {}", "Issuer".yellow(), cert.issuer);
                println!("{:<20}: {}", "Key Info".yellow(), cert.key_info);
                println!("{:<20}: {}", "Signature Alg.".yellow(), cert.signature_algorithm);
                println!("{:<20}: {}", "Not Before".yellow(), cert.not_before);
                println!("{:<20}: {}", "Not After".yellow(), cert.not_after);
                println!("{:<20}: {}", "SANs".yellow(), cert.subject_alt_names.join(", "));
                
                let hsts = if cert.hsts_enabled { "ENABLED".green().bold() } else { "DISABLED".red() };
                println!("{:<20}: {}", "HSTS".yellow(), hsts);

                let validity = if cert.is_valid {
                    "VALID".green().bold()
                } else {
                    "EXPIRED/INVALID".red().bold()
                };
                println!("{:<20}: {}", "Status".yellow(), validity);
            }

            println!("\n{}", "--- DNS Security & Compliance ---".bold().cyan());
            if analysis.caa_records.is_empty() {
                println!("{:<20}: {}", "CAA Records".yellow(), "NONE (Insecure/No Policy)".red());
            } else {
                println!("{:<20}:", "CAA Records".yellow());
                for caa in analysis.caa_records {
                    println!("  ┗━ {}", caa.green());
                }
            }

            println!("\n{}", "--- TLS Protocol Support ---".bold().cyan());
            for tv in analysis.tls_versions {
                let status = if tv.supported {
                    "SUPPORTED".green().bold()
                } else {
                    "NOT SUPPORTED".red()
                };
                println!("{:<20}: {}", tv.version.yellow(), status);
            }

            if !analysis.supported_ciphers.is_empty() {
                println!("\n{}", "--- Enumerated Cipher Suites ---".bold().cyan());
                for cipher in analysis.supported_ciphers {
                    let strength_color = match cipher.strength.as_str() {
                        "SECURE" => cipher.name.green(),
                        "WEAK" => cipher.name.yellow(),
                        "INSECURE" => cipher.name.red().bold(),
                        _ => cipher.name.white(),
                    };
                    println!("{} [Strength: {}]", strength_color, cipher.strength);
                    if let Some(rec) = cipher.recommendation {
                        println!("   ┗━ {}", rec.dimmed().italic());
                    }
                }
            }

            if show_grade {
                println!("\n{}", "--- Security Grade ---".bold().cyan());
                let grade_color = if analysis.grade.starts_with('A') {
                    analysis.grade.green().bold()
                } else if analysis.grade.starts_with('B') {
                    analysis.grade.blue().bold()
                } else if analysis.grade.starts_with('C') {
                    analysis.grade.yellow().bold()
                } else {
                    analysis.grade.red().bold()
                };
                println!("Grade: {}", grade_color);
            }
        }
        Err(e) => {
            eprintln!("{} Analysis failed for {}: {}", "✖".red(), host, e);
        }
    }

    Ok(())
}
