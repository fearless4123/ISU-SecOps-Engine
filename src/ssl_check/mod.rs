use crate::ssl_check::scanner::perform_analysis;
use colored::*;
use anyhow::Result;

pub mod models;
pub mod scanner;

pub async fn run_analysis(host: &str, show_grade: bool) -> Result<()> {
    match perform_analysis(host).await {
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

                println!("\n{}", "--- Connection Details ---".bold().cyan());
                println!("{:<20}: {}", "Cipher Suite".yellow(), cert.cipher_suite.bold().blue());
            } else {
                println!("{}", "No certificate information available.".red());
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

            if show_grade {
                println!("\n{}", "--- Security Grade ---".bold().cyan());
                let grade_color = match analysis.grade.chars().next().unwrap_or('F') {
                    'A' => analysis.grade.green().bold(),
                    'B' => analysis.grade.blue().bold(),
                    'C' => analysis.grade.yellow().bold(),
                    _ => analysis.grade.red().bold(),
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
