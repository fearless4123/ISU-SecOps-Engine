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
                println!("{:<15}: {}", "Common Name".yellow(), cert.common_name);
                println!("{:<15}: {}", "Issuer".yellow(), cert.issuer);
                println!("{:<15}: {}", "Not Before".yellow(), cert.not_before);
                println!("{:<15}: {}", "Not After".yellow(), cert.not_after);
                println!("{:<15}: {}", "SANs".yellow(), cert.subject_alt_names.join(", "));
                
                let validity = if cert.is_valid {
                    "VALID".green().bold()
                } else {
                    "EXPIRED/INVALID".red().bold()
                };
                println!("{:<15}: {}", "Status".yellow(), validity);
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
                println!("{:<15}: {}", tv.version.yellow(), status);
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
