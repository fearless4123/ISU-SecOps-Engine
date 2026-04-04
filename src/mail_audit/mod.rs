use crate::mail_audit::checker::audit_email_security;
use colored::*;
use anyhow::Result;

pub mod checker;

pub async fn run_mail_audit(domain: &str) -> Result<()> {
    println!("{} Auditing email security for {}...", "📧".cyan(), domain.bold());
    
    match audit_email_security(domain).await {
        Ok(result) => {
            println!("\n{}", "--- Email Security Audit ---".bold().green());
            
            // SPF
            println!("{:<15} : {}", "SPF Record".yellow(), 
                result.spf_record.clone().unwrap_or_else(|| "MISSING".red().to_string()));
            let spf_status = if result.is_spf_strong { "STRONG".green() } else { "WEAK / MISSING".red() };
            println!("{:<15} : {}", "SPF Strength".yellow(), spf_status.bold());

            // DMARC
            println!("{:<15} : {}", "DMARC Record".yellow(), 
                result.dmarc_record.clone().unwrap_or_else(|| "MISSING".red().to_string()));
            let dmarc_status = if result.is_dmarc_strong { "STRONG".green() } else { "WEAK / MISSING".red() };
            println!("{:<15} : {}", "DMARC Strength".yellow(), dmarc_status.bold());

            if !result.recommendation.is_empty() {
                println!("\n{}", "--- Security Recommendations ---".bold().yellow());
                for rec in result.recommendation {
                    println!("{} {}", "⚠️".yellow(), rec);
                }
            } else {
                println!("\n{}", "✅ Email security configuration looks solid!".green().bold());
            }
        }
        Err(e) => {
            eprintln!("{} Email security audit failed: {}", "✖".red(), e);
        }
    }

    Ok(())
}
