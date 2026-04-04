use crate::subdomain::scanner::{scan_subdomains, SubdomainResult};
use colored::*;
use anyhow::Result;

pub mod scanner;

pub async fn run_sub_enum(domain: &str) -> Result<()> {
    println!("{} Enumerating subdomains for {}...", "🔍".cyan(), domain.bold());
    
    match scan_subdomains(domain).await {
        Ok(results) => {
            if results.is_empty() {
                println!("{}", "No subdomains found with current wordlist.".yellow());
            } else {
                println!("\n{}", "--- Found Subdomains ---".bold().green());
                for res in results {
                    println!("{:<25} -> {}", res.subdomain.yellow(), res.ip_addresses.join(", ").cyan());
                }
                println!("\nTotal: {} subdomains found.", results.len().to_string().bold());
            }
        }
        Err(e) => {
            eprintln!("{} Subdomain enumeration failed: {}", "✖".red(), e);
        }
    }

    Ok(())
}
