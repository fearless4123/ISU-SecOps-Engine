use crate::recon::scanner::{run_recon, ReconResult};
use colored::*;
use anyhow::Result;

pub mod scanner;

pub async fn run_recon_module(target: &str) -> Result<()> {
    println!("{} Performing reconnaissance for {}...", "🔭".cyan(), target.bold());
    
    match run_recon(target).await {
        Ok(result) => {
            if let Some(geo) = result.geo {
                println!("\n{}", "--- IP Geolocation ---".bold().green());
                println!("{:<15} : {}", "IP Address".yellow(), geo.query.unwrap_or_default());
                println!("{:<15} : {}", "Country".yellow(), geo.country.unwrap_or_default());
                println!("{:<15} : {}", "City".yellow(), geo.city.unwrap_or_default());
                println!("{:<15} : {}", "ISP".yellow(), geo.isp.unwrap_or_default());
            }

            if let Some(whois) = result.whois {
                println!("\n{}", "--- WHOIS Information ---".bold().green());
                // Show first 20 lines of WHOIS to keep it clean
                let lines: Vec<&str> = whois.lines().collect();
                for line in lines.iter().take(20) {
                    if !line.trim().is_empty() && !line.starts_with('%') {
                        println!("{}", line);
                    }
                }
                if lines.len() > 20 {
                    println!("{}", "... [truncated for brevity]".dimmed());
                }
            } else {
                println!("\n{}", "No WHOIS information found.".yellow());
            }
        }
        Err(e) => {
            eprintln!("{} Reconnaissance failed: {}", "✖".red(), e);
        }
    }

    Ok(())
}
