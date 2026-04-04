use crate::fuzzer::scanner::{fuzz_url, FuzzResult};
use colored::*;
use anyhow::Result;

pub mod scanner;

pub async fn run_fuzz(base_url: &str) -> Result<()> {
    println!("{} Starting web fuzzer for {}...", "🌪️".cyan(), base_url.bold());
    
    match fuzz_url(base_url).await {
        Ok(results) => {
            if results.is_empty() {
                println!("{}", "No interesting paths found with current wordlist.".yellow());
            } else {
                println!("\n{}", "--- Fuzzing Results ---".bold().green());
                println!("{:<20} | {:<10} | {:<30}", "Path".bold(), "Status".bold(), "URL".bold());
                println!("{}", "-".repeat(70));
                for res in results {
                    let status_str = res.status.as_str();
                    let colored_status = if res.status.is_success() {
                        status_str.green()
                    } else if res.status.is_redirection() {
                        status_str.blue()
                    } else if res.status == reqwest::StatusCode::FORBIDDEN {
                        status_str.yellow()
                    } else {
                        status_str.red()
                    };
                    
                    println!("{:<20} | {:<10} | {:<30}", res.path.yellow(), colored_status.bold(), res.url.cyan());
                }
                println!("\nTotal: {} items discovered.", results.len().to_string().bold());
            }
        }
        Err(e) => {
            eprintln!("{} Fuzzing failed: {}", "✖".red(), e);
        }
    }

    Ok(())
}
