use crate::http_audit::checker::check_headers;
use colored::*;
use anyhow::Result;

pub mod checker;

pub async fn run_http_audit(url: &str) -> Result<()> {
    println!("{} Auditing HTTP security headers for {}...", "🛡️".cyan(), url.bold());
    
    match check_headers(url).await {
        Ok(analysis) => {
            println!("\n{}", "--- Security Header Audit ---".bold().green());
            for header in analysis.headers {
                let status_icon = match header.status.as_str() {
                    "PRESENT" => "✅".green(),
                    "MISSING" => "❌".red(),
                    "INFO_LEAK" => "⚠️".yellow(),
                    _ => "✅".green(),
                };

                println!("{} {:<30} : {}", status_icon, header.name.yellow(), 
                    header.value.unwrap_or_else(|| "MISSING".to_string()).cyan());
                
                if let Some(rec) = header.recommendation {
                    println!("   ┗━ {} {}", "💡 Suggestion:".dimmed(), rec.italic().dimmed());
                }
            }
        }
        Err(e) => {
            eprintln!("{} HTTP header audit failed: {}", "✖".red(), e);
        }
    }

    Ok(())
}
