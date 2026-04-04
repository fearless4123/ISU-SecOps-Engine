use crate::cms::detector::detect_cms;
use colored::*;
use anyhow::Result;

pub mod detector;

pub async fn run_cms_detect(url: &str) -> Result<()> {
    println!("{} Detecting CMS for {}...", "🏷️".cyan(), url.bold());
    
    match detect_cms(url).await {
        Ok(Some(result)) => {
            println!("\n{}", "--- CMS Detection Result ---".bold().green());
            println!("{:<15} : {}", "CMS Name".yellow(), result.name.bold().green());
            println!("{:<15} : {}", "Version".yellow(), result.version.unwrap_or_else(|| "Unknown".to_string()).cyan());
            println!("{:<15} : {}", "Confidence".yellow(), result.confidence.bold().blue());
            
            if result.name == "WordPress" {
                println!("\n{}", "💡 Recommendation: Check for common WordPress vulnerabilities (e.g., using wpscan)".italic().dimmed());
            }
        }
        Ok(None) => {
            println!("{}", "No common CMS detected.".yellow());
        }
        Err(e) => {
            eprintln!("{} CMS detection failed: {}", "✖".red(), e);
        }
    }

    Ok(())
}
