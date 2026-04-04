use crate::port_scan::scanner::{scan_ports, get_top_ports, OpenPort};
use colored::*;
use anyhow::Result;

pub mod scanner;

pub async fn run_port_scan(host: &str) -> Result<()> {
    println!("{} Starting port scan for {}...", "📡".cyan(), host.bold());
    let ports = get_top_ports();
    
    match scan_ports(host, ports).await {
        Ok(results) => {
            if results.is_empty() {
                println!("{}", "No common open ports found.".yellow());
            } else {
                println!("\n{}", "--- Open Ports & Services ---".bold().green());
                println!("{:<10} | {:<15}", "Port".bold(), "Service".bold());
                println!("{}", "-".repeat(30));
                for res in results {
                    println!("{:<10} | {:<15}", res.port.to_string().yellow(), res.service.cyan());
                }
                println!("\nTotal: {} open ports found.", results.len().to_string().bold());
            }
        }
        Err(e) => {
            eprintln!("{} Port scan failed: {}", "✖".red(), e);
        }
    }

    Ok(())
}
