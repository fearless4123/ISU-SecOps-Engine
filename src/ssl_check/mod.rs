use crate::ssl_check::scanner::perform_analysis;
use colored::*;
use anyhow::Result;
use std::fs::File;
use std::io::Write;

pub mod models;
pub mod scanner;

pub async fn run_analysis(host: &str, show_grade: bool, probe_ciphers: bool, json_path: Option<String>) -> Result<()> {
    match perform_analysis(host, probe_ciphers).await {
        Ok(analysis) => {
            println!("\n{}", format!("--- Audit Results for {} ---", host).bold().cyan());
            
            if let Some(ref geo) = analysis.geo_info {
                println!("{}", "--- Global Intelligence & Intel ---".bold().cyan());
                println!("{:<20}: {} ({})", "Physical Location".yellow(), geo.city, geo.country);
                println!("{:<20}: {}", "ISP Provider".yellow(), geo.isp);
                println!("{:<20}: {}", "ASN / Network".yellow(), geo.as_num);
                println!("{:<20}: {}", "Server IP".yellow(), geo.query.bold().white());
            }

            println!("\n{}", "--- Certificate Information ---".bold().cyan());
            if let Some(ref cert) = analysis.certificate {
                println!("{:<20}: {}", "Common Name".yellow(), cert.common_name);
                let ct_status = if cert.ct_logged { "LOGGED (Safe)".green().bold() } else { "NOT LOGGED (Risk)".red() };
                println!("{:<20}: {}", "CT Logs".yellow(), ct_status);
                let validity = if cert.is_valid { "VALID".green().bold() } else { "EXPIRED/INVALID".red().bold() };
                println!("{:<20}: {}", "Status".yellow(), validity);
            }

            if !analysis.vulnerabilities.is_empty() {
                println!("\n{}", "--- Vulnerability Assessment ---".bold().red());
                for v in &analysis.vulnerabilities { println!("  {} {}", "✖".red(), v); }
            }

            println!("\n{}", "--- Certificate Chain (Trust Path) ---".bold().cyan());
            for (i, node) in analysis.cert_chain.iter().enumerate() {
                let indent = "  ".repeat(i);
                let prefix = if i == 0 { "●" } else { "┗━" };
                println!("{}{}{}", indent, prefix.dimmed(), node.white());
            }

            if show_grade { println!("\n{:<20}: {}", "Security Grade".yellow(), analysis.grade.bold().green()); }

            if let Some(path) = json_path {
                let data = serde_json::to_string_pretty(&analysis)?;
                File::create(&path)?.write_all(data.as_bytes())?;
                println!("\n{} Exported to: {}", "✔".green(), path.bold().cyan());
            }
        }
        Err(e) => eprintln!("{} Failed: {}", "✖".red(), e),
    }
    Ok(())
}

pub async fn run_batch_analysis(file_path: &str, grade: bool, ciphers: bool, json_dir: Option<String>) -> Result<()> {
    let file = File::open(file_path)?;
    let reader = std::io::BufReader::new(file);
    let mut success = 0;
    let mut fail = 0;

    for line in std::io::BufRead::lines(reader) {
        let host = line?.trim().to_string();
        if host.is_empty() { continue; }
        println!("{} Auditing: {}", "ℹ".blue(), host.bold());
        let json_path = json_dir.as_ref().map(|d| format!("{}/report_{}.json", d, host.replace(".", "_")));
        if run_analysis(&host, grade, ciphers, json_path).await.is_ok() { success += 1; } else { fail += 1; }
    }

    println!("\n{}", "--- Batch Summary ---".bold().cyan());
    println!("Total Success : {}", success.to_string().green());
    println!("Total Failed  : {}", fail.to_string().red());
    Ok(())
}
