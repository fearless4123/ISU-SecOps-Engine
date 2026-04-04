use crate::ssl_check::scanner::perform_analysis;
use colored::*;
use anyhow::Result;
use std::fs::File;
use std::io::Write;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::*;

pub mod models;
pub mod scanner;

pub async fn run_analysis(host: &str, show_grade: bool, probe_ciphers: bool, json_path: Option<String>) -> Result<()> {
    match perform_analysis(host, probe_ciphers).await {
        Ok(analysis) => {
            println!("\n{}", format!("🛡️  ISU SecOps Engine - Audit Report: {}", host).bold().bright_cyan());
            
            // 1. Intelligence Table
            let mut intel_table = Table::new();
            intel_table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![Cell::new("Feature").add_attribute(Attribute::Bold).fg(Color::Cyan), Cell::new("Value").add_attribute(Attribute::Bold).fg(Color::Cyan)]);

            if let Some(ref geo) = analysis.geo_info {
                intel_table.add_row(vec!["Server IP", &geo.query]);
                intel_table.add_row(vec!["Location", &format!("{}, {}", geo.city, geo.country)]);
                intel_table.add_row(vec!["ISP / AS", &format!("{} ({})", geo.isp, geo.as_num)]);
            }
            println!("\n{}", "📡 GLOBAL INTELLIGENCE".bold().yellow());
            println!("{intel_table}");

            // 2. Certificate Table
            let mut cert_table = Table::new();
            cert_table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![Cell::new("Certificate Metric").add_attribute(Attribute::Bold).fg(Color::Cyan), Cell::new("Status").add_attribute(Attribute::Bold).fg(Color::Cyan)]);

            if let Some(ref cert) = analysis.certificate {
                cert_table.add_row(vec!["Common Name", &cert.common_name]);
                let validity = if cert.is_valid { "VALID".green().to_string() } else { "INVALID".red().to_string() };
                cert_table.add_row(vec!["Chain Trust", &validity]);
                let ct = if cert.ct_logged { "LOGGED".green().to_string() } else { "MISSING".red().to_string() };
                cert_table.add_row(vec!["Transparency (CT)", &ct]);
                let hsts = if cert.hsts_enabled { "ENABLED".green().to_string() } else { "DISABLED".yellow().to_string() };
                cert_table.add_row(vec!["HSTS Policy", &hsts]);
            }
            println!("\n{}", "📜 CERTIFICATE ANALYTICS".bold().yellow());
            println!("{cert_table}");

            // 3. Vulnerabilities
            if !analysis.vulnerabilities.is_empty() {
                println!("\n{}", "🚨 VULNERABILITY ASSESSMENT".bold().red());
                for v in &analysis.vulnerabilities {
                    println!("  {} {}", "✖".red(), v.bright_red());
                }
            } else {
                println!("\n{} No major vulnerabilities detected (POODLE, Heartbleed checked).", "✅".green());
            }

            // 4. Security Grade
            if show_grade {
                let color = if analysis.grade.contains('A') { Color::Green } else if analysis.grade.contains('B') { Color::Cyan } else { Color::Red };
                let mut grade_table = Table::new();
                grade_table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
                grade_table.add_row(vec![
                    Cell::new("FINAL SECURITY GRADE").add_attribute(Attribute::Bold),
                    Cell::new(&analysis.grade).add_attribute(Attribute::Bold).fg(color)
                ]);
                println!("\n{grade_table}");
            }

            if let Some(path) = json_path {
                let data = serde_json::to_string_pretty(&analysis)?;
                File::create(&path)?.write_all(data.as_bytes())?;
                println!("\n{} Exported full report to: {}", "💾".green(), path.bold().cyan());
            }
        }
        Err(e) => eprintln!("{} Optimization Audit Failed: {}", "✖".red(), e),
    }
    Ok(())
}

pub async fn run_batch_analysis(file_path: &str, grade: bool, ciphers: bool, json_dir: Option<String>) -> Result<()> {
    let file = File::open(file_path)?;
    let reader = std::io::BufReader::new(file);
    let mut success = 0;
    let mut fail = 0;

    println!("{} Starting Batch Audit from {}...", "🚀".cyan(), file_path.bold());

    for line in std::io::BufRead::lines(reader) {
        let host = line?.trim().to_string();
        if host.is_empty() { continue; }
        let json_path = json_dir.as_ref().map(|d| format!("{}/report_{}.json", d, host.replace(".", "_")));
        if run_analysis(&host, grade, ciphers, json_path).await.is_ok() { success += 1; } else { fail += 1; }
    }

    println!("\n{}", "--- Batch Summary ---".bold().cyan());
    println!("Total Success : {}", success.to_string().green());
    println!("Total Failed  : {}", fail.to_string().red());
    Ok(())
}
