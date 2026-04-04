use crate::ssl_check::scanner::perform_analysis;
use anyhow::Result;
use colored::*;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::*;
use std::fs::File;
use std::io::Write;

pub mod models;
pub mod scanner;

pub async fn run_analysis(
    host: &str,
    show_grade: bool,
    probe_ciphers: bool,
    json_path: Option<String>,
) -> Result<()> {
    match perform_analysis(host, probe_ciphers).await {
        Ok(analysis) => {
            println!(
                "\n{}",
                format!("🛡️  AegisTLS - Denetim Raporu: {}", host)
                    .bold()
                    .bright_cyan()
            );

            // 1. İstihbarat Tablosu
            let mut intel_table = Table::new();
            intel_table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("Özellik")
                        .add_attribute(Attribute::Bold)
                        .fg(comfy_table::Color::Cyan),
                    Cell::new("Değer")
                        .add_attribute(Attribute::Bold)
                        .fg(comfy_table::Color::Cyan),
                ]);

            if let Some(ref geo) = analysis.geo_info {
                intel_table.add_row(vec!["Sunucu IP", &geo.query]);
                intel_table.add_row(vec!["Konum", &format!("{}, {}", geo.city, geo.country)]);
                intel_table.add_row(vec![
                    "Servis Sağlayıcı (ISP)",
                    &format!("{} ({})", geo.isp, geo.as_num),
                ]);
            }
            println!("\n{}", "📡 KÜRESEL İSTİHBARAT".bold().yellow());
            println!("{intel_table}");

            // 2. Sertifika Tablosu
            let mut cert_table = Table::new();
            cert_table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("Sertifika Metriği")
                        .add_attribute(Attribute::Bold)
                        .fg(comfy_table::Color::Cyan),
                    Cell::new("Durum")
                        .add_attribute(Attribute::Bold)
                        .fg(comfy_table::Color::Cyan),
                ]);

            if let Some(ref cert) = analysis.certificate {
                cert_table.add_row(vec!["Ortak Ad (Common Name)", &cert.common_name]);
                let validity = if cert.is_valid {
                    "GEÇERLİ".green().to_string()
                } else {
                    "GEÇERSİZ".red().to_string()
                };
                cert_table.add_row(vec!["Güven Zinciri", &validity]);
                let ct = if cert.ct_logged {
                    "KAYITLI (Safe)".green().to_string()
                } else {
                    "KAYITSIZ (Risk)".red().to_string()
                };
                cert_table.add_row(vec!["Şeffaflık (CT)", &ct]);
                let hsts = if cert.hsts_enabled {
                    "AKTİF".green().to_string()
                } else {
                    "PASİF".yellow().to_string()
                };
                cert_table.add_row(vec!["HSTS Politikası", &hsts]);
            }
            println!("\n{}", "📜 SERTİFİKA ANALİTİĞİ".bold().yellow());
            println!("{cert_table}");

            // 3. Zafiyetler
            if !analysis.vulnerabilities.is_empty() {
                println!("\n{}", "🚨 ZAFİYET DEĞERLENDİRMESİ".bold().red());
                for v in &analysis.vulnerabilities {
                    println!("  {} {}", "✖".red(), v.bright_red());
                }
            } else {
                println!(
                    "\n{} Herhangi bir kritik zafiyet (POODLE vb.) tespit edilmedi.",
                    "✅".green()
                );
            }

            // 4. Güvenlik Puanı
            if show_grade {
                let color = if analysis.grade.contains('A') {
                    comfy_table::Color::Green
                } else if analysis.grade.contains('B') {
                    comfy_table::Color::Cyan
                } else {
                    comfy_table::Color::Red
                };
                let mut grade_table = Table::new();
                grade_table
                    .load_preset(UTF8_FULL)
                    .apply_modifier(UTF8_ROUND_CORNERS);
                grade_table.add_row(vec![
                    Cell::new("FİNAL GÜVENLİK PUANI").add_attribute(Attribute::Bold),
                    Cell::new(&analysis.grade)
                        .add_attribute(Attribute::Bold)
                        .fg(color),
                ]);
                println!("\n{grade_table}");
            }

            if let Some(path) = json_path {
                let data = serde_json::to_string_pretty(&analysis)?;
                File::create(&path)?.write_all(data.as_bytes())?;
                println!(
                    "\n{} Exported full report to: {}",
                    "💾".green(),
                    path.bold().cyan()
                );
            }
        }
        Err(e) => eprintln!("{} Optimization Audit Failed: {}", "✖".red(), e),
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn run_batch_analysis(
    file_path: &str,
    grade: bool,
    ciphers: bool,
    json_dir: Option<String>,
) -> Result<()> {
    let file = File::open(file_path)?;
    let reader = std::io::BufReader::new(file);
    let mut success = 0;
    let mut fail = 0;

    println!(
        "{} Starting Batch Audit from {}...",
        "🚀".cyan(),
        file_path.bold()
    );

    for line in std::io::BufRead::lines(reader) {
        let host = line?.trim().to_string();
        if host.is_empty() {
            continue;
        }
        let json_path = json_dir
            .as_ref()
            .map(|d| format!("{}/report_{}.json", d, host.replace(".", "_")));
        if run_analysis(&host, grade, ciphers, json_path).await.is_ok() {
            success += 1;
        } else {
            fail += 1;
        }
    }

    println!("\n{}", "--- Batch Summary ---".bold().cyan());
    println!("Total Success : {}", success.to_string().green());
    println!("Total Failed  : {}", fail.to_string().red());
    Ok(())
}
