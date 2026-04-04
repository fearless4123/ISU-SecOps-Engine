use clap::{Parser, CommandFactory};
use colored::*;

mod ssl_check;

#[derive(Parser)]
#[command(name = "secops")]
#[command(author = "Antigravity Security")]
#[command(version = "0.1.0")]
#[command(about = "ISU SecOps Engine - Professional SSL/TLS Security Auditor", long_about = None)]
struct Cli {
    /// Target host to audit (e.g., google.com)
    #[arg(value_name = "HOST")]
    host: Option<String>,

    /// Calculate and display security grade (A-F)
    #[arg(short, long)]
    grade: bool,

    /// Enumerate all supported cipher suites (Active probing)
    #[arg(short, long)]
    ciphers: bool,

    /// Export the full analysis to a JSON file
    #[arg(short, long, value_name = "FILE")]
    json: Option<String>,

    /// Scan multiple hosts from a file (one host per line)
    #[arg(short, long, value_name = "FILE")]
    file: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(target) = cli.host {
        ssl_check::run_analysis(&target, cli.grade, cli.ciphers, cli.json).await?;
    } else if let Some(path) = cli.file {
        ssl_check::run_batch_analysis(&path, cli.grade, cli.ciphers, cli.json).await?;
    } else {
        Cli::command().print_help()?;
        println!("\n\n{} Usage: cargo run -- <HOST> [OPTIONS]", "💡".yellow());
        println!("{} Example: cargo run -- google.com --grade", "🚀".cyan());
    }

    Ok(())
}
