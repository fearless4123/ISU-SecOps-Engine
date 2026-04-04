use clap::{Parser, Subcommand};
use colored::*;

mod ssl_check;
mod web_ui;

#[derive(Parser)]
#[command(name = "secops")]
#[command(about = "ISU SecOps Engine - SSL/TLS Security Analyzer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Pentest modules
    Pentest {
        #[command(subcommand)]
        action: PentestCommands,
    },
    /// Start the Web User Interface
    WebUi {
        /// Port to run the web server on
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum PentestCommands {
    /// SSL/TLS certificate and configuration analysis
    SslCheck {
        /// Target host (optional if --file is provided)
        host: Option<String>,

        /// Calculate and display security grade (A-F)
        #[arg(long)]
        grade: bool,

        /// Enumerate all supported cipher suites
        #[arg(long)]
        ciphers: bool,

        /// Export the full analysis to a JSON file
        #[arg(long, value_name = "FILE")]
        json: Option<String>,

        /// Scan multiple hosts from a file (one host per line)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pentest { action } => match action {
            PentestCommands::SslCheck { host, grade, ciphers, json, file } => {
                if let Some(target) = host {
                    println!("{} Single Audit for {}...", "ℹ".blue(), target.bold());
                    ssl_check::run_analysis(&target, grade, ciphers, json).await?;
                } else if let Some(path) = file {
                    println!("{} Batch Audit from {}...", "ℹ".blue(), path.bold());
                    ssl_check::run_batch_analysis(&path, grade, ciphers, json).await?;
                } else {
                    eprintln!("{} Error: Must provide either a <host> or --file <FILE>.", "✖".red());
                    std::process::exit(1);
                }
            }
        },
        Commands::WebUi { port } => {
            println!("{} Initializing SecOps Web Engine...", "⚡".cyan());
            web_ui::start_server(port).await?;
        }
    }

    Ok(())
}
