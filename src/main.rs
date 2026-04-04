use clap::{Parser, Subcommand};
use colored::*;

mod ssl_check;
mod web_ui;

#[derive(Parser)]
#[command(name = "secops")]
#[command(about = "ISU SecOps Engine - Security Auditing Tool", long_about = None)]
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
        /// Target host (e.g., example.com)
        host: String,

        /// Calculate and display security grade (A-F)
        #[arg(long)]
        grade: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pentest { action } => match action {
            PentestCommands::SslCheck { host, grade } => {
                println!("{} Analyzing SSL/TLS for {}...", "ℹ".blue(), host.bold());
                ssl_check::run_analysis(&host, grade).await?;
            }
        },
        Commands::WebUi { port } => {
            println!("{} Initializing SecOps Web Engine...", "⚡".cyan());
            web_ui::start_server(port).await?;
        }
    }

    Ok(())
}
