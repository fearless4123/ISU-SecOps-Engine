use clap::{Parser, Subcommand};
use colored::*;

mod ssl_check;
mod web_ui;
mod subdomain;
mod http_audit;
mod port_scan;
mod fuzzer;
mod mail_audit;
mod recon;
mod cms;

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
    /// Subdomain enumeration (wordlist based)
    SubEnum {
        /// Target domain (e.g., example.com)
        domain: String,
    },
    /// HTTP security header audit
    HttpHeaders {
        /// Target URL (e.g., https://google.com)
        url: String,
    },
    /// Port scanning and service discovery
    PortScan {
        /// Target host (e.g., 127.0.0.1)
        host: String,
    },
    /// Web directory and file discovery (Fuzzing)
    Fuzz {
        /// Target base URL (e.g., https://example.com)
        url: String,
    },
    /// Email spoofing audit (SPF/DMARC)
    MailAudit {
        /// Target domain (e.g., example.com)
        domain: String,
    },
    /// Information gathering (WHOIS & Geolocation)
    Recon {
        /// Target domain or IP (e.g., google.com)
        target: String,
    },
    /// CMS type and version detection
    CmsDetect {
        /// Target URL (e.g., https://wordpress.org)
        url: String,
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
            PentestCommands::SubEnum { domain } => {
                subdomain::run_sub_enum(&domain).await?;
            }
            PentestCommands::HttpHeaders { url } => {
                http_audit::run_http_audit(&url).await?;
            }
            PentestCommands::PortScan { host } => {
                port_scan::run_port_scan(&host).await?;
            }
            PentestCommands::Fuzz { url } => {
                fuzzer::run_fuzz(&url).await?;
            }
            PentestCommands::MailAudit { domain } => {
                mail_audit::run_mail_audit(&domain).await?;
            }
            PentestCommands::Recon { target } => {
                recon::run_recon_module(&target).await?;
            }
            PentestCommands::CmsDetect { url } => {
                cms::run_cms_detect(&url).await?;
            }
        },
        Commands::WebUi { port } => {
            println!("{} Initializing SecOps Web Engine...", "⚡".cyan());
            web_ui::start_server(port).await?;
        }
    }

    Ok(())
}
