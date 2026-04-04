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
mod vulnerability;
mod db;

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
    /// View scan history from the local database
    History,
}

#[derive(Subcommand)]
enum PentestCommands {
    /// SSL/TLS certificate and configuration analysis
    SslCheck { host: String, #[arg(long)] grade: bool },
    /// Subdomain enumeration (wordlist based)
    SubEnum { domain: String },
    /// HTTP security header audit
    HttpHeaders { url: String },
    /// Port scanning and service discovery
    PortScan { host: String },
    /// Web directory and file discovery (Fuzzing)
    Fuzz { url: String },
    /// Email spoofing audit (SPF/DMARC)
    MailAudit { domain: String },
    /// Information gathering (WHOIS & Geolocation)
    Recon { target: String },
    /// CMS type and version detection
    CmsDetect { url: String },
    /// Basic CVE lookup for a service and version
    CveCheck { product: String, version: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize Database
    let _ = db::setup_db();
    
    let cli = Cli::parse();

    match cli.command {
        Commands::Pentest { action } => match action {
            PentestCommands::SslCheck { host, grade } => {
                println!("{} Analyzing SSL/TLS for {}...", "ℹ".blue(), host.bold());
                ssl_check::run_analysis(&host, grade).await?;
                let _ = db::log_scan("SSL Check", &host);
            }
            PentestCommands::SubEnum { domain } => {
                subdomain::run_sub_enum(&domain).await?;
                let _ = db::log_scan("Subdomain Enum", &domain);
            }
            PentestCommands::HttpHeaders { url } => {
                http_audit::run_http_audit(&url).await?;
                let _ = db::log_scan("HTTP Headers", &url);
            }
            PentestCommands::PortScan { host } => {
                port_scan::run_port_scan(&host).await?;
                let _ = db::log_scan("Port Scan", &host);
            }
            PentestCommands::Fuzz { url } => {
                fuzzer::run_fuzz(&url).await?;
                let _ = db::log_scan("Web Fuzzing", &url);
            }
            PentestCommands::MailAudit { domain } => {
                mail_audit::run_mail_audit(&domain).await?;
                let _ = db::log_scan("Email Audit", &domain);
            }
            PentestCommands::Recon { target } => {
                recon::run_recon_module(&target).await?;
                let _ = db::log_scan("Reconnaissance", &target);
            }
            PentestCommands::CmsDetect { url } => {
                cms::run_cms_detect(&url).await?;
                let _ = db::log_scan("CMS Detect", &url);
            }
            PentestCommands::CveCheck { product, version } => {
                vulnerability::run_cve_check(&product, &version).await?;
                let _ = db::log_scan("CVE Check", &format!("{} {}", product, version));
            }
        },
        Commands::WebUi { port } => {
            println!("{} Initializing SecOps Web Engine...", "⚡".cyan());
            web_ui::start_server(port).await?;
        }
        Commands::History => {
            println!("{} Fetching scan history...", "📚".cyan());
            match db::get_history() {
                Ok(history) => {
                    println!("\n{}", "--- Scan History ---".bold().green());
                    println!("{:<5} | {:<25} | {:<15} | {:<20}", "ID", "Timestamp", "Module", "Target");
                    println!("{}", "-".repeat(75));
                    for h in history {
                        println!("{:<5} | {:<25} | {:<15} | {:<20}", 
                            h.id.to_string().dimmed(), h.timestamp.cyan(), h.module.yellow(), h.target.bold());
                    }
                }
                Err(e) => eprintln!("{} Failed to fetch history: {}", "✖".red(), e),
            }
        }
    }

    Ok(())
}
