use clap::{Parser, Subcommand};
use colored::*;
use dialoguer::{Input, Select, theme::ColorfulTheme};

mod ssl_check;
mod web_ui;

#[derive(Parser)]
#[command(name = "aegis-tls")]
#[command(author = "Aegis Security Team")]
#[command(version = "1.0.0")]
#[command(about = "🛡️ AegisTLS - Profesyonel SSL/TLS Pentest Platformu", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Terminal üzerinden hızlı tarama başlatır
    Cli {
        /// Hedef domain adı (örn: google.com)
        host: String,
        /// Güvenlik puanını hesaplasın mı?
        #[arg(short, long)]
        grade: bool,
    },
    /// Web Dashboard arayüzünü başlatır
    Web {
        /// Port numarası (Varsayılan: 8080)
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
    /// İnteraktif Sihirbaz moduna geçer
    Wizard,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Cli { host, grade }) => {
            ssl_check::run_analysis(&host, grade, false, None).await?;
        }
        Some(Commands::Web { port }) => {
            web_ui::start_server(port).await?;
        }
        Some(Commands::Wizard) | None => {
            run_wizard().await?;
        }
    }

    Ok(())
}

async fn run_wizard() -> anyhow::Result<()> {
    println!(
        "\n{}",
        "🛡️  AegisTLS - İnteraktif Sihirbaz".bold().bright_cyan()
    );

    let selections = &[
        "🔍 Hızlı Tarama (Domain)",
        "🌐 Web Dashboard Başlat",
        "🚪 Çıkış",
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Ne yapmak istersiniz?")
        .default(0)
        .items(&selections[..])
        .interact()?;

    match selection {
        0 => {
            let host: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Hedef Host (örn: google.com)")
                .interact_text()?;
            ssl_check::run_analysis(&host, true, false, None).await?;
        }
        1 => {
            web_ui::start_server(8080).await?;
        }
        _ => println!("Hoşça kalın!"),
    }

    Ok(())
}
