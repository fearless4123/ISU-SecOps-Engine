use crate::ssl_check::scanner::perform_analysis;
use axum::{Json, Router, extract::Path, response::Html, routing::get};
use colored::Colorize;
use rust_embed::RustEmbed;
use serde_json::json;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

#[derive(RustEmbed)]
#[folder = "src/web_ui/static/"]
struct Assets;

pub async fn start_server(port: u16) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/scan/:host", get(scan_handler))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!(
        "\n{} {} {}",
        "⚡".yellow(),
        "AegisTLS Dashboard:".bold().cyan(),
        format!("http://{}", addr).underline().white()
    );
    axum::serve(listener, app).await?;

    Ok(())
}

async fn index_handler() -> Html<String> {
    let index = match Assets::get("index.html") {
        Some(file) => file,
        None => return Html("<h1>Dashboard Error</h1><p>index.html not found in embedded assets.</p>".to_string()),
    };
    Html(String::from_utf8(index.data.to_vec()).unwrap_or_else(|_| "Decode Error".to_string()))
}

async fn scan_handler(Path(host): Path<String>) -> Json<serde_json::Value> {
    match perform_analysis(&host, false).await {
        Ok(analysis) => Json(json!(analysis)),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}
