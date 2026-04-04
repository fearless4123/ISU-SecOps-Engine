use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::net::SocketAddr;
use crate::ssl_check::scanner::perform_analysis;

#[derive(RustEmbed)]
#[folder = "src/web_ui/static/"]
struct Assets;

#[derive(Deserialize)]
pub struct ScanParams {
    pub host: String,
}

pub async fn start_server(port: u16) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/scan/ssl", get(ssl_scan_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("🚀 Web UI running at http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn index_handler() -> impl IntoResponse {
    let index_file = Assets::get("index.html").expect("index.html not found");
    Html(index_file.data)
}

async fn ssl_scan_handler(Query(params): Query<ScanParams>) -> Response {
    // For the Web UI, we always perform the full audit including cipher probing
    match perform_analysis(&params.host, true).await {
        Ok(analysis) => Json(analysis).into_response(),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}
