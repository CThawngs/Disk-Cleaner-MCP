//! Disk Cleaner MCP Server — entry point.
//!
//! Serves MCP protocol over stdio. Run as a binary, connect from any MCP client
//! (Hermes, Claude, Cursor, OpenClaw, etc.).

mod analytics;
mod brain;
mod config;
mod engine;
mod insights;
mod model;
mod safety;
mod server;
mod sysinfo_helper;

use rmcp::ServiceExt;
use server::DiskCleanerServer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing (logs go to stderr, not stdout — stdout is for MCP)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("disk_cleaner_mcp=info".parse()?),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting Disk Cleaner MCP Server v{}", model::VERSION);

    // Optional HTTP mode (feature "http"): `disk-cleaner-mcp --http [PORT]`
    // serves Streamable HTTP on loopback only (default 8000) — stdio default.
    #[cfg(feature = "http")]
    if let Some(port) = http_port_arg() {
        return run_http(port).await;
    }

    let server = DiskCleanerServer::new();

    // Serve over stdio (MCP standard transport)
    let transport = rmcp::transport::stdio();

    match server.serve(transport).await {
        Ok(running) => {
            tracing::info!("MCP server started, waiting for connections...");
            running.waiting().await?;
            tracing::info!("MCP server shutdown complete");
        }
        Err(e) => {
            tracing::error!("Failed to start MCP server: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

/// Parse `--http [PORT]` / `--http=PORT` (None = stdio mode).
#[cfg(feature = "http")]
fn http_port_arg() -> Option<u16> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--http" {
            return args.next().and_then(|p| p.parse().ok()).or(Some(8000));
        }
        if let Some(p) = a.strip_prefix("--http=") {
            return p.parse().ok().or(Some(8000));
        }
    }
    None
}

/// Serve MCP over Streamable HTTP, bound to loopback only.
#[cfg(feature = "http")]
async fn run_http(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;

    let service = StreamableHttpService::new(
        || Ok(DiskCleanerServer::new()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let app = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tracing::info!("MCP Streamable HTTP on http://127.0.0.1:{port}/mcp (loopback only)");
    axum::serve(listener, app).await?;
    Ok(())
}
