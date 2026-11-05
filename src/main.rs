//! Disk Cleaner MCP Server — entry point.
//!
//! Serves MCP protocol over stdio. Run as a binary, connect from any MCP client
//! (Hermes, Claude, Cursor, OpenClaw, etc.).

mod analytics;
mod brain;
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
