use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tokio::net::TcpListener;
use vouchkit_server::{ActivationServer, MemoryActivationStore, ServerConfig};

const DEFAULT_STORAGE: &str = if cfg!(feature = "sqlite") {
    "sqlite"
} else {
    "memory"
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Storage {
    #[cfg(feature = "sqlite")]
    Sqlite,
    Memory,
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Path to the activation server's TOML configuration.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
    /// Storage backend for activation state.
    #[arg(long, value_enum, default_value = DEFAULT_STORAGE)]
    storage: Storage,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = ServerConfig::load(&args.config)
        .with_context(|| format!("loading configuration from {}", args.config.display()))?;
    let server = match args.storage {
        #[cfg(feature = "sqlite")]
        Storage::Sqlite => ActivationServer::load(&config)?,
        Storage::Memory => {
            tracing::warn!("memory storage is process-local and resets on restart");
            ActivationServer::load_with_store(&config, MemoryActivationStore::new())?
        }
    };
    let listener = TcpListener::bind(config.listen()).await?;
    tracing::info!(listen = %listener.local_addr()?, "activation service listening");

    let maintenance = tokio::spawn(maintain(
        server.clone(),
        config.crl_path().map(PathBuf::from),
    ));
    let result = axum::serve(
        listener,
        server
            .router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await;
    maintenance.abort();
    result.context("serving activation requests")
}

async fn maintain(server: ActivationServer, crl_path: Option<PathBuf>) {
    let mut daily = tokio::time::interval(Duration::from_secs(86_400));
    daily.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut poll = tokio::time::interval(Duration::from_secs(30));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = daily.tick() => {
                let server = server.clone();
                let result = tokio::task::spawn_blocking(move || {
                    server.warn_if_certificate_expiring()
                }).await;
                if !matches!(result, Ok(Ok(()))) {
                    tracing::warn!("could not determine delegation certificate health");
                }
            },
            _ = poll.tick(), if crl_path.is_some() => {
                if let Some(path) = crl_path.clone() {
                    let server = server.clone();
                    let result = tokio::task::spawn_blocking(move || server.install_crl_file(&path)).await;
                    match result {
                        Ok(Ok(true)) => tracing::info!("installed a new signed revocation list"),
                        Ok(Ok(false)) => {}
                        Ok(Err(error)) => tracing::warn!(%error, "could not update signed revocation list"),
                        Err(_) => tracing::warn!("revocation list worker unavailable"),
                    }
                }
            },
        }
    }
}

async fn shutdown() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        return;
    }
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "could not listen for shutdown signal");
        std::future::pending::<()>().await;
    }
}
