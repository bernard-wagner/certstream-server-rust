//! Certificate rotation for the TLS listener.

use axum_server::tls_rustls::RustlsConfig;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// An ACME client replaces the certificate files every couple of months, and
/// `RustlsConfig` read them once, so the old certificate stayed in use until the
/// process restarted. Polls the modification times of both files and reloads
/// when either changes. A reload that fails, a pair caught half written for
/// instance, keeps the certificate in use and is tried again on the next poll.
pub async fn reload_when_files_change(
    config: RustlsConfig,
    cert: String,
    key: String,
    every: Duration,
    cancel: CancellationToken,
) {
    let mut seen = modified(&cert, &key).await;
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tick.tick() => {}
        }
        let now = modified(&cert, &key).await;
        if now == seen {
            continue;
        }
        match config.reload_from_pem_file(&cert, &key).await {
            Ok(()) => {
                seen = now;
                info!(cert = %cert, "TLS certificate reloaded");
            }
            Err(e) => warn!(
                cert = %cert,
                error = %e,
                "TLS certificate changed but could not be loaded; keeping the current one"
            ),
        }
    }
}

async fn modified(cert: &str, key: &str) -> Option<(SystemTime, SystemTime)> {
    let time = |path: String| async move { tokio::fs::metadata(path).await.ok()?.modified().ok() };
    Some((time(cert.to_string()).await?, time(key.to_string()).await?))
}
