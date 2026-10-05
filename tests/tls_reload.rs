//! A certificate replaced on disk reaches clients without a restart, checked
//! with real TLS handshakes against a listener.

use std::net::SocketAddr;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use certstream_server_rust::tls::reload_when_files_change;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use tokio_util::sync::CancellationToken;

struct Pki {
    ca_pem: String,
    leaf_pem: String,
    leaf_key_pem: String,
}

fn pki(name: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &Issuer::new(ca_params, ca_key))
        .unwrap();
    Pki {
        ca_pem: ca.pem(),
        leaf_pem: leaf.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
    }
}

/// Whether a client that trusts only `ca_pem` completes a handshake.
async fn handshake_ok(addr: SocketAddr, ca_pem: &str) -> bool {
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .resolve("localhost", addr)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    client
        .get(format!("https://localhost:{}/", addr.port()))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_certificate_is_served_without_a_restart() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let before = pki("before");
    let after = pki("after");

    let dir = std::env::temp_dir().join(format!("certstream-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem").to_string_lossy().into_owned();
    let key = dir.join("key.pem").to_string_lossy().into_owned();
    std::fs::write(&cert, &before.leaf_pem).unwrap();
    std::fs::write(&key, &before.leaf_key_pem).unwrap();

    let config = RustlsConfig::from_pem_file(&cert, &key).await.unwrap();
    let handle = axum_server::Handle::new();
    let app = Router::new().route("/", get(|| async { "ok" }));
    tokio::spawn({
        let handle = handle.clone();
        let config = config.clone();
        async move {
            axum_server::bind_rustls("127.0.0.1:0".parse().unwrap(), config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .unwrap();
        }
    });
    let addr = handle.listening().await.unwrap();

    let cancel = CancellationToken::new();
    tokio::spawn(reload_when_files_change(
        config,
        cert.clone(),
        key.clone(),
        Duration::from_millis(50),
        cancel.clone(),
    ));

    assert!(handshake_ok(addr, &before.ca_pem).await, "the first certificate must work");
    assert!(!handshake_ok(addr, &after.ca_pem).await);

    tokio::time::sleep(Duration::from_millis(100)).await;
    std::fs::write(&cert, &after.leaf_pem).unwrap();
    std::fs::write(&key, &after.leaf_key_pem).unwrap();

    let mut reloaded = false;
    for _ in 0..50 {
        if handshake_ok(addr, &after.ca_pem).await {
            reloaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(reloaded, "the replaced certificate must be served");
    assert!(
        !handshake_ok(addr, &before.ca_pem).await,
        "the old certificate must no longer be served"
    );

    cancel.cancel();
    handle.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
