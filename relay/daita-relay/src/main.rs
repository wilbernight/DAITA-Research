mod defenses;
mod peers;
mod pq;
mod service;
mod uapi;

mod proto {
    tonic::include_proto!("ephemeralpeer");
}

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser;
use tonic::transport::Server;

#[derive(Parser)]
#[command(about = "Relay-side PQ + DAITA v2 ephemeral peer service for gotatun")]
struct Args {
    /// Address of the config service inside the tunnel.
    #[arg(long, default_value = "10.64.0.1:1337")]
    listen: SocketAddr,
    /// gotatun UAPI socket of the WireGuard interface.
    #[arg(long, default_value = "/var/run/wireguard/wg0.sock")]
    uapi_socket: PathBuf,
    /// Directory of DAITA release JSON files (output of `maybenot release`).
    #[arg(long, default_value = "/etc/daita-relay/defenses")]
    defenses: PathBuf,
    /// How often to check handshakes and move addresses between parent and ephemeral peers.
    #[arg(long, default_value_t = 100)]
    poll_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let releases = Arc::new(defenses::Releases::load_dir(&args.defenses)?);
    let peers = Arc::new(peers::Peers::new(uapi::Uapi::new(&args.uapi_socket)));

    let poller = peers.clone();
    let poll = Duration::from_millis(args.poll_ms);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(poll);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(e) = poller.reconcile().await {
                log::error!("reconcile: {e:#}");
            }
        }
    });

    log::info!("listening on {}", args.listen);
    Server::builder()
        .add_service(proto::ephemeral_peer_server::EphemeralPeerServer::new(
            service::Service { peers, releases },
        ))
        .serve_with_shutdown(args.listen, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
