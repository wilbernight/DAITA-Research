//! The `ephemeralpeer.EphemeralPeer` gRPC service that the app calls on the relay's gateway
//! address (`10.64.0.1:1337` by default) from inside the tunnel.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::{
    defenses::Releases,
    peers::{Peers, Registration},
    pq,
    proto::{
        DaitaPlatform, DaitaResponseV2, EphemeralPeerRequestV1, EphemeralPeerResponseV1,
        PostQuantumResponseV1, ephemeral_peer_server::EphemeralPeer,
    },
    uapi::DaitaPeerSettings,
};

/// The only DAITA protocol version current clients speak.
const DAITA_VERSION: u32 = 2;
// Same queue settings the app applies on its side.
const MAX_DELAYED_PACKETS: usize = 1024;
const MIN_DELAY_CAPACITY: usize = 50;

pub struct Service {
    pub peers: Arc<Peers>,
    pub releases: Arc<Releases>,
}

fn key(bytes: &[u8], what: &str) -> Result<[u8; 32], Status> {
    bytes
        .try_into()
        .map_err(|_| Status::invalid_argument(format!("{what} must be 32 bytes")))
}

#[tonic::async_trait]
impl EphemeralPeer for Service {
    async fn register_peer_v1(
        &self,
        request: Request<EphemeralPeerRequestV1>,
    ) -> Result<Response<EphemeralPeerResponseV1>, Status> {
        let source = request
            .remote_addr()
            .ok_or_else(|| Status::internal("no remote address"))?
            .ip();
        let request = request.into_inner();
        let parent = key(&request.wg_parent_pubkey, "wg_parent_pubkey")?;
        let ephemeral = key(&request.wg_ephemeral_peer_pubkey, "wg_ephemeral_peer_pubkey")?;

        if request.daita.is_some() && request.daita_v2.is_none() {
            return Err(Status::invalid_argument("DAITA v1 is not supported; update the app"));
        }

        let pq = match &request.post_quantum {
            Some(pq) => Some(
                pq::encapsulate_all(&pq.kem_pubkeys)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?,
            ),
            None => None,
        };

        let (daita_peer, daita_response) = match &request.daita_v2 {
            Some(req) => {
                if req.version != DAITA_VERSION {
                    return Err(Status::invalid_argument(format!(
                        "unsupported DAITA version {}",
                        req.version
                    )));
                }
                let platform = DaitaPlatform::try_from(req.platform)
                    .unwrap_or(DaitaPlatform::Undefined)
                    .as_str_name();
                let chosen = self
                    .releases
                    .choose(platform, &mut rand::thread_rng())
                    .ok_or_else(|| Status::unavailable("no DAITA defenses for this platform"))?;
                let peer = DaitaPeerSettings {
                    machines: chosen.server_machines,
                    max_decoy_frac: chosen.server_padding_frac,
                    max_delay_frac: chosen.server_blocking_frac,
                    max_delayed_packets: MAX_DELAYED_PACKETS,
                    min_delay_capacity: MIN_DELAY_CAPACITY,
                };
                let response = DaitaResponseV2 {
                    client_machines: chosen.client_machines.to_vec(),
                    max_padding_frac: chosen.client_padding_frac,
                    max_blocking_frac: chosen.client_blocking_frac,
                };
                (Some(peer), Some(response))
            }
            None => (None, None),
        };

        self.peers
            .register(Registration {
                parent,
                ephemeral,
                source,
                psk: pq.as_ref().map(|pq| &*pq.psk),
                daita: daita_peer,
            })
            .await
            .map_err(|e| {
                log::warn!("register from {source} failed: {e:#}");
                Status::failed_precondition(e.to_string())
            })?;

        log::info!(
            "ephemeral peer for {source}: pq={} daita={}",
            pq.is_some(),
            daita_response.is_some()
        );
        Ok(Response::new(EphemeralPeerResponseV1 {
            post_quantum: pq.map(|pq| PostQuantumResponseV1 {
                ciphertexts: pq.ciphertexts,
            }),
            daita: daita_response,
        }))
    }
}
