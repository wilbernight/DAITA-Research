//! Parent/ephemeral peer pairs.
//!
//! The proto requires the two peers of a pair to be mutually exclusive: whichever handshook most
//! recently owns the tunnel addresses. WireGuard routes by allowed IPs, so "owning" means holding
//! the parent's allowed IPs; a poll loop watches handshake times and moves them atomically.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tokio::sync::Mutex;

use crate::uapi::{self, DaitaPeerSettings, PeerInfo, Uapi};

/// An ephemeral peer that never handshakes is dropped after this long.
const UNUSED_EPHEMERAL_TTL: Duration = Duration::from_secs(300);

/// Where the parent↔ephemeral pairs are persisted between relay restarts.
/// Without this, a restart that loses the in-memory map strands the tunnel
/// addresses on an orphaned ephemeral peer: the next client SYN-ACK then
/// routes to a dead session and the gRPC register can never be reached.
const PAIRS_FILE: &str = "/var/lib/daita/pairs.json";

/// Wall-clock age of a UAPI `(sec, nsec)` handshake timestamp.
fn handshake_age(hs: (u64, u64)) -> Duration {
    let hs_time = std::time::SystemTime::UNIX_EPOCH + Duration::new(hs.0, hs.1 as u32);
    std::time::SystemTime::now()
        .duration_since(hs_time)
        .unwrap_or(Duration::ZERO)
}

/// Half-open IPv4 connections to the relay's own port in `SYN-RECV`, as a
/// set of little-endian `/proc/net/tcp` source addresses. A half-open SYN
/// from inside a pair's allowed-ips is a client trying to reach the relay
/// THROUGH the parent — its SYN-ACK is meanwhile being routed to whichever
/// peer owns the source address.
///
/// Only state `03` counts. `04` is FIN_WAIT1: the register connection the
/// client just finished lingers there for ~70s while the relay's FIN
/// retransmits, and matching it released every fresh ephemeral ~2s after
/// the switch. Other ports (DNS over TCP to the gateway, ...) are ignored
/// for the same reason: only a new connection to the relay means reconnect.
///
/// The SYN-ACK must also have been retransmitted at least once. The client
/// itself SYNs the relay right after switching (to force the ephemeral
/// handshake); that SYN-ACK goes to the live ephemeral and is answered
/// within one RTT. A SYN-ACK still unanswered after a full RTO (~1s) is
/// the one being routed to a dead peer.
fn syn_recv_sources(listen_port: u16) -> HashMap<u32, ()> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string("/proc/net/tcp") else {
        return out;
    };
    let local_port = format!(":{listen_port:04X}");
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 7 {
            continue;
        }
        if f[3] != "03" {
            continue; // 03 = TCP_SYN_RECV
        }
        if !f[1].ends_with(&local_port) {
            continue;
        }
        // `retrnsmt` = SYN-ACK retransmissions of this request socket
        if u32::from_str_radix(f[6], 16).unwrap_or(0) == 0 {
            continue;
        }
        let Some((ip, _)) = f[2].rsplit_once(':') else { continue };
        if ip.len() != 8 {
            continue;
        }
        let byte = |i: usize| u8::from_str_radix(&ip[i..i + 2], 16).unwrap_or(0);
        // /proc/net/tcp stores the address little-endian: AABBCCDD → D.C.B.A
        let src = u32::from(byte(6)) << 24 | u32::from(byte(4)) << 16
            | u32::from(byte(2)) << 8 | u32::from(byte(0));
        out.insert(src, ());
    }
    out
}

/// Persist the pair map. Best-effort: a write failure only costs restart
/// resilience, never the data path.
fn save_pairs(pairs: &HashMap<String, Pair>) {
    let path = std::path::Path::new(PAIRS_FILE);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match serde_json::to_string(pairs) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                log::warn!("persisting {PAIRS_FILE} failed: {e}");
            }
        }
        Err(e) => log::warn!("serializing pairs failed: {e}"),
    }
}

/// Restore the pair map at startup. A missing or corrupt file just starts
/// the relay with an empty map (the pre-persistence behavior).
fn load_pairs() -> HashMap<String, Pair> {
    match std::fs::read_to_string(PAIRS_FILE) {
        Ok(text) => match serde_json::from_str::<HashMap<String, Pair>>(&text) {
            Ok(pairs) => {
                log::info!("restored {} peer pair(s) from {PAIRS_FILE}", pairs.len());
                pairs
            }
            Err(e) => {
                log::warn!("could not parse {PAIRS_FILE} — starting empty: {e}");
                HashMap::new()
            }
        },
        Err(_) => HashMap::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Active {
    Parent,
    Ephemeral,
}

/// A parent↔ephemeral pair. Persisted to [`PAIRS_FILE`] on every change so
/// a relay restart cannot lose track of who owns the tunnel addresses.
/// `created` is runtime-only: after a restart it resets to now, which only
/// re-arms the unused-ephemeral TTL.
#[derive(serde::Serialize, serde::Deserialize)]
struct Pair {
    ephemeral: String,
    allowed_ips: Vec<String>,
    active: Active,
    #[serde(skip, default = "Instant::now")]
    created: Instant,
    ever_handshook: bool,
    /// Reconnect latch: while `Instant::now()` is inside this window the pair
    /// stays with the PARENT regardless of the ephemeral grace. The SYN-RECV
    /// signal blinks in /proc/net/tcp, so without the latch a momentary miss
    /// flips the addresses back onto the dead ephemeral and blackholes the
    /// retry mid-handshake (observed live: reconnect SYN → Parent → 100ms
    /// later back to Ephemeral → the client still hung until TCP timeout).
    #[serde(skip)]
    reconnect_until: Option<Instant>,
    /// (rx_bytes, when they last changed) on the ephemeral peer. A live
    /// session's 25s keepalives keep this rolling; frozen bytes mean the
    /// session is dead.
    #[serde(skip)]
    eph_rx: Option<(u64, Instant)>,
}

pub struct Peers {
    uapi: Uapi,
    /// Port of the gRPC service; only SYNs to it signal a reconnect.
    listen_port: u16,
    pairs: Mutex<HashMap<String, Pair>>,
}

pub struct Registration<'a> {
    pub parent: [u8; 32],
    pub ephemeral: [u8; 32],
    pub source: IpAddr,
    pub psk: Option<&'a [u8; 32]>,
    pub daita: Option<DaitaPeerSettings<'a>>,
}

impl Peers {
    pub fn new(uapi: Uapi, listen_port: u16) -> Self {
        let pairs = load_pairs();
        Self {
            uapi,
            listen_port,
            pairs: Mutex::new(pairs),
        }
    }

    pub async fn register(&self, reg: Registration<'_>) -> Result<()> {
        let parent_hex = hex::encode(reg.parent);
        let ephemeral_hex = hex::encode(reg.ephemeral);
        if parent_hex == ephemeral_hex {
            bail!("ephemeral key equals parent key");
        }

        let mut pairs = self.pairs.lock().await;
        let device = self.uapi.peers().await?;
        let find = |key: &str| device.iter().find(|p| p.public_key == key);

        // A replaced pair hands its addresses back to the parent first.
        let allowed_ips = match pairs.remove(&parent_hex) {
            Some(old) => {
                if old.active == Active::Ephemeral {
                    self.uapi
                        .set(&uapi::move_allowed_ips(&old.ephemeral, &parent_hex, &old.allowed_ips))
                        .await?;
                }
                self.uapi.set(&uapi::remove_peer(&old.ephemeral)).await?;
                old.allowed_ips
            }
            None => find(&parent_hex)
                .context("parent key is not a peer on this relay")?
                .allowed_ips
                .clone(),
        };

        // The request travels inside the parent's tunnel, so its source address must be one of
        // the parent's. Otherwise any client could attach an ephemeral peer to someone else's key.
        if !allowed_ips.iter().any(|net| cidr_contains(net, reg.source)) {
            bail!("request from {} does not come from the parent's tunnel", reg.source);
        }
        if find(&ephemeral_hex).is_some() {
            bail!("ephemeral key is already in use");
        }

        self.uapi
            .set(&uapi::add_ephemeral_peer(&ephemeral_hex, reg.psk, reg.daita.as_ref()))
            .await?;
        pairs.insert(
            parent_hex,
            Pair {
                ephemeral: ephemeral_hex,
                allowed_ips,
                active: Active::Parent,
                created: Instant::now(),
                ever_handshook: false,
                reconnect_until: None,
                eph_rx: None,
            },
        );
        save_pairs(&pairs);
        Ok(())
    }

    /// One pass of the swap loop.
    pub async fn reconcile(&self) -> Result<()> {
        let mut pairs = self.pairs.lock().await;
        if pairs.is_empty() {
            return Ok(());
        }
        let device: HashMap<String, PeerInfo> = self
            .uapi
            .peers()
            .await?
            .into_iter()
            .map(|p| (p.public_key.clone(), p))
            .collect();

        // Reconnect detection: a half-open SYN from an address this pair
        // owns can only come through the PARENT tunnel — a client holding
        // the ephemeral key never SYNs a new relay connection. Seeing one
        // while the addresses sit on the ephemeral means the client
        // reconnected and the old ephemeral is dead; flip home NOW instead
        // of waiting out gotatun's dead-session window (that wait is what
        // made quick reconnects hang for minutes behind a dead peer).
        let syn_sources = syn_recv_sources(self.listen_port);

        let mut drop_pairs = Vec::new();
        let mut changed = false;
        for (parent, pair) in pairs.iter_mut() {
            if !device.contains_key(parent) {
                // The parent was revoked (key rotated or account removed): take the pair down.
                drop_pairs.push(parent.clone());
                continue;
            }
            let eph_info = device.get(&pair.ephemeral);
            let eph_hs = eph_info.map_or((0, 0), |p| p.last_handshake);
            pair.ever_handshook |= eph_hs != (0, 0);

            // Track inbound silence on the ephemeral: keepalives arrive every
            // 25s, so 30s without a byte change means nobody is there.
            let eph_silent = match (&mut pair.eph_rx, eph_info) {
                (Some((bytes, changed)), Some(info)) => {
                    if info.rx_bytes != *bytes {
                        *bytes = info.rx_bytes;
                        *changed = Instant::now();
                        false
                    } else {
                        changed.elapsed() >= Duration::from_secs(30)
                    }
                }
                (None, Some(info)) => {
                    pair.eph_rx = Some((info.rx_bytes, Instant::now()));
                    false // no baseline yet — judge from the next interval on
                }
                _ => false,
            };

            // Ownership follows the *ephemeral* handshake alone: only the
            // client holding the ephemeral key can produce one, and while it
            // is connected, WireGuard rekeys (REKEY_AFTER_TIME ≈ 120s, session
            // keys die at REJECT_AFTER_TIME = 180s) keep that timestamp
            // rolling. So a handshake within the last 240s means "the client
            // is on the ephemeral"; anything older means the session is
            // certainly dead and the addresses go home to the parent (the
            // stable identity the next client `up` starts from). Timestamp
            // comparisons between the two peers are useless here: after the
            // switch the parent never handshakes again, so "most recent
            // handshake" would keep the ephemeral in charge forever.
            let eph_live = eph_hs != (0, 0) && handshake_age(eph_hs) < Duration::from_secs(240);
            let mut wanted = if eph_live { Active::Ephemeral } else { Active::Parent };
            if wanted == Active::Ephemeral {
                let mut reconnect = false;

                // Signal A (opportunistic): a half-open SYN from an address
                // this pair owns can only come through the PARENT tunnel — a
                // client holding the ephemeral key never SYNs a new relay
                // connection. Seeing one while the addresses sit on the
                // ephemeral means the client reconnected and the old
                // ephemeral is dead.
                if pair
                    .allowed_ips
                    .iter()
                    .any(|net| cidr_set_contains(net, &syn_sources))
                {
                    log::info!(
                        "{parent}: reconnect SYN from the parent tunnel — releasing the dead ephemeral"
                    );
                    reconnect = true;
                }

                // Signal B (reliable): a FRESH parent handshake with a silent
                // ephemeral. A reconnecting client forces the parent
                // handshake at phase 1, while its dead ephemeral stops
                // keepaliving — and a LIVE session can never look like this:
                // its parent rekeys ~120s after the ephemeral does (the eph
                // is set up seconds later), so whenever the parent is fresh
                // the eph is either fresh too or still receiving keepalives.
                // The window must outlast the 30s silence test: a client's
                // reconnect SYNs through the parent never reach the relay
                // while the addresses sit on the ephemeral (gotatun drops
                // them by allowed-ips), so its one phase-1 handshake is all
                // the evidence there is — with 15s it went stale before the
                // ephemeral counted as silent and reconnects waited ~180s.
                let par_hs = device.get(parent).map_or((0, 0), |p| p.last_handshake);
                let par_fresh = par_hs != (0, 0) && handshake_age(par_hs) < Duration::from_secs(90);
                let par_newer = par_hs != (0, 0) && (eph_hs == (0, 0) || par_hs > eph_hs);
                if par_fresh && par_newer && eph_silent {
                    log::info!(
                        "{parent}: fresh parent handshake with a silent ephemeral — releasing the dead ephemeral"
                    );
                    reconnect = true;
                }

                if reconnect {
                    // Latch the release: the SYN signal blinks, and without
                    // this the next tick would hand the addresses straight
                    // back to the dead ephemeral.
                    pair.reconnect_until = Some(Instant::now() + Duration::from_secs(60));
                    wanted = Active::Parent;
                }
            }

            // While latched, home stays with the parent until the window
            // expires or a NEW register replaces this pair — the reconnecting
            // client's retry then lands on a live parent path and its
            // register installs a fresh ephemeral the normal way.
            if pair.reconnect_until.is_some_and(|until| until > Instant::now()) {
                wanted = Active::Parent;
            } else {
                pair.reconnect_until = None;
            }
            if wanted != pair.active {
                let (from, to) = match wanted {
                    Active::Ephemeral => (parent.as_str(), pair.ephemeral.as_str()),
                    Active::Parent => (pair.ephemeral.as_str(), parent.as_str()),
                };
                self.uapi.set(&uapi::move_allowed_ips(from, to, &pair.allowed_ips)).await?;
                log::info!("{parent}: tunnel addresses moved to {wanted:?}");
                pair.active = wanted;
                changed = true;
            }

            if pair.active == Active::Parent
                && !pair.ever_handshook
                && pair.created.elapsed() > UNUSED_EPHEMERAL_TTL
            {
                drop_pairs.push(parent.clone());
            }
        }

        let dropped = !drop_pairs.is_empty();
        for parent in drop_pairs {
            let pair = pairs.remove(&parent).unwrap();
            if pair.active == Active::Ephemeral && device.contains_key(&parent) {
                self.uapi
                    .set(&uapi::move_allowed_ips(&pair.ephemeral, &parent, &pair.allowed_ips))
                    .await?;
            }
            self.uapi.set(&uapi::remove_peer(&pair.ephemeral)).await?;
            log::debug!("{parent}: ephemeral peer removed");
        }
        if changed || dropped {
            save_pairs(&pairs);
        }
        Ok(())
    }
}

/// Does the single-IP set contain an address inside `net` (a `a.b.c.d[/len]`)?
fn cidr_set_contains(net: &str, ips: &HashMap<u32, ()>) -> bool {
    let Some((addr, len)) = net.split_once('/') else { return false };
    let (Ok(addr), Ok(len)) = (addr.parse::<IpAddr>(), len.parse::<u32>()) else {
        return false;
    };
    let IpAddr::V4(a) = addr else { return false };
    let len = len.min(32);
    let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
    let base = u32::from(a) & mask;
    ips.keys().any(|ip| ip & mask == base)
}

fn cidr_contains(net: &str, ip: IpAddr) -> bool {
    let Some((addr, len)) = net.split_once('/') else {
        return false;
    };
    let (Ok(addr), Ok(len)) = (addr.parse::<IpAddr>(), len.parse::<u32>()) else {
        return false;
    };
    match (addr, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) if len <= 32 => {
            let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) if len <= 128 => {
            let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::cidr_contains;

    #[test]
    fn cidr() {
        assert!(cidr_contains("10.64.0.2/32", "10.64.0.2".parse().unwrap()));
        assert!(!cidr_contains("10.64.0.2/32", "10.64.0.3".parse().unwrap()));
        assert!(cidr_contains("10.64.0.0/16", "10.64.9.3".parse().unwrap()));
        assert!(!cidr_contains("10.64.0.2/32", "fc00::2".parse().unwrap()));
        assert!(!cidr_contains("fc00:bbbb::2/128", "10.64.0.2".parse().unwrap()));
        assert!(!cidr_contains("0.0.0.0/0", "fc00::2".parse().unwrap()));
    }
}
