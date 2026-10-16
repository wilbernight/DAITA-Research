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

#[derive(Debug, Clone, Copy, PartialEq)]
enum Active {
    Parent,
    Ephemeral,
}

struct Pair {
    ephemeral: String,
    allowed_ips: Vec<String>,
    active: Active,
    created: Instant,
    ever_handshook: bool,
}

pub struct Peers {
    uapi: Uapi,
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
    pub fn new(uapi: Uapi) -> Self {
        Self {
            uapi,
            pairs: Mutex::new(HashMap::new()),
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
            },
        );
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

        let mut drop_pairs = Vec::new();
        for (parent, pair) in pairs.iter_mut() {
            let Some(parent_info) = device.get(parent) else {
                // The parent was revoked (key rotated or account removed): take the pair down.
                drop_pairs.push(parent.clone());
                continue;
            };
            let eph_hs = device.get(&pair.ephemeral).map_or((0, 0), |p| p.last_handshake);
            let parent_hs = parent_info.last_handshake;
            pair.ever_handshook |= eph_hs != (0, 0);

            let wanted = if eph_hs > parent_hs { Active::Ephemeral } else { Active::Parent };
            if wanted != pair.active {
                let (from, to) = match wanted {
                    Active::Ephemeral => (parent.as_str(), pair.ephemeral.as_str()),
                    Active::Parent => (pair.ephemeral.as_str(), parent.as_str()),
                };
                self.uapi.set(&uapi::move_allowed_ips(from, to, &pair.allowed_ips)).await?;
                log::debug!("{parent}: tunnel addresses moved to {wanted:?}");
                pair.active = wanted;
            }

            if pair.active == Active::Parent
                && !pair.ever_handshook
                && pair.created.elapsed() > UNUSED_EPHEMERAL_TTL
            {
                drop_pairs.push(parent.clone());
            }
        }

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
        Ok(())
    }
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
        assert!(cidr_contains("fc00:bbbb::2/128", "fc00:bbbb::2".parse().unwrap()));
        assert!(!cidr_contains("10.64.0.2/32", "fc00::2".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0/0", "1.2.3.4".parse().unwrap()));
    }
}
