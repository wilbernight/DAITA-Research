//! Minimal client for the WireGuard cross-platform UAPI (the `wg` configuration protocol) as
//! served by gotatun on `/var/run/wireguard/<iface>.sock`. gotatun must be built with the
//! `daita-uapi` feature for the `daita_*` keys to be accepted.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};

/// A peer as reported by `get=1`. Keys are lowercase hex, as on the wire.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PeerInfo {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    /// (seconds, nanoseconds) since the epoch; (0, 0) if the peer never completed a handshake.
    pub last_handshake: (u64, u64),
    /// Total inbound bytes. Used to tell a silent (dead) ephemeral session from
    /// a live one: keepalives arrive every 25s, so frozen bytes mean nobody is
    /// there anymore.
    pub rx_bytes: u64,
}

pub struct DaitaPeerSettings<'a> {
    pub machines: &'a [String],
    pub max_decoy_frac: f64,
    pub max_delay_frac: f64,
    pub max_delayed_packets: usize,
    pub min_delay_capacity: usize,
}

pub struct Uapi {
    socket: PathBuf,
}

impl Uapi {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_path_buf(),
        }
    }

    pub async fn peers(&self) -> Result<Vec<PeerInfo>> {
        let reply = self.exchange("get=1\n\n").await?;
        parse_get(&reply)
    }

    pub async fn set(&self, body: &str) -> Result<()> {
        let reply = self.exchange(&format!("set=1\n{body}\n")).await?;
        match reply.lines().find_map(|l| l.strip_prefix("errno=")) {
            Some("0") => Ok(()),
            Some(errno) => bail!("UAPI set failed with errno={errno}"),
            None => bail!("UAPI set: no errno in reply {reply:?}"),
        }
    }

    #[cfg(unix)]
    async fn exchange(&self, request: &str) -> Result<String> {
        use anyhow::Context;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connecting to {}", self.socket.display()))?;
        stream.write_all(request.as_bytes()).await?;
        // The server ends every reply with an empty line; read until we see it.
        let mut reply = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&buf[..n]);
            if reply.ends_with(b"\n\n") {
                break;
            }
        }
        Ok(String::from_utf8(reply)?)
    }

    #[cfg(not(unix))]
    async fn exchange(&self, _request: &str) -> Result<String> {
        bail!(
            "the UAPI socket {} is only reachable on Linux",
            self.socket.display()
        )
    }
}

pub fn parse_get(reply: &str) -> Result<Vec<PeerInfo>> {
    let mut peers: Vec<PeerInfo> = Vec::new();
    for line in reply.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "public_key" => peers.push(PeerInfo {
                public_key: value.to_string(),
                ..Default::default()
            }),
            "errno" if value != "0" => bail!("UAPI get failed with errno={value}"),
            _ => {
                let Some(peer) = peers.last_mut() else {
                    continue; // interface-level keys come before the first peer
                };
                match key {
                    "allowed_ip" => peer.allowed_ips.push(value.to_string()),
                    "last_handshake_time_sec" => peer.last_handshake.0 = value.parse()?,
                    "last_handshake_time_nsec" => peer.last_handshake.1 = value.parse()?,
                    "rx_bytes" => peer.rx_bytes = value.parse()?,
                    _ => {}
                }
            }
        }
    }
    Ok(peers)
}

/// Body that adds (or replaces) the ephemeral peer. It starts with no allowed IPs: it can
/// handshake, but carries no traffic until [`move_allowed_ips`] hands it the parent's addresses.
pub fn add_ephemeral_peer(
    public_key: &str,
    psk: Option<&[u8; 32]>,
    daita: Option<&DaitaPeerSettings<'_>>,
) -> String {
    let mut body = String::new();
    writeln!(body, "public_key={public_key}").unwrap();
    if let Some(psk) = psk {
        writeln!(body, "preshared_key={}", hex::encode(psk)).unwrap();
    }
    writeln!(body, "replace_allowed_ips=true").unwrap();
    if let Some(d) = daita {
        writeln!(body, "daita_enable=1").unwrap();
        for m in d.machines {
            writeln!(body, "daita_machine={m}").unwrap();
        }
        writeln!(body, "daita_max_delayed_packets={}", d.max_delayed_packets).unwrap();
        writeln!(body, "daita_min_delay_capacity={}", d.min_delay_capacity).unwrap();
        writeln!(body, "daita_max_decoy_frac={}", d.max_decoy_frac).unwrap();
        writeln!(body, "daita_max_delay_frac={}", d.max_delay_frac).unwrap();
    }
    body
}

/// Body that moves `ips` from one peer to another in a single transaction.
pub fn move_allowed_ips(from: &str, to: &str, ips: &[String]) -> String {
    let mut body = format!("public_key={from}\nreplace_allowed_ips=true\n");
    writeln!(body, "public_key={to}\nreplace_allowed_ips=true").unwrap();
    for ip in ips {
        writeln!(body, "allowed_ip={ip}").unwrap();
    }
    body
}

pub fn remove_peer(public_key: &str) -> String {
    format!("public_key={public_key}\nremove=true\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_reply() {
        let reply = "private_key=aa\nlisten_port=51820\npublic_key=01\npreshared_key=00\n\
            allowed_ip=10.64.0.2/32\nallowed_ip=fc00::2/128\nlast_handshake_time_sec=17\n\
            last_handshake_time_nsec=5\nrx_bytes=1234\npublic_key=02\nlast_handshake_time_sec=0\n\
            last_handshake_time_nsec=0\nrx_bytes=0\nerrno=0\n\n";
        let peers = parse_get(reply).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].allowed_ips, ["10.64.0.2/32", "fc00::2/128"]);
        assert_eq!(peers[0].last_handshake, (17, 5));
        assert_eq!(peers[0].rx_bytes, 1234);
        assert!(peers[1].allowed_ips.is_empty());
        assert_eq!(peers[1].rx_bytes, 0);
    }

    #[test]
    fn move_is_one_transaction() {
        let body = move_allowed_ips("aa", "bb", &["10.64.0.2/32".into()]);
        assert_eq!(
            body,
            "public_key=aa\nreplace_allowed_ips=true\npublic_key=bb\nreplace_allowed_ips=true\nallowed_ip=10.64.0.2/32\n"
        );
    }
}
