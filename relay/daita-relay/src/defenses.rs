//! DAITA defense releases, in the JSON format written by `maybenot release`.
//!
//! Each release holds many (client machines, server machines) pairs. Every negotiation picks one
//! pair at random, so each tunnel gets its own defense (the "ephemeral defenses" design of DAITA
//! v2). The client half goes back in the RPC response; the server half is loaded into gotatun.

use std::{collections::HashMap, fs, path::Path, str::FromStr};

use anyhow::{Context, Result, bail};
use maybenot::Machine;
use rand::{Rng, seq::SliceRandom};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, Copy)]
pub struct Limits {
    pub min_padding_frac: f64,
    pub max_padding_frac: f64,
    pub min_blocking_frac: f64,
    pub max_blocking_frac: f64,
}

impl Limits {
    fn validate(&self) -> Result<()> {
        for (min, max) in [
            (self.min_padding_frac, self.max_padding_frac),
            (self.min_blocking_frac, self.max_blocking_frac),
        ] {
            if !(0.0..=1.0).contains(&min) || !(0.0..=1.0).contains(&max) || min > max {
                bail!("limits must satisfy 0 <= min <= max <= 1, got {self:?}");
            }
        }
        Ok(())
    }

    /// (padding fraction, blocking fraction) drawn uniformly from the configured ranges.
    pub fn sample(&self, rng: &mut impl Rng) -> (f64, f64) {
        let pick = |rng: &mut dyn rand::RngCore, min: f64, max: f64| {
            if min == max { min } else { rng.gen_range(min..=max) }
        };
        (
            pick(rng, self.min_padding_frac, self.max_padding_frac),
            pick(rng, self.min_blocking_frac, self.max_blocking_frac),
        )
    }
}

#[derive(Deserialize, Debug)]
pub struct Release {
    pub version: String,
    pub platform: String,
    pub client_limits: Limits,
    pub server_limits: Limits,
    pub defenses: Vec<(Vec<String>, Vec<String>)>,
}

pub struct Chosen<'a> {
    pub client_machines: &'a [String],
    pub server_machines: &'a [String],
    pub client_padding_frac: f64,
    pub client_blocking_frac: f64,
    pub server_padding_frac: f64,
    pub server_blocking_frac: f64,
}

/// Releases indexed by platform name (`windows_wg_go`, `linux_wg_go`, ..., or `any`).
pub struct Releases {
    by_platform: HashMap<String, Release>,
}

impl Releases {
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let mut by_platform = HashMap::new();
        for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let release = load_release(&path)?;
            log::info!(
                "loaded {} defenses for platform {} (version {}) from {}",
                release.defenses.len(),
                release.platform,
                release.version,
                path.display()
            );
            if by_platform.insert(release.platform.clone(), release).is_some() {
                bail!("two releases for the same platform in {}", dir.display());
            }
        }
        if by_platform.is_empty() {
            bail!("no defense releases (*.json) in {}", dir.display());
        }
        Ok(Self { by_platform })
    }

    pub fn choose(&self, platform: &str, rng: &mut impl Rng) -> Option<Chosen<'_>> {
        let release = self
            .by_platform
            .get(platform)
            .or_else(|| self.by_platform.get("any"))?;
        let (client, server) = release.defenses.choose(rng)?;
        let (client_padding_frac, client_blocking_frac) = release.client_limits.sample(rng);
        let (server_padding_frac, server_blocking_frac) = release.server_limits.sample(rng);
        Some(Chosen {
            client_machines: client,
            server_machines: server,
            client_padding_frac,
            client_blocking_frac,
            server_padding_frac,
            server_blocking_frac,
        })
    }
}

fn load_release(path: &Path) -> Result<Release> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let release: Release =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    release.client_limits.validate()?;
    release.server_limits.validate()?;
    if release.defenses.is_empty() {
        bail!("{} contains no defenses", path.display());
    }
    // Reject the file up front rather than failing a client's negotiation later.
    for (i, (client, server)) in release.defenses.iter().enumerate() {
        for m in client.iter().chain(server) {
            Machine::from_str(m)
                .map_err(|e| anyhow::anyhow!("defense {i} in {}: {e}", path.display()))?;
        }
    }
    Ok(release)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The example machine from the maybenot-simulator README.
    const MACHINE: &str = "02eNp1ibEJAEAIA5Nf7B3N0v1cSESwEL0m5A6YvBqSgP7WeXfM5UoBW7ICYg==";

    fn release(platform: &str) -> String {
        format!(
            r#"{{"version":"t","platform":"{platform}",
            "client_limits":{{"min_padding_frac":0.2,"max_padding_frac":0.4,"min_blocking_frac":0,"max_blocking_frac":0}},
            "server_limits":{{"min_padding_frac":0.5,"max_padding_frac":0.5,"min_blocking_frac":0,"max_blocking_frac":0}},
            "defenses":[[["{MACHINE}"],["{MACHINE}","{MACHINE}"]]]}}"#
        )
    }

    #[test]
    fn loads_and_chooses_with_fallback() {
        let dir = std::env::temp_dir().join(format!("daita-relay-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("any.json"), release("any")).unwrap();
        let releases = Releases::load_dir(&dir).unwrap();
        let mut rng = rand::thread_rng();
        let chosen = releases.choose("windows_wg_go", &mut rng).unwrap();
        assert_eq!(chosen.client_machines.len(), 1);
        assert_eq!(chosen.server_machines.len(), 2);
        assert!((0.2..=0.4).contains(&chosen.client_padding_frac));
        assert_eq!(chosen.server_padding_frac, 0.5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_bad_machine() {
        let dir = std::env::temp_dir().join(format!("daita-relay-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("any.json"), release("any").replace(MACHINE, "garbage")).unwrap();
        assert!(Releases::load_dir(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
