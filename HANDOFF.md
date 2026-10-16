# Project status: self-hosted WireGuard VPN with DAITA

Last updated: 2026-10-16

## Goal
Run a private VPN service modelled on Mullvad:

- **Server side:** our own relay servers on a dedicated VPS (not provisioned yet).
- **Client:** a rebranded fork of `mullvad/mullvadvpn-app` (GPL-3), desktop first.

The client should support Mullvad's connection methods:
- WireGuard
- UDP-over-TCP
- Shadowsocks
- QUIC/MASQUE
- LWO
- post-quantum PSK
- multihop
- DAITA
- API bridges

ExpressVPN's Lightway (`expressvpn/lightway`) will be added as an extra protocol.

Mullvad's server side (API, relay management, relay-side DAITA) is closed source, so it is implemented here.

**Current focus:** the relay half of DAITA, and building defenses that are at least as strong as Mullvad's.

## Background
- **Relay-side DAITA:** Mullvad's code and its generated defense set are not public.
- **Public building blocks:**
  - `mullvad/gotatun`: userspace WireGuard, MPL-2.0. Runs DAITA symmetrically and accepts per-peer Maybenot machines over UAPI when built with feature `daita-uapi` (see its `UAPI.md`).
  - `maybenot-io/maybenot`: the framework, simulator, `maybenot-gen` and `maybenot-cli` (search / derive / combo / sim / eval / release). This is the pipeline from the PETS 2026 paper *Ephemeral Network-Layer Fingerprinting Defenses*, which DAITA v2 is based on.
- **DAITA v2 protocol** (`relay/daita-relay/proto/ephemeralpeer.proto`):
  1. Inside the tunnel, the client sends `DaitaRequestV2{version=2, platform, level=default}` to `10.64.0.1:1337`.
  2. The relay replies with the client-side machines and the maximum padding/blocking fractions, and applies the server-side machines itself.
  3. Each tunnel gets a defense drawn at random from a released set.

## Repository layout
| Path | Contents |
|---|---|
| `relay/daita-relay/` | Relay-side EphemeralPeer gRPC service (Rust) |
| `experiments/daita-defenses/` | Defense search configs, classifier scripts, results, logs, report |
| `upstream/`, `data/`, `work/` | Local only (gitignored): upstream checkouts, dataset, scratch output |

## Done
### Relay service (`relay/daita-relay/`)
Builds; 5 unit tests pass.
- Post-quantum PSK negotiation: ML-KEM-1024 + HQC-256.
- DAITA v2 negotiation, serving defenses from `maybenot release` JSON files per platform, with an `any` fallback.
- Drives gotatun through its UAPI socket.
- Parent/ephemeral peer swap on handshake (poll loop).
- Source-IP check against the parent peer's allowed IPs.
- **Not yet tested end to end.** That needs the Linux VPS and gotatun built with `--features gotatun/daita-uapi`.

### Defense evaluation (`experiments/daita-defenses/`)
Full write-up: `REPORT.md`.

**Method:**
- BigEnough dataset: 95 sites × 10 subpages × 20 samples, 19,000 traces.
- Defense set size: 19,000 defenses per configuration.
- Attacks: Deep Fingerprinting (DF) and Robust Fingerprinting (RF), trained and tested on defended traces.
- Two folds per configuration.

**Results** (lower attack accuracy is better):

| Configuration | RF | DF | Data overhead | Delay |
|---|---|---|---|---|
| Undefended | 90.8% | 92.8% | — | — |
| Baseline (Mullvad-equivalent, padding only) | 72.0% | 61.1% | 0.64× | 1% |
| Padding + blocking | 65.6% | 54.7% | 0.67× | 6% |
| Heavier padding | 66.0% | 52.1% | 0.97× | 1% |
| **Blocking + moderate padding (`blockmid`)** | **61.0%** | **47.2%** | **0.81×** | 7% |
| Blocking + heavy padding | 62.1% | 49.4% | 0.89× | 6% |

`blockmid` is the current best candidate:
- **Gain:** about 14 points lower DF accuracy and 11 points lower RF accuracy than the baseline.
- **Cost:** about 27% more bandwidth and 7% added latency.

**Findings:**
- Allowing blocking matters more than adding padding.
- A larger search (500 instead of 100 base defenses) gave no improvement.

## Next steps
1. **Release `blockmid`** with `maybenot release`. The relay's advertised `max_padding_frac` / `max_blocking_frac` must match the simulation limits (padding 0.95, blocking 0.3). Place the output in the relay's defenses directory.
2. **Optional tuning:** search around `blockmid` (blocking fraction, slightly lower load) to get the same strength at lower overhead.
3. **VPS deployment:** build gotatun with DAITA UAPI, run `daita-relay`, and test end to end with the client.
4. **Real-world validation:** capture traffic through real Mullvad DAITA and through our relay, then run the same classifiers on both. This requires a Mullvad account.
5. **Client fork:** rebranding, relay list/API endpoint, then the remaining connection methods and Lightway.

## Reproducing the experiments
Prerequisites:
- Rust (stable).
- Python 3.12 with `torch` and `scikit-learn`. The scripts in `experiments/daita-defenses/scripts/` support CUDA and Apple MPS.

```sh
git clone --depth 1 https://github.com/maybenot-io/maybenot.git upstream/maybenot
(cd upstream/maybenot && cargo build --release -p maybenot-cli)
mkdir -p data && curl -L https://dart.cse.kau.se/popets-2026.1-ephemeral-defs-paper-artifacts/bigenough-95x10x20-standard-rngsubpages.tar.gz | tar xz -C data
uv venv --python 3.12 .venv && uv pip install --python .venv torch scikit-learn numpy
cd experiments/daita-defenses && ./run-cand.sh blockmid
```

Notes:
- **Run time:** searches that allow blocking take 20 minutes to 2 hours on a 10-core machine. One RF + DF evaluation takes about 20–25 minutes on Apple silicon.
- **Disk:** each simulation writes about 13 GB.

## Open questions
- VPS provider, location and specs.
- Domain for the API and QUIC endpoints.
- Target operating systems (only Windows confirmed so far).
- Account model: fixed accounts for a few users, or full sign-up.
