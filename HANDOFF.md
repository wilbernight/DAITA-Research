# Handoff: self-hosted Mullvad-style VPN — DAITA phase

Context for the Claude session continuing this work (on the user's MacBook M5).
Talk to the user in Persian.

## Overall goal
The user wants their own VPN service modelled on Mullvad: own server(s) on a separate VPS
(not yet created) and a rebranded fork of `mullvad/mullvadvpn-app` (GPL-3) for desktop that
connects to it with all Mullvad connection methods (WireGuard, UDP-over-TCP, Shadowsocks,
QUIC/MASQUE, LWO, quantum-resistant PSK, multihop, DAITA, API bridges), plus ExpressVPN's
Lightway (`expressvpn/lightway`) as an extra protocol. Mullvad's server side (API, relay
management) is closed source and has to be written by us.

**Current phase (user's priority):** the missing server half of DAITA, and an experiment to
see whether our DAITA defenses can be at least as strong as Mullvad's.

## What's known
- Mullvad's relay-side DAITA code and its generated defense set are not public. Everything
  else is: `mullvad/gotatun` (userspace WireGuard, MPL-2.0) runs DAITA symmetrically and
  accepts per-peer machines over UAPI when built with feature `daita-uapi` (see its UAPI.md);
  `maybenot-io/maybenot` has the framework, simulator, `maybenot-gen` and `maybenot-cli`
  (defense search/derive/combo/sim/eval/release) — the pipeline from the PETS 2026 paper
  "Ephemeral Network-Layer Fingerprinting Defenses", which DAITA v2 is based on.
- DAITA v2 protocol: `ephemeralpeer.proto` (copied into `relay/daita-relay/proto/`). The client
  sends `DaitaRequestV2{version=2, platform, level=default}` to `10.64.0.1:1337` inside the
  tunnel; the server returns client machines + max padding/blocking fractions and applies
  the server machines itself. Each tunnel gets a randomly chosen defense from a release.

## Done
- `relay/daita-relay/` (Rust, builds, 5 unit tests pass): gRPC EphemeralPeer service —
  ML-KEM-1024 + HQC-256 PSK, DAITA v2 negotiation from `maybenot release` JSON files per
  platform (fallback `any`), drives gotatun via UAPI socket, parent/ephemeral peer swap on
  handshake (poll loop), source-IP check against the parent's allowed IPs.
  NOT yet tested end to end (needs Linux VPS + gotatun built with `--features gotatun/daita-uapi`).
- Dataset downloaded on the Windows box: BigEnough
  `https://dart.cse.kau.se/popets-2026.1-ephemeral-defs-paper-artifacts/bigenough-95x10x20-standard-rngsubpages.tar.gz`
  (34 MB, 19,000 traces, 95 sites x 10 subpages x 20). Re-download it on the Mac into `data/`.

## Next steps
1. Clone upstream into `upstream/` (gitignored): `maybenot-io/maybenot`, `mullvad/gotatun`,
   sparse `mullvad/mullvadvpn-app` (talpid-tunnel-config-client, talpid-wireguard).
   Build `cargo build --release -p maybenot-cli`.
2. Python env with torch (MPS) + scikit-learn for `maybenot-cli/scripts/rf.py` and `df.py`
   (check whether they need a device flag for MPS).
3. Baseline = Mullvad-equivalent: run `maybenot-cli/examples/popets26-eph-padding.toml`
   (search 100 → combo 19,000 → sim → eval with RF and DF). Fix dataset paths.
4. Candidates: stronger configs (more search, larger budgets, allow blocking/delay machines,
   different load constraints). Compare attack accuracy vs bandwidth/latency overhead.
   "Better" = lower RF/DF accuracy at equal or lower overhead.
5. Release the winner with `maybenot release` (fill in limits) into the relay's defenses dir.
6. Later, on the VPS: end-to-end test with the real app, then a real-world comparison
   (traffic captures via real Mullvad DAITA vs ours, same classifiers) if the user has a
   Mullvad account.

## Open questions for the user
VPS details, domain for API/QUIC, target OSes (only Windows so far?), account model
(fixed accounts for a few people vs full sign-up).
