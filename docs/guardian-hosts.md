# Guardian hosts (mainnet, set 1)

Guardian set 1 has eight guardians and a quorum of 6. The addresses and rotation transactions are in
`docs/mainnet-deployment.md`.

| index | where | Rand view | Dilithium2 (chain 14) |
|---|---|---|---|
| 0–5 | droplets `rand-guardian-1..6` (DigitalOcean nyc3, sfo3, ams3, fra1, lon1, sgp1) | its own non-validator chain-14 node | the seed at its own `pq_guardians` index |
| 6–7 | the operator laptop (`daemons/mainnet/run-guardians-set1.sh`) | the laptop's chain-14 node | none |

- **Liveness.** Any six guardians sign a transfer, so the laptop can sleep. A mint on Rand also
  needs 5 of the 6 Dilithium2 co-signatures, and all of them come from the droplets. The bridge
  keeps working with the laptop off plus at most one droplet down.
- **Safety.** No single host holds more than two ECDSA keys, and a quorum needs six.

## What each droplet runs

- `rand-node.service`: since 2026-09-26 13:1x UTC a **chain-15** node (fullnode dd2ccbe, v0.5.8, sha256
  `61e40aa1…822f`, checked on the droplet; unit override `rand-node.service.d/chain15.conf`), data in
  `/var/lib/randnode/data-15`, genesis `cc30e085…b6b8`. User `randnode`, RPC on `127.0.0.1:8545` only.
  The chain-14 binary (`rand-node-14`) and `data-14` are kept until chain 14 is retired.
  It runs with `--verify-chain off`. The default quick replay of the whole chain took 35 minutes on
  a restart, and the guardian was blind for all of it. The node already checked every block while
  syncing. `/etc/needrestart/conf.d/rand.conf` stops unattended-upgrades from restarting the
  `rand-*` services on its own (it did so at 06:20 UTC on 2026-09-25). Restart them by hand, one
  droplet at a time.
- `rand-guardian.service`: the guardian (built from bridge `ef4d40f`, sha256 `b9c28f0b…d8f673`).
  User `guardian`, data in `/var/lib/rand-guardian/data`, signature API on `127.0.0.1:7071` only.
  Config in `/etc/rand-guardian.toml`, a copy of `daemons/mainnet/guardian-1.toml` with the droplet's
  paths and start blocks.
- `/etc/rand-guardian/` (root, mode 700):
  - `ecdsa.key`: the guardian key, generated on the droplet with `openssl rand`. It never left the droplet.
  - `pq-chain14.seed`: the chain-14 Dilithium2 seed for that index, copied from the laptop.
  - `pq-next.seed` / `pq-next.pub`: a fresh Dilithium2 seed, generated on the droplet, for the
    chain-15 `RotatePqGuardians`.
  - `env`: what systemd hands the guardian (`GUARDIAN_PRIV_KEY`, `GUARDIAN_PQ_SEED`).
- The cloud firewall `rand-guardian-fw` (tag `rand-guardian`) allows SSH in and nothing else.
  Backups and snapshots are off, because a snapshot would copy the keys.

## Operating

The droplet IPs are kept out of this public repository, in `~/.rand-bridge/mainnet-set1/hosts.txt`
(lines `<i> <ip>`). SSH uses `~/.ssh/rand_guardian_ed25519`, with known hosts in
`~/.ssh/rand_guardian_known_hosts`.

```sh
daemons/mainnet/guardian-tunnels.sh    # 127.0.0.1:717<i> -> droplet i's 127.0.0.1:7071, restarted on drop
daemons/mainnet/run-guardians-set1.sh  # laptop guardians 7 and 8 (ports 7077, 7078)
daemons/mainnet/run-relayer.sh         # the relayer, set 1, all four submitters
ssh -i ~/.ssh/rand_guardian_ed25519 root@<ip> 'journalctl -u rand-guardian -n 50; rand status'
```

To update the guardian binary on a droplet: build it (`cargo build --release --locked` in
`daemons/`, with `../../fullnode/crates/bridge-codec` beside it), check its sha256, then
`install -m 755` it to `/usr/local/bin/` and `systemctl restart rand-guardian`. Do one droplet at a
time, because the quorum tolerates two down.

**Public RPC trap.** `bsc-rpc.publicnode.com` only serves logs from about the last hour (8,000 BSC
blocks), and Ethereum's window is about a day. A guardian stopped for longer than that stalls on 403
and must have its cursor moved forward: stop it, check that the endpoint's `sequence()` still equals
the cursor's `next_sequence`, then rewrite `next_block` in `data/cursors/<chain>.json`. Paid RPCs
remove this problem.

## What this does not close yet (BR-4)

- **One custodian.** All six droplets sit in one DigitalOcean account, which also hosts other
  projects. The laptop's `rand_guardian_ed25519` key reaches every droplet as root. So the laptop
  plus that key, or the DO account alone, still reaches six keys, which is a quorum. The next steps
  are, in order:
  1. lock the SSH key down **before mainnet beta** (deferred by the owner on 2026-09-25). This is
     half prepared. Each droplet already has a `tunnel` user whose `authorized_keys` entry
     (`restrict,port-forwarding,permitopen="127.0.0.1:7071"`) admits only
     `~/.ssh/rand_guardian_tunnel_ed25519`, which nothing uses yet. To finish:
     - point `guardian-tunnels.sh` at `tunnel@` with that key, and check the relayer reaches all eight;
     - the owner puts a passphrase on the root key (`ssh-keygen -p -f ~/.ssh/rand_guardian_ed25519`);
     - maintenance then goes through `ssh-add`.
  2. move droplets to a second provider;
  3. hand droplets to separate operators, who re-key by rotation.
- **Chain-15 PQ set (2026-09-26).** `~/.rand-bridge/mainnet-set1/pq-guardians-chain15.json`: position
  i = set-1 index i. Positions 0–5 are the droplets' `pq-next.pub`, 6–7 laptop seeds
  `~/.rand-bridge/mainnet-set1/pq-next-{7,8}.seed` (mode 600). Pause key unchanged from chain 14.
  `daemons/examples/pq_pubkey.rs` prints a seed's public key (`PQ_SEED` from the environment).
- **Dilithium2.** The laptop still holds all six chain-14 PQ seeds (`NEW_GUARDIAN<i>_PQ_SEED`), and
  now each droplet holds one too. This closes only at the next chain cut, by rotating to the
  `pq-next` keys.
- **Set 0.** `GUARDIAN<i>_PRIV_KEY` in `~/.zshrc` expire with set 0's grace period (about
  2026-09-26 03:35 UTC). After that they can be deleted.

## The relayer host (from the chain-19 cut)

The relayer moves off the laptop to the droplet `rand-relayer-1` (DigitalOcean sgp1, 4 vCPU / 8 GB:
it proves each mint's fee bundle itself, about 6 GB a proof). On chain 19 (v0.6.7, single-threaded,
256-root anchor window ≈ 4.7 min) it ran at 8 dedicated vCPUs; back at 4 vCPU / 8 GB since
2026-10-01 11:00 UTC, where a chain-20 mint (v0.6.8, multi-core, 1,024-root window ≈ 20 min) takes
about 160 s. Its IPs are in
`~/.rand-bridge/relayer-host/host.txt`, not in this repository; the firewall `rand-relayer-fw`
allows SSH only. It pays gas with copies of the deployer keys, at the owner's choice
(2026-09-30), in `/etc/rand-relayer/env` (root, mode 600).

- `rand-relayer.service` (user `relayer`, config `/etc/rand-relayer.toml`, data
  `/var/lib/rand-relayer/data`, wallet `/var/lib/rand-relayer/wallet`, API on `127.0.0.1:7080`).
- `rand-relayer-tunnel@1..6.service`: one SSH forward per guardian droplet, as that droplet's
  `tunnel` user with the relayer's own key (`permitopen 127.0.0.1:7071`, and on host 6 also
  `:8545`, the Rand RPC the relayer uses). Guardian i answers on `127.0.0.1:717<i>`.
- The laptop guardians 7 and 8 reach it through `daemons/mainnet/guardian-reverse-tunnel.sh`
  (reverse forward to `127.0.0.1:7077` and `:7078`, `permitlisten` only). While the laptop is off
  the six droplet guardians are exactly a quorum.
- randbridge.org keeps its own forward-only SSH tunnel to those loopback ports (its key, user
  `tunnel`, `permitopen` 7080, 7171–7176, 7077, 7078).
- `daemons/mainnet/move-relayer-to-droplet.sh check | move | back` moves the relayer's config, data
  directory and Rand wallet across and back; one relayer at a time, since two on one EVM key race
  each other's nonces.

## Rebuild on a second DigitalOcean account (2026-10-22)

The first account was locked for billing and its droplets powered off on 2026-10-16 (they must never
be powered on again: the guardian keys now sign on the new droplets). The six guardians, the relayer
and randbridge-web were rebuilt on new droplets with the same names, from local material only. The
new IPs are in `~/.rand-bridge/mainnet-set1/hosts.txt` and `~/.rand-bridge/relayer-host/host.txt`
(the old files are kept beside them as `*.old-droplet-2026-10-22`).

- **Binaries.** Built on the new relayer host (Ubuntu 24.04, Rust 1.91.1) from bridge `55a7f23`
  with fullnode `246cb5f9` beside it: `cargo build --release --locked` in `daemons/`, and
  `cargo build --release -p rand-bridge-cli` in `solana/` (its `Cargo.lock` still names
  bridge-codec 0.5.7, so `--locked` refuses; the only lock change is that version, to 0.8.0).
  sha256: `rand-guardian` `750965aa…2fb0`, `rand-relayer` `f7b673e0…792a`,
  `rand-bridge-cli` `090a0dae…2076`; `rand` is the signed v0.8.0 release (`e3a38e74…bbf4`).
- **Guardians.** `/etc/rand-guardian*`, `/var/lib/rand-guardian` (cursors **and** `signed/`, the
  equivocation log) and the unit restored from the `configuration/` fleet snapshot of 2026-10-12.
  Each re-observed and re-signed the two messages of 2026-10-12 that the snapshot predates
  (Ethereum lock 3, Rand burn 14), byte-identical bodies, so no equivocation.
- **Catch-up past publicnode's window.** Ethereum lock 3 (block 26 176 705) was ~70 000 blocks
  behind the head, outside publicnode's log window, and `sequence()` (4) no longer equalled the
  cursors' 3, so the fallback rightly refused to skip it. The Ethereum `rpc` was pointed at
  `https://gateway.tenderly.co/public/mainnet` (serves archive `eth_getLogs` keyless) until each
  cursor was inside publicnode's window, then put back.
- **Relayer.** Config is `mainnet/relayer.toml` with the droplet paths and `chain_id = 21`. Data
  rebuilt: `done/` from the copy taken at the chain-21 cut (`~/.rand-chain21/relayer-done/done`),
  `recipients/` from the laptop's `data/mainnet/relayer` (registrations made on the old droplet
  after 2026-09-30 are lost), cursors at the cut's values. The tunnels are
  `rand-relayer-tunnel@1..6.service` running `/usr/local/bin/rand-relayer-tunnel <i>`, with the
  relayer's new key `/etc/rand-relayer/tunnel_ed25519` authorized for each guardian's `tunnel` user.
