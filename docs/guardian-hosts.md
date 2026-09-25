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

- `rand-node.service`: a chain-14 node (release v0.5.6, sha256 `8edb8dbb…bdbc0d`, checked on
  install). User `randnode`, data in `/var/lib/randnode/data-14`, RPC on `127.0.0.1:8545` only.
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
- **Dilithium2.** The laptop still holds all six chain-14 PQ seeds (`NEW_GUARDIAN<i>_PQ_SEED`), and
  now each droplet holds one too. This closes only at the next chain cut, by rotating to the
  `pq-next` keys.
- **Set 0.** `GUARDIAN<i>_PRIV_KEY` in `~/.zshrc` expire with set 0's grace period (about
  2026-09-26 03:35 UTC). After that they can be deleted.
