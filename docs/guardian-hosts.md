# Guardian hosts (mainnet, set 1)

Guardian set 1 has eight guardians and a quorum of 6. The addresses and rotation transactions are in
`docs/mainnet-deployment.md`.

- **Liveness.** Any six guardians sign a transfer. A mint on Rand also needs a quorum of the
  Dilithium2 co-signatures (`spec/PQ-COSIGNATURE.md`).
- **Safety.** A quorum needs six ECDSA signatures. Each guardian should be run by its own operator,
  with its keys generated on its own host; keys are moved to new holders by rotation (README,
  "Governance", and `docs/pq-rotation.md`), never by copying them.

## What a guardian host runs

- `rand-node.service`: a non-validator node of the bridged Rand chain, RPC on `127.0.0.1:8545` only.
  It runs with `--verify-chain off`: the default quick replay of the whole chain on a restart
  leaves the guardian blind for its whole length, and the node already checked every block while
  syncing. Keep unattended upgrades from restarting the `rand-*` services
  (`/etc/needrestart/conf.d/`), and restart them by hand, one host at a time.
- `rand-guardian.service`: the guardian, as its own user, data in `/var/lib/rand-guardian/data`,
  signature API on `127.0.0.1:7071` only, config in `/etc/rand-guardian.toml` (a copy of
  `daemons/mainnet/guardian-<i>.toml` with the host's paths and start blocks). Secrets reach it only
  through the service environment (`key_env`, `pq_seed_env`; `daemons/README.md`).
- A firewall that admits SSH and nothing else.

## Operating

Host addresses and SSH host keys are not in this repository. The scripts read them from
operator-local files — `~/.rand-bridge/mainnet-set1/hosts.txt` (lines `<i> <ip>`) for the guardian
hosts, `~/.rand-bridge/relayer-host/host.txt` (lines `public <ip>` and `hostkey SHA256:<fingerprint>`)
for the relayer host — or from the `RELAYER_IP` / `RELAYER_HOSTKEY` environment variables.

```sh
daemons/mainnet/guardian-tunnels.sh    # 127.0.0.1:717<i> -> guardian i's 127.0.0.1:7071, restarted on drop
daemons/mainnet/run-guardians-set1.sh  # guardians 7 and 8 (ports 7077, 7078)
daemons/mainnet/run-relayer.sh         # the relayer, set 1, all four submitters
```

To update the guardian binary on a host: build it (`cargo build --release --locked` in
`daemons/`, with `../../fullnode/crates/bridge-codec` beside it), check its sha256, then
`install -m 755` it to `/usr/local/bin/` and `systemctl restart rand-guardian`. Do one host at a
time, because the quorum tolerates two down.

## The mainnet guard (BR-601)

On a public Rand chain (`rand.chain_id` 14 or higher, or none configured) `rand-guardian` refuses to
start unless its config has all three controls:

- every watched chain (Rand, each `[[evm]]`, `[solana]`) read through **at least two distinct
  providers** (`rpc` + `rpcs`) at an **`rpc_quorum` of at least 2** (BR-4);
- a non-empty **`guardian.peers`** (BR-502);
- a **`[guardian.limits]`** section (BRG-1).

The error lists every missing control. `rand-guardian --config <file> --check-config` runs the same
check and exits (0 when the guardian would start); it needs no key. `--unsafe-skip-mainnet-guards`
(or `RAND_GUARDIAN_UNSAFE_SKIP_MAINNET_GUARDS=1`) starts the guardian anyway, logging every missing
control at error level on each start. It is for an emergency or a dev run only, never a standing
setting. `--pause-signing`, `--resume-signing` and `--list-held` work without the check.

### Providers

`daemons/mainnet/guardian-<i>.toml` lists the keyless providers verified on 2026-11-04 (each answered
`eth_getLogs` over 1,000 blocks on the endpoint contract, or `getAccountInfo` on the program), plus
one `${NAME}` placeholder per chain for a provider whose URL carries an API key. The placeholders are
filled from the guardian's environment when the config is loaded (`Config::load_with`). An unset or
empty one stays as written and counts as a missing control. RPC errors name the host only, never the
URL, so a key in a path does not reach the log.

| chain | providers in the repo config | from the environment | quorum |
|---|---|---|---|
| Rand | `127.0.0.1:8545` (this host's node) | `GUARDIAN_RPC_RAND`: a Rand node on another host | 2 of 2 |
| Ethereum | publicnode, `rpc.mevblocker.io` | `GUARDIAN_RPC_ETHEREUM` | 2 of 3 |
| BSC | publicnode | `GUARDIAN_RPC_BSC` | 2 of 2 |
| Tron | publicnode, `api.trongrid.io` | `GUARDIAN_RPC_TRON` (origin; `/jsonrpc` is appended) | 2 of 3 |
| Solana | `api.mainnet-beta.solana.com`, publicnode | `GUARDIAN_RPC_SOLANA` | 2 of 3 |

Choose providers run by different companies from the keyless ones above. With 2 of 2 (Rand, BSC),
one provider being down defers signing on that chain until it is back. Nothing is skipped, but on
this set every deferral stops transfers (BR-402). A third BSC provider removes that: add it to
`rpcs`. On a droplet the values go in `/etc/rand-guardian/env` (mode 600, read by systemd) next to
the keys. On the laptop, `run-guardians-set1.sh` reads `GUARDIAN_RPC_*` lines from
`~/.rand-bridge/mainnet-set1/rpc.env`.

`GUARDIAN_RPC_RAND` must reach a Rand node that does not share this host. The public RPC
(`randscan.org/rpc`) refuses the bridge methods. Options: another guardian host's node, through an
SSH forward like the peers' below (its `tunnel` entry then also needs
`permitopen="127.0.0.1:8545"`), or a validator run by another operator.

### Peers

The droplet guardian APIs listen on loopback only. Guardian i's config names the other droplets as
`http://127.0.0.1:717<j>`, so each droplet needs one SSH local forward per peer, the same way the
relayer host has them: `127.0.0.1:717<j>` goes to guardian j's `127.0.0.1:7071`, as guardian j's
`tunnel` user. Give each host its own forwarding key. Its entry in every other host's
`~tunnel/.ssh/authorized_keys` reads `restrict,port-forwarding,permitopen="127.0.0.1:7071" <key>`, so
a compromised host can only read the others' signature APIs. Run the forwards as a systemd template
unit (`rand-guardian-peer@<j>.service`, restarting on drop). Host addresses stay in operator-local
files, as for `guardian-tunnels.sh`. Guardians 7 and 8 name the droplets through
`guardian-tunnels.sh` (7171-7176) and each other.

A peer answers with its **own** signature only. The peer check catches this guardian's forgotten
signature only when some peer keeps a copy of it (`daemons/README.md`, Guardian), and no API serves
such a copy today. Pointing the peers at the other guardians satisfies the guard and adds the
liveness check (no peer answering defers the transfer), but it is not yet the restored-store
protection that BR-502 describes.

### Rolling the guarded config to the live guardians

The config needs the binary that has this guard, because an older binary would treat `${NAME}` as a
URL. That breaks Rand and BSC, whose quorum is 2 of 2. Roll the binary and the config together, one
host at a time.

**Quorum during the roll (BR-402).** Set 1 needs 6 of 8 ECDSA signatures, and chain 21 needs 6 of 8
Dilithium2 co-signatures on every mint. Guardians 7 and 8 are offline, so all six droplets must sign.
While any one droplet restarts, nothing is signed: no mint and no release. Nothing is lost. Locks and
burns stay on their chains, and each guardian signs from its cursor once it is back. Two ways to
roll:

1. **Preferred: bring guardians 7 and 8 up first** (`run-guardians-set1.sh` with `rpc.env`,
   `guardian-tunnels.sh`, `guardian-reverse-tunnel.sh`), on the new binary and config, and confirm
   that the relayer reaches 7077 and 7078. Then seven of eight sign while each droplet restarts, and
   releases keep flowing. Mints keep flowing only if 7 and 8 also hold their chain-21 Dilithium2
   seeds (`GUARDIAN7_PQ_SEED`, `GUARDIAN8_PQ_SEED`). Without the seeds, the PQ quorum still needs all
   six droplets.
2. **Otherwise: one host at a time inside an announced window** with no transfer in flight (on the relayer host,
   every entry under `data/observed/` has its match under `data/done/`). Each restart is a
   short bridge-wide stop. The order among the six does not matter for quorum. Start with the host
   whose provider and peer forwards were checked first.

Never take two droplets down at once while 7 and 8 are offline.

**Before the first host:**

1. Build and checksum the binary (above). The owner fills the values below into each host's
   `/etc/rand-guardian/env`; they are not in this repository.
2. On every droplet, install the peer forwards and the `tunnel` entries. Check that
   `curl -s http://127.0.0.1:717<j>/v1/health` answers for every j ≠ i. This touches no running
   guardian.

**Per host (i = 1..6), one at a time:**

1. Back up: `cp -a /etc/rand-guardian.toml /etc/rand-guardian.toml.pre-br601-$(date +%F)`, and the
   same for `/usr/local/bin/rand-guardian` and `/etc/rand-guardian/env`.
2. Write `/etc/rand-guardian.toml.new` as the host's current file (keep its `data_dir`, `key_env`,
   `pq_seed_env`, `listen` and start blocks) plus the `rpcs`/`rpc_quorum` lines, `peers` and
   `[guardian.limits]` from `daemons/mainnet/guardian-<i>.toml`.
3. Check it with the new binary, passing only the provider variables:
   `env $(grep '^GUARDIAN_RPC_' /etc/rand-guardian/env | xargs) /usr/local/bin/rand-guardian.new --config /etc/rand-guardian.toml.new --check-config`.
   It must print `config OK for Rand chain 21`. Stop here if it does not.
4. Swap: `install -m 755 rand-guardian.new /usr/local/bin/rand-guardian`,
   `mv /etc/rand-guardian.toml.new /etc/rand-guardian.toml`, `systemctl restart rand-guardian`.
5. Verify within a minute in `journalctl -u rand-guardian`: no `refusing to start` and no `UNSAFE`;
   `<chain>: 2 of <n> RPCs must agree before signing` for every chain; `<n> of 5 peers answer` with n ≥ 1; a `caps:` line; and
   the signature API answering through the relayer's forward. Then wait for this guardian's signature
   on the next transfer, or for its cursors to reach the chain heads, before the next host.
6. Rollback if any check fails: restore the three backups and `systemctl restart rand-guardian`.

Afterwards, record the roll (BR-602): date, host, binary sha256, config sha256, and the
`--check-config` output. Then take a fleet snapshot.

**Public RPC trap.** `bsc-rpc.publicnode.com` only serves logs from about the last hour (8,000 BSC
blocks), and Ethereum's window is about a day. A guardian stopped for longer than that stalls on 403
and must have its cursor moved forward: stop it, check that the endpoint's `sequence()` still equals
the cursor's `next_sequence`, then rewrite `next_block` in `data/cursors/<chain>.json`. Paid or
archive-capable RPCs remove this problem.

## The relayer host

The relayer proves each mint's fee bundle itself (about 6 GB of memory a proof).

- `rand-relayer.service` (its own user, config `/etc/rand-relayer.toml`, data
  `/var/lib/rand-relayer/data`, API on `127.0.0.1:7080`).
- One SSH forward per guardian host, as that host's `tunnel` user, whose `authorized_keys` entry
  (`restrict,port-forwarding,permitopen="127.0.0.1:7071"`) admits only port forwarding to the
  guardian's API. Guardian i answers on `127.0.0.1:717<i>`.
- Guardians 7 and 8 reach it through `daemons/mainnet/guardian-reverse-tunnel.sh` (reverse forward
  to `127.0.0.1:7077` and `:7078`, `permitlisten` only).
- randbridge.org keeps its own forward-only SSH tunnel to those loopback ports (user `tunnel`,
  `permitopen` 7080, 7171–7176, 7077, 7078).
- Recipient registrations live only in `/var/lib/rand-relayer/data/recipients/`; export them to an
  off-host, private copy after registrations and on a schedule, and restore through
  `recipients_file` (BR-503; recipe in `daemons/README.md`, "Relayer").
- Run one relayer at a time: two on one EVM key race each other's nonces.
