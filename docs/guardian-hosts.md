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

Configure each guardian with more than one independent RPC per chain (`rpcs`, `rpc_quorum`; BR-4)
and with its peers (`guardian.peers`; BR-502). The repository's configs carry one RPC per chain and
no peers; the hosts' configs are where these are set.

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
- Run one relayer at a time: two on one EVM key race each other's nonces.
