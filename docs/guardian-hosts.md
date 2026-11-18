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

## Quorum headroom (BR-402)

A set of `n` guardians needs `n * 2 / 3 + 1` signatures: 6 of 8 for set 1, and the same 6 of 8
Dilithium2 co-signatures for a mint. With exactly six running there is no spare: one host down,
one guardian paused, or one deferral stops every transfer until it clears.

```sh
rand-bridge-audit --config /etc/rand-relayer.toml --headroom              # [--min-spare 1] [--guardian-origins a,b]
```

Run where the guardian APIs are reachable (the relayer host, through its forwards). It reads the
registered set from the Rand node and `/v1/health` from every origin in `[relayer].guardians`, and
prints one line per origin, then:

```
releases: 6 of 6 required are signing; NO SPARE: any one guardian stopping stops it
mints: 6 of 6 required PQ co-signers are signing; NO SPARE: any one guardian stopping stops it
ALERT: at least 1 spare is asked for (BR-402)
```

A guardian counts when it answers, the address it answers with is in the registered set, and it is
not paused; two origins answering as one guardian count once. For mints it counts only when its
health names a PQ key (`pq_key_sha256`) that is the registered one at its own index. A guardian on
a build that does not report the key is listed as unknown and not counted, so until the guardians
run a build with this change the mints line under-counts: read it as a floor. The command is
read-only and exits non-zero under `--min-spare` (default 1), so today it fails, which is the
correct reading.

**Alert.** `daemons/mainnet/systemd/rand-bridge-headroom.{service,timer}` run it every five minutes
on the relayer host; the service's `OnFailure=` names the unit that tells someone, which you
supply (the repository ships no notifier). Install both under `/etc/systemd/system/`, set the
config path and the notifier, then `systemctl enable --now rand-bridge-headroom.timer`.

### Bringing a guardian up on its own host

Guardians 7 and 8 are registered and not running. Each goes on its own host, ideally under a
different hosting account from the six. On the new host, as root, after it runs a synced
`rand-node` (above):

```sh
daemons/mainnet/provision-guardian.sh --index 7 --binary ./rand-guardian --sha256 <recorded checksum> \
    --config ./guardian-7.toml          # --dry-run prints what it would write; --root <dir> rehearses
```

It checks the binary against the checksum, checks that the config is this guardian's (its
`key_env` carries the number, its API is on loopback, no key in it), and writes the binary, the
config, `rand-guardian.service`, an empty `/etc/rand-guardian/env` (mode 600, variable names only)
and the data directory. It reads and writes no key, overwrites nothing that differs, contacts
nothing, and does not start the service. Then:

1. The key holder fills `GUARDIAN<i>_PRIV_KEY` and `GUARDIAN<i>_PQ_SEED` in `/etc/rand-guardian/env`
   on that host. The key must be the one registered at that index: a guardian that was never run
   from this key material is brought in by rotation (`rand-bridge-gov rotate`,
   `docs/pq-rotation.md`), not by copying a key onto a new host.
2. Set the config's start blocks to recent ones the providers still serve (the "Public RPC trap"
   below), so the guardian does not stall on old log ranges.
3. `systemctl enable --now rand-guardian`; its log must show the guardian's address, the PQ key
   prefix, and cursors moving.
4. Give the relayer a path to its API (a forward like the others: `guardian-tunnels.sh` reads
   `hosts.txt`), and list the origin in `[relayer].guardians`.
5. `rand-bridge-audit --headroom` must now count it. With both up: `2 spare`, and `OK`.

If 7 and 8 are not coming back, the alternative is to rotate the ECDSA and the PQ set together to
the guardians that run plus new ones, so that the registered set again has spares.

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
