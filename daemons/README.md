# Rand bridge daemons

The off-chain half of the bridge (`docs/architecture.md` §4): nothing moves a token until a
guardian quorum has signed a message and someone has submitted the result.

| binary | who runs it | what it holds |
|---|---|---|
| `rand-guardian` | each of the six guardians, **one per host, one key per host** | a guardian key (env only) |
| `rand-relayer` | anyone; the bridge is permissionless | gas keys for the chains it submits to |

```
source chain ──MessagePublished / PostedMessage / rand_getBridgeBurn──▶ guardian ×6
                                                                          │ sign mu = keccak256(keccak256(body))
relayer ◀──GET /v1/signature/{emitter_chain}/{sequence}───────────────────┘
   │ quorum (n*2/3+1), indices strictly increasing
   ├─▶ to_chain 1      rand bridge-mint        (the Rand wallet seals the note and proves the fee bundle)
   ├─▶ to_chain 2,3    release(bytes)          (EIP-1559, signed here)
   ├─▶ to_chain 4      release(bytes)          (Tron HTTP API; the node-built tx is re-hashed and checked before signing)
   └─▶ to_chain 5      rand-bridge-cli release (creates the token accounts first, then ComputeBudget + Release)
```

## Guardian

- Reads each source only past its **consistency level** (`finality` in the config: `finalized`
  on Ethereum, 15 confirmations on BSC, 19 on Tron; Solana at `finalized` commitment; a Rand
  block is final when it commits).
- Reads each chain through **several providers** when `rpcs` is configured (BR-4): a message is
  signed only when `rpc_quorum` of them (default a majority) independently report the same body in
  the same block, final at their own consistency level, and an EVM scan must match the endpoint's
  `sequence()` counter at a quorum of providers, so a provider that invents, alters or leaves out a
  lock cannot get one signed. One `rpc` alone still works, with a startup warning.
- Rebuilds the body from the event plus the block timestamp, the emitter chain id and the
  emitter address (`spec/ATTESTATION.md` §3.2), checks it re-encodes canonically, and signs it
  only if the destination would accept it: registered emitter, `to_chain` / `token_chain` rules,
  `fee <= amount`, non-zero, within `u64`, EVM address padding. A refused message is written to
  `data_dir/refused/` with the reason. **Rotations are never signed by the daemon.**
- **Caps every message before it signs** (BRG-1, `[guardian.limits]`): a per-transfer cap and a
  per-window cap (default 86,400 s, rolling, on the guardian's own clock), per token and direction
  (deposits and releases counted apart), in attested 8-decimal units, with per-token overrides. The
  mainnet configs carry the published caps: 100 per transfer, 1,000 per day. A message over either
  cap is refused and **pauses all signing**; `/v1/health` shows the pause, and
  `rand-guardian --config <file> --resume-signing` clears it after review. This bounds loss without
  any contract change; a guardian without the section warns at startup.
- Persists the signature before it advances its cursor, and refuses — fatally — to sign a
  second body under an `(emitter chain, sequence)` it has already signed.
- **Asks its peers before a first signature** (BR-502, `guardian.peers`): replay protection on
  the destinations is by body digest, so two bodies of one lock could each be redeemed. The
  guardian's own `signed/` record stops a second body only while it exists; a `data_dir` restored
  from a snapshot taken before the first signature has lost it. So for every `(chain, sequence)`
  it holds no record of, the guardian fetches the peers' records and refuses (recorded under
  `refused/`) when one is a valid signature by a member of the current guardian set over a
  different body. At startup it reports how many peers answer, or warns that none are configured.
  After restoring a `data_dir` from any backup, configure the peers before the first poll.
- Every record under `data_dir` is written durably (BR-951): a temp file, fsynced, renamed over
  the record, then the directory fsynced. A record that is still unreadable (zero-length,
  truncated, not JSON) fails that `(emitter chain, sequence)` alone: the guardian signs nothing
  for it, writes the reason to `data_dir/refused/<chain>/<sequence>.json`, logs it, and signs the
  rest of the source as usual. To recover, restore the record from a backup, or — if this
  guardian is known never to have served a signature for it — delete the file and rewind that
  source's cursor so the lock is read again.
- **Co-signs deposits with Dilithium2** when `GUARDIAN_PQ_SEED` and `rand.chain_id` are set
  (`spec/PQ-COSIGNATURE.md`): a second quorum the chain-14 ledger requires on every mint, over
  `"rand-bridge-pq-cosign-1" ‖ rand_chain_id ‖ mu`. Releases stay classical. The seed is generated on
  the operator's host and never leaves it; only the 1,312-byte public key goes into the genesis.
- Serves `GET /v1/signature/{chain}/{sequence}` and `GET /v1/health`. A signature carries no
  guardian index: `mu` covers the body only, so after a rotation the same signature is simply
  assembled under the new set's indices. That is all "re-signing under the current set" takes.

## Relayer

- Watches the same sources itself, so it trusts no guardian about what was said on a chain: a
  signature only counts if it recovers, over the digest of the body the *relayer* observed, to a
  member of the guardian set (read from `rand_getBridgeState`).
- Uses exactly a quorum, lowest indices first (every extra signature is 66 bytes and one more
  recovery; Solana has no slack).
- **Deposits need the recipient's address.** A lock names only the 32-byte recipient hash, but
  minting seals a note to the full `rand1…` address. Whoever wants a deposit relayed registers the
  address (`POST /v1/recipients`, or `recipients_file`). The chain refuses a mint whose address does
  not hash to the lock's recipient, so a wrong registration can only fail, never misdirect. The
  relayer refuses it first: an address is registered only under the hash it hashes to (the hash is
  its own authorization, no other credential exists), and the API never replaces an entry that
  maps to a different address (409) — before this, anyone who reached the port could re-point a
  depositor's hash and stall that deposit.
- For a deposit on a chain that lists `pq_guardians`, also collects the co-signatures, verifies
  each under the key at its guardian's index, keeps exactly a quorum and hands it to the wallet
  (`rand bridge-mint @att --pq @pq.json --to …`); short of either quorum nothing is submitted.
- Checks `consumed(digest)` first and treats "already consumed" as done: relayers race, by design.

## Governance: rotating the guardian set

`rand-bridge-gov` is a deliberate command-line tool, not a daemon — a rotation is an act by people.

```sh
rand-bridge-gov rotate --current-index 0 --current-guardians 0x…,0x…(six) \
    --new-guardians 0x…,0x…(index order) \
    --signer-envs GUARDIAN1_PRIV_KEY,GUARDIAN2_PRIV_KEY,…(a quorum of the CURRENT set) \
    --out rotation-1.hex
rand-bridge-gov verify --current-index 0 --current-guardians … --attestation-file rotation-1.hex
```

It builds the payload-2 body (governance emitter, `new_index = current + 1`, unique non-zero keys),
signs with exactly a quorum in index order, and re-checks the result under every rule the verifiers
apply before it writes anything. It reproduces the shared vector `upgrade_set1_ok` byte for byte and
rotates the real `EthereumRandBridge` on anvil (`cargo test --test governance`).

**The file is a bearer instrument**: `submitGuardianSetUpgrade` is open to anyone, so whoever holds a
valid rotation can apply it. Produce it only when the rotation is meant to happen, then submit the
SAME file everywhere so all five chains stay on one set index: `rand-bridge-gov submit-evm`
(Ethereum, BSC), `rand-bridge-gov submit-tron`, `rand-bridge-cli guardian-set-upgrade` (Solana), and
on Rand a `BridgeAttest` carrying it (after the bridged chain is cut; its genesis starts at set 0).
A superseded set keeps verifying *transfers* for 86,400 s, so leave a day between rotating away from
exposed keys and whitelisting anything. The Dilithium2 set is not changed by a rotation
(`spec/PQ-COSIGNATURE.md` §5).

## Governance on Rand: pause, unpause, list, register

The Rand-only messages (`spec/PQ-COSIGNATURE.md` §8) are signed by the same tool: `pause` with the
single genesis pause key (`RAND_BRIDGE_PAUSE_KEY_SEED`), `pq-unpause`, `pq-list` and `pq-register`
with a PQ guardian quorum (`--seed-envs`, `--pq-guardians-file`). Each takes the ledger's current
nonce (`rand_getBridgeState`: `pause_nonce` or `list_nonce`) and the chain id, and **on a chain cut
with `binding_domain` (chain 20 onward) the chain's genesis hash**, which the message binds under
the `…-2` tags — without it the fullnode refuses the signature, and the tool refuses to sign:

```sh
# the emergency stop on chain 21: the pause file binds chain 21's genesis
RAND_BRIDGE_PAUSE_KEY_SEED=… rand-bridge-gov pause --rand-chain-id 21 --nonce <pause_nonce> \
    --genesis ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a --out pause.sig
# or read the hash from a node, which is first checked to serve chain 21
rand-bridge-gov pause --rand-chain-id 21 --nonce <pause_nonce> --rand-rpc http://127.0.0.1:8545 --out pause.sig
rand-bridge-gov pq-unpause --rand-chain-id 21 --nonce <pause_nonce> --genesis ca76c276… \
    --pq-guardians-file pq.json --seed-envs PQ_SEED_1,PQ_SEED_2,… --out unpause.json
```

Which form a chain takes is decided by its chain id (`pq_gov::CHAIN_ID_BINDING_CHAIN_IDS`): chains
14–19 sign the chain-id layouts and refuse a `--genesis`; every other chain needs one. Given both
`--genesis` and `--rand-rpc`, the two must agree. The tool prints the form it signed (`binding`) and
the message bytes, so a second person can re-derive them by hand. The wallet carries the files:
`rand bridge-pause --sig @pause.sig`, `rand bridge-unpause --pq @unpause.json`. A pause file is
only ever valid at one nonce on one chain — re-make the kept-ready one after every cut.

## Audit

`rand-bridge-audit --config <any daemon config>` reconciles custody: for each of the seven approved
backings it reads the endpoint's `custody`, its accrued protocol fees and the token balance it really
holds, and — once the Rand node serves per-backing `locked` rows — what Rand says is outstanding. It
checks `balance >= custody + fees` (exit code 1 otherwise) and reports `custody - locked`, which is
zero whenever no message is in flight. Run it against mainnet with `mainnet/relayer.toml`.

## Run

```sh
cargo build --release
GUARDIAN_KEY=0x… target/release/rand-guardian --config guardian.toml
RELAYER_EVM_KEY=0x… RELAYER_TRON_KEY=0x… SOL_KEYPAIR=… target/release/rand-relayer --config relayer.toml
```

Neither daemon starts until its Rand node has answered (BR-401): `rand_chainId` must equal
`rand.chain_id` when it is set — a node that is silent or on another chain stops the daemon with the
reason, it is not skipped over — and the Rand cursor in `data_dir/cursors/rand.json` must not be past
the chain's `burn_sequence` (a cursor kept across a cut, or a node on the wrong chain, used to poll
forever as "caught up"). The poll refuses the same cursor with an error-level log should it ever
happen while running. Fix the cursor or the node; the daemon never rewrites the cursor itself.

`cargo test` pins signing and assembly to the shared vectors byte for byte and, when Foundry is
installed, runs a lock and a release against the real `EthereumRandBridge` on anvil.

Not covered by an automated test yet: the Tron submitter and the Tron log facade (first exercised
on Nile), the Solana and Rand subprocess paths (devnet / a bridged Rand chain).
