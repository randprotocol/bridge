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
- Rebuilds the body from the event plus the block timestamp, the emitter chain id and the
  emitter address (`spec/ATTESTATION.md` §3.2), checks it re-encodes canonically, and signs it
  only if the destination would accept it: registered emitter, `to_chain` / `token_chain` rules,
  `fee <= amount`, non-zero, within `u64`, EVM address padding. A refused message is written to
  `data_dir/refused/` with the reason. **Rotations are never signed by the daemon.**
- Persists the signature before it advances its cursor, and refuses — fatally — to sign a
  second body under an `(emitter chain, sequence)` it has already signed.
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
  not hash to the lock's recipient, so a wrong registration can only fail, never misdirect.
- For a deposit on a chain that lists `pq_guardians`, also collects the co-signatures, verifies
  each under the key at its guardian's index, keeps exactly a quorum and hands it to the wallet
  (`rand bridge-mint @att --pq @pq.json --to …`); short of either quorum nothing is submitted.
- Checks `consumed(digest)` first and treats "already consumed" as done: relayers race, by design.

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

`cargo test` pins signing and assembly to the shared vectors byte for byte and, when Foundry is
installed, runs a lock and a release against the real `EthereumRandBridge` on anvil.

Not covered by an automated test yet: the Tron submitter and the Tron log facade (first exercised
on Nile), the Solana and Rand subprocess paths (devnet / a bridged Rand chain).
