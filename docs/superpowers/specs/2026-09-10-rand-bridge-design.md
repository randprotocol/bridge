# Rand Bridge: design

Date: 2026-09-10
Status: approved design, pre-implementation
Scope: four source-chain custody contracts (Ethereum, BNB Smart Chain, Tron, Solana), the
attestation format they share, and the Rand fullnode changes that mint and burn bridged assets.

Sources: `../whitepapers/randprotocol.tex` Section 8 (`sec:bridge`, lines 500-688) and the
fullnode at `../fullnode` (git rev `92c9684`).

## 1. Goal and non-goals

Goal: a user locks USDT or USDC on Ethereum, BNB Smart Chain, Tron, or Solana and receives the
same amount, 1:1, as a bridged asset on Rand. A holder of a bridged asset on Rand burns it and
receives the locked tokens back on the asset's home chain. Every chain verifies the same
attestation format against the same guardian set.

Non-goals for this pass:

- The guardian daemon and the relayer daemon. The format is fixed here so they can be built
  against it; nothing in this pass runs off-chain except tests and the vector generator.
- Shielded notes. The whitepaper mints into a Poseidon commitment tree; the fullnode has no note
  model yet (see its README roadmap). This pass mints a transparent per-account balance, which
  is the same public boundary the paper describes, and leaves the in-pool step to the shielded
  balance work.
- Source-chain light clients. The paper rules them out for now (line 524).
- Wrapped tokens on source chains. Value only ever flows source -> Rand -> home chain. A source
  contract releases only tokens whose home chain is itself.

## 2. Topology

```
 Ethereum / BSC / Tron / Solana                Guardians (6, secp256k1)               Rand fullnode
 ------------------------------                -------------------------              -------------
 lock(token, amount, randRecipient)  --emit-->  observe after lambda confs,           BridgeAttest tx
                                                sign digest (5 of 6)        --------> verify quorum, mint
 release(attestation)               <--------   sign Rand burn message      <-------- BridgeBurn tx
                                                                                      (debit, emit message)
```

The guardian set is not the validator set (paper line 539). Rand validators sign with Dilithium2,
which no source chain can verify at acceptable gas, so the release path is authorised by guardian
ECDSA signatures on every chain including Rand. The paper's own words apply: a valid quorum
signature is the authorisation, and the guardians are neither bonded nor slashable.

## 3. Attestation format

Shared by all five verifiers (three Solidity, one Solana, one Rust in the fullnode). It is the
Wormhole VAA layout the paper says it follows, with our own chain-id registry and payloads.
All integers are big-endian. No length prefixes; every field is fixed width except `payload`,
which runs to the end of the body.

### 3.1 Envelope

| offset | size | field |
|---|---|---|
| 0 | 1 | `version`, must be 1 |
| 1 | 4 | `guardian_set_index` (u32) |
| 5 | 1 | `n_sigs` (u8) |
| 6 | 66 x n_sigs | signatures, each `guardian_index` (u8), `r` (32), `s` (32), `recovery_id` (u8, 0 or 1) |
| after sigs | rest | `body` |

### 3.2 Body

| size | field |
|---|---|
| 4 | `timestamp` (u32, seconds, source-chain block time) |
| 4 | `nonce` (u32, caller supplied on lock; 0 for Rand and governance messages) |
| 2 | `emitter_chain` (u16, registry below) |
| 32 | `emitter_address` (32 bytes, left-padded for 20-byte addresses) |
| 8 | `sequence` (u64, per emitter, strictly increasing from 0) |
| 1 | `consistency_level` (u8, informational: the depth the emitter asks guardians to wait) |
| rest | `payload` |

### 3.3 Digest and signatures

```
mu = keccak256(keccak256(body))
```

Each signature is secp256k1 ECDSA over `mu` directly, with no prefix. Verifiers require
`s <= secp256k1n / 2` (low-s) and recover an Ethereum-style 20-byte address
`keccak256(pubkey)[12..]` to compare against the guardian set. Keccak is chosen because it is
the only hash that is cheap on the EVM, on the TVM, and as a Solana syscall; the paper leaves the
choice of `H` for `mu` open (it fixes Poseidon only for the commitment tree). BLAKE3 remains
Rand-internal and never appears in an attestation.

### 3.4 Quorum rule

With `n` guardians in the set, `q = floor(2n / 3) + 1`. The verifier requires:

- `n_sigs >= q`
- guardian indices strictly increasing and every index `< n` (paper `lem:bridgenonreplay`)
- each recovered address equals `guardians[guardian_index]`
- the set at `guardian_set_index` exists and is either current or within its 86400 s grace
  period after being superseded

The grace period applies to **transfer payloads (id 1) only**. A guardian set upgrade
(payload id 2) additionally requires `guardian_set_index == current`, so a set that has been
superseded — possibly the very set the rotation is running away from — cannot rotate the bridge
again while its grace window runs. See Section 3.6.

Launch parameters: `n = 6`, `q = 5`.

### 3.5 Chain-id registry

| id | chain | emitter address | token address |
|---|---|---|---|
| 1 | Rand | genesis `bridge.emitter` (32 bytes) | none (Rand emits burns only) |
| 2 | Ethereum | contract address, left-padded | ERC20 address, left-padded |
| 3 | BNB Smart Chain | contract address, left-padded | BEP20 address, left-padded |
| 4 | Tron | 20-byte TVM address (base58check without the 0x41 prefix), left-padded | TRC20 address, same rule |
| 5 | Solana | program id (32 bytes) | mint pubkey (32 bytes) |

Ids are bridge-network ids, unrelated to EVM `chainid`. Testnets and mainnets use the same ids;
the EVM contracts pin `block.chainid` at deployment as a fork guard (Section 5.4).

A governance emitter exists on chain 1 in addition to the Rand burn emitter:

```
GOVERNANCE_EMITTER = keccak256("rand-bridge-governance")   (32 bytes)
```

Keeping the two emitters distinct means a Rand burn message can never satisfy a governance
check or the reverse (paper `rem:emitterindex`: the binding must be a function of authenticated
data only, and here that data is the pair `(emitter_chain, emitter_address)`).

### 3.6 Payloads

Payload id 1, transfer (exactly 133 bytes):

| size | field |
|---|---|
| 1 | `payload_id` = 1 |
| 32 | `amount` (u256, units at 8 decimals) |
| 32 | `token_address` |
| 2 | `token_chain` (home chain of the asset) |
| 32 | `to` (recipient: Rand address, EVM/TVM address left-padded, or Solana pubkey) |
| 2 | `to_chain` |
| 32 | `fee` (u256, relayer fee at 8 decimals, `fee <= amount`) |

Payload id 2, guardian set upgrade:

| size | field |
|---|---|
| 1 | `payload_id` = 2 |
| 4 | `new_index` (u32, must equal current index + 1) |
| 1 | `n` (u8, 1..=255) |
| 20 x n | guardian addresses |

A guardian set upgrade is signed by the current set, carries `emitter_chain = 1`,
`emitter_address = GOVERNANCE_EMITTER`, `sequence = new_index`, `nonce = 0`,
`consistency_level = 0`. It is submitted to every chain independently; each chain checks
`new_index == current + 1` so the same message cannot be applied twice and sets cannot be skipped.

"Signed by the current set" is a rule the verifier enforces, not a convention: a payload-2
message additionally requires `guardian_set_index == current`, checked in addition to the
quorum rule of Section 3.4. The grace window of Section 3.4 covers transfer payloads only, so a
superseded set inside its grace window can still have an in-flight transfer minted but cannot
rotate the guardian set. Every verifier rejects such a message (the Rand ledger as
`Verify(SetExpired)`, the EVM contracts as `GuardianSetExpired`, the Solana program as
`GuardianSetExpired`); the shared vector is `upgrade_signed_by_superseded_set`.

### 3.7 Amounts and decimals

Attestations carry value at `d_max = 8` decimals (paper `lem:normalization`). A source contract
locking a token with `d` decimals computes

```
if d > 8:  locked = floor(amount / 10^(d-8)) * 10^(d-8);  attested = amount / 10^(d-8)
if d <= 8: locked = amount;                                attested = amount * 10^(8-d)
```

and pulls only `locked` from the user, so every custodied unit is covered by an attestation. On
release the contract denormalises the same way. Rand bridged balances are held directly in
attested units (8 decimals) as `u128`; an attested `amount` above `u128::MAX` is rejected.

### 3.8 Emitter binding and replay

Every verifier keeps a table `registered_emitter[chain] -> address` fixed at deployment. A
transfer is accepted only if `emitter_address == registered_emitter[emitter_chain]`, looked up
by the attestation's own `emitter_chain` field (paper `def:emitterbinding`). Source contracts
register exactly one entry, chain 1 -> the Rand emitter. The fullnode registers one entry per
source chain from genesis.

Every verifier records consumed digests `mu` and rejects a second submission.

## 4. Rand asset model

```
AssetId = blake3("shrugg-bridge-asset" || token_chain (u16 BE) || token_address (32))
```

Assets are keyed on `(home chain, token)`, so USDT from Ethereum and USDT from Tron are different
assets with separate custody (paper line 614). Balances are `u128` in 8-decimal units, stored
per `(AssetId, Address)`. The first mint of an asset records its `(token_chain, token_address)`
in an asset registry so a later burn can rebuild the payload.

## 5. Source-chain contracts

### 5.1 Common rules (all four)

Roles:

- `admin`: manages the token whitelist and caps, sets the pauser, unpauses, transfers admin in
  two steps. Intended to be a multisig.
- `pauser`: pauses both lock and release. Cannot unpause. This is the paper's separate pause
  quorum.
- guardians: authorise releases and their own replacement via payload id 2. Anyone may submit
  an attestation.

Immutable at deployment: bridge chain id, Rand emitter address, initial guardian set (index 0).

Per-token config (`setToken`): `enabled`, `per_transfer_cap`, `daily_cap`, both caps in the
token's native units and applied to releases only. Releases are the loss surface; caps on locks
protect nobody. A cap of 0 means unlimited.

Lock (`lock(token, amount, randRecipient, relayerFee, nonce)`):

1. not paused, token enabled, `randRecipient != 0`, `relayerFee <= amount`
2. normalise; require `attested > 0`
3. pull `locked` from the caller, measure the balance delta, require it equals `locked`
   (fee-on-transfer tokens are rejected rather than mis-accounted)
4. `custody[token] += locked`
5. `sequence += 1` and emit the message with `to_chain = 1`, `token_chain = this chain`

Release (`release(attestation)`):

1. not paused
2. parse; verify version, guardian set, quorum, signatures (3.4)
3. `payload_id == 1`, exact payload length
4. emitter binding: `emitter_chain == 1 && emitter_address == RAND_EMITTER`
5. `to_chain == this chain`, `token_chain == this chain`, token enabled
6. digest not consumed; mark consumed
7. denormalise `amount` and `fee`; require `fee <= amount`
8. `custody[token] >= amount`; decrement (paper `thm:custodysoundness`)
9. per-transfer cap and rolling daily cap (window = `timestamp / 86400`)
10. pay `fee` to the submitter, `amount - fee` to `to`

Guardian upgrade (`submitGuardianSetUpgrade(attestation)`): verify as above but require
`guardian_set_index == current` (the grace window of Section 3.4 buys a superseded set nothing
here — it covers transfer payloads only), `emitter_chain == 1`,
`emitter_address == GOVERNANCE_EMITTER`, `payload_id == 2`,
`new_index == current + 1`, `n >= 1`, no zero address, no duplicates. Store the new set, mark
the old one as expiring at `now + 86400`, mark the digest consumed.

Messages are emitted with the emitter's constant `consistency_level`: Ethereum 1 (finalized),
BSC 15, Tron 19 (solidified), Solana 1 (finalized commitment).

### 5.2 Ethereum: `EthereumRandBridge`

Solidity 0.8.20, Foundry. Layout:

```
evm/
  foundry.toml                     evm_version = "paris", optimizer on
  src/RandBridgeBase.sol           all rules above; abstract
  src/EthereumRandBridge.sol       CHAIN_ID = 2, CONSISTENCY = 1
  src/BscRandBridge.sol            CHAIN_ID = 3, CONSISTENCY = 15
  src/TronRandBridge.sol           CHAIN_ID = 4, CONSISTENCY = 19, fork guard disabled
  src/lib/Attestation.sol          parse + digest + signature verification (pure library)
  src/lib/SafeTransfer.sol         transfer / transferFrom tolerant of missing return values (USDT)
  src/interfaces/IRandBridge.sol
  test/                            Foundry tests, including the shared vectors
  script/Deploy.s.sol
```

Events: `MessagePublished(uint64 sequence, uint32 nonce, uint8 consistencyLevel, bytes payload)`
plus `Locked`, `Released`, `TokenConfigured`, `GuardianSetUpgraded`, `Paused`, `Unpaused`.
Guardians rebuild the body from the event plus the block timestamp, the chain id constant, and
the contract address.

Recipient decoding: `to` must have its upper 12 bytes zero.

### 5.3 BNB Smart Chain: `BscRandBridge`

Same source, chain id 3. USDT and USDC on BSC have 18 decimals, so the normalisation path is
exercised for real here; Foundry tests cover an 18-decimal mock.

### 5.4 Tron: `TronRandBridge`

Same source compiled for the Paris EVM (no PUSH0). The base contract's fork guard
(`require(block.chainid == DEPLOY_CHAIN_ID)` in lock and release) is disabled on Tron by an
override, since the TVM's `chainid` support is not relied on. Tron base58check addresses map to
the same 20-byte value after dropping the `0x41` prefix, so the 32-byte encoding is identical to
Ethereum's. Deployment uses TronBox with the Foundry-compiled artifact; a `tron/README.md`
documents the steps. No Tron toolchain is installed on the build machine, so this pass ships the
artifact and instructions but does not deploy.

### 5.5 Solana: `rand_bridge` program

Native `solana-program` Rust (no Anchor; none is installed and native keeps the dependency
footprint small). Tests run under `solana-program-test`, which compiles the program natively and
does not need the SBF toolchain. Layout:

```
solana/
  Cargo.toml                       workspace
  programs/rand-bridge/src/
    lib.rs entrypoint.rs instruction.rs state.rs processor.rs attestation.rs error.rs
  programs/rand-bridge/tests/     program-test integration tests, including the shared vectors
```

PDAs (seeds):

| account | seeds | holds |
|---|---|---|
| Config | `["config"]` | admin, pending admin, pauser, paused, chain id (5), Rand emitter, current guardian set index, sequence |
| GuardianSet | `["guardian", index u32 LE]` | keys (20 bytes each), expiration time |
| TokenRegistry | `["token", mint]` | enabled, per-transfer cap, daily cap, window start, window used, custody count |
| CustodyAuthority | `["authority"]` | signer for custody token accounts |
| Custody | `["custody", mint]` | SPL token account owned by CustodyAuthority |
| Consumed | `["spent", digest]` | existence marks the digest consumed |
| PostedMessage | `["msg", sequence u64 LE]` | the full body bytes, so guardians read durably instead of from logs |

Instructions: `Initialize`, `SetToken`, `Lock`, `Release`, `GuardianSetUpgrade`, `Pause`,
`Unpause`, `TransferAdmin`, `AcceptAdmin`. Signatures are checked with the `secp256k1_recover`
syscall; five recoveries cost about 125k compute units, so clients attach a compute-budget
instruction. Recipient is a wallet pubkey; the program transfers to the recipient's associated
token account, which the caller passes and the program re-derives.

## 6. Fullnode changes (`../fullnode`)

Everything below is gated on an optional `bridge` section in genesis. Chains without it are
unchanged byte for byte: same transaction encodings for existing kinds, same state roots, same
genesis hash.

### 6.1 Genesis

```json
"bridge": {
  "emitter": "<64 hex chars>",
  "guardians": ["<40 hex chars>", ...],
  "emitters": { "2": "<64 hex>", "3": "<64 hex>", "4": "<64 hex>", "5": "<64 hex>" }
}
```

`bincode(bridge)` is appended to the genesis commit when present. `emitters` is the registered
emitter table for source chains and may be partial (a chain without an entry cannot mint).

### 6.2 Transactions

Two variants appended to `TxKind` (tags 4 and 5):

```rust
BridgeAttest { attestation: Vec<u8> }
BridgeBurn { asset: AssetId, amount: u128, to_chain: u16, to: [u8; 32], fee: u128 }
```

`BridgeAttest` is submitted by anyone (a relayer). Payload id 1 credits `amount - fee` to `to`
and `fee` to the submitter for the asset derived from `(token_chain, token_address)`, after the
checks of Section 3 with `to_chain == 1` and `token_chain == emitter_chain` (a source contract
only ever custodies its own chain's tokens, so a registered emitter on one chain must not be able
to mint an asset whose home is another chain). Genesis validation rejects a `bridge` section
whose `emitters` map has an entry for chain 1 or any value equal to `GOVERNANCE_EMITTER`, and
whose guardian list has duplicate or zero keys. Payload id 2 rotates the guardian set. Minimum fee for
`BridgeAttest` is 0 like `Transfer`; the SHRUGG fee still goes to the proposer.

`BridgeBurn` requires the asset to be registered, `to_chain` to equal the asset's home chain,
`amount > 0`, `fee <= amount`, balance `>= amount`, and a usable recipient: `to != 0` on every
chain, and — for the EVM-family chains 2, 3 and 4, whose `to` is a 20-byte address left-padded
to 32 bytes (Section 3.5) — the upper 12 bytes of `to` must be zero. Both are rejected as
`BadRecipient`. A burn is irreversible once guardians sign it, so an unspendable destination is
refused before the message exists rather than left for the source contract to reject on release;
the wallet CLI applies the same two checks before it signs.

A `BridgeAttest` transaction is additionally capped at `MAX_ATTESTATION_BYTES` (16384) and
rejected as `AttestationTooLarge` before anything is decoded, so an oversized blob cannot buy
decode and signature-recovery work at the zero minimum fee. For the same reason, `check_attest`
runs every check that needs no signature recovery first — guardian-set resolution
(`UnknownGuardianSet`, immediately after the decode), then the replay check on the digest, the
emitter binding, the payload's shape, chains and amounts, and a rotation's index — and recovers
the quorum's signatures last (set expiry, index order and quorum, low-s, recovery), so a replayed
(public, already-consumed) or mis-addressed attestation costs a node one keccak rather than a
quorum of secp256k1 recoveries. The set of
accepted attestations is the same either way; only which refusal is reported first differs. The
EVM and Solana verifiers keep the Section 5.1 order, since there the submitter pays for the
recovery. A transfer payload with
`amount == 0` is rejected as `ZeroAmount`, symmetrically with burns: it would consume a digest
and move nothing. Genesis validation additionally rejects a zero value in the `emitters` map.

A valid `BridgeBurn` debits the balance, increments the burn sequence,
and records a `BridgeBurnRecord { sequence, body, digest, tx, height }` whose body is the
Section 3.2 body with `emitter_chain = 1`, `emitter_address = genesis emitter`,
`timestamp = block timestamp_ms / 1000`, `nonce = 0`, `consistency_level = 0`. Guardians read
records over RPC and sign the digest; a source contract releases against it.

### 6.3 Ledger state and state root

`Ledger` gains `bridge: Option<BridgeState>`:

```rust
struct BridgeState {
    emitter: [u8; 32],
    emitters: BTreeMap<u16, [u8; 32]>,
    guardian_sets: BTreeMap<u32, GuardianSet>,   // keys + expires_at (unix seconds, 0 = current)
    current_set: u32,
    balances: BTreeMap<(AssetId, Address), u128>,
    assets: BTreeMap<AssetId, (u16, [u8; 32])>,
    spent: BTreeSet<Hash>,                        // consumed digests
    burn_sequence: u64,
    burns: BTreeMap<u64, BridgeBurnRecord>,       // not part of the state root; derivable
}
```

**Deferral — `burns` growth.** `BridgeState::burns` is kept fully in memory and, because the
ledger is cloned for speculative block execution, cloned with it on every block. Each record is
a few hundred bytes, so the cost is linear in the number of burns the chain has ever produced
and is paid again per speculative execution. This is a known, accepted bound for launch
volumes, not a permanent design: before any chain approaches roughly 100k burns, `burns` must
move out of the cloned ledger — drained into the `bridge_burns` column family per block, with
the ledger holding at most the records of the block in flight. Nothing else depends on it: the
map is excluded from the state root and is derivable from transaction history, so the change is
not a fork.

When `bridge` is `Some`, the state root becomes
`blake3("shrugg-state" || accounts_root || programs_root || bridge_root)` where

```
bridge_root = blake3("shrugg-bridge-state"
    || bincode(emitter, emitters, current_set, guardian_sets)
    || merkle(blake3("shrugg-asset-balance" || asset || addr || balance BE))
    || merkle(blake3("shrugg-asset-registry" || asset || chain BE || token))
    || merkle(sorted spent digests)
    || burn_sequence BE)
```

The ledger also learns the block timestamp (`set_timestamp_ms`, set by `apply_block`) for burn
message timestamps and guardian set grace periods. Because that field now decides whether a
retired guardian set is still inside its grace period, chains with a `bridge` section bound it:
a block whose `timestamp_ms` is lower than its parent's is invalid (`TimestampRewind`), and a
validator rejects a proposal whose `timestamp_ms` exceeds its own clock by more than
30 seconds (`MAX_CLOCK_SKEW_MS`). Equal timestamps are allowed. Proposers always set
`max(now, parent timestamp)`. Chains without a `bridge` section keep their existing validity
rules unchanged.

### 6.4 Storage, RPC, CLI

New RocksDB column families: `bridge_balances` (asset || addr -> u128), `bridge_spent`
(digest -> empty), `bridge_burns` (sequence BE -> record), and a `bridge_meta` blob in `meta`
(guardian sets, current index, asset registry, burn sequence, emitters). `commit` writes the
balances touched by the block's bridge transactions the same way it writes touched accounts;
`load_ledger` rebuilds `BridgeState`; the integrity check compares it like accounts.

RPC:

| method | params | result |
|---|---|---|
| `shrugg_getAssetBalance` | `[address, asset_hex]` | units string |
| `shrugg_getAssets` | `[address]` | `[{asset, token_chain, token_address, balance}]` |
| `shrugg_getBridgeState` | `[]` | `{enabled, emitter, emitters, guardian_set_index, guardians, burn_sequence, assets}` |
| `shrugg_getBridgeBurn` | `[sequence]` | `{sequence, body_hex, digest, tx, height}` or null |
| `shrugg_bridgeAssetId` | `[token_chain, token_address_hex]` | asset id hex |

Wallet CLI: `shrugg bridge-mint <attestation hex or @file>`, `shrugg bridge-burn <asset>
<amount> <to_chain> <to hex> [--fee]`, `shrugg asset-balance [address] <asset>`,
`shrugg bridge-status`.

## 7. Testing

### 7.1 Shared vectors

`tools/vectors` is a Rust binary in this repo that depends on `shrugg-core` by path and writes
`vectors/attestations.json`. Guardian test keys are secp256k1 scalars derived from fixed seeds
and are printed into the file. Each vector has a name, the attestation hex, the expected digest,
the parsed fields, and the expected verdict. Cases:

- valid transfer to Rand from each of chains 2..5, at 6 and 18 decimals
- valid Rand burn release to each source chain
- valid guardian set upgrade, then a transfer signed by the new set, then one by the old set
  inside and outside the grace period
- quorum of 4 (rejected), 5, 6
- duplicate guardian index, decreasing indices, index out of range
- high-s signature, wrong recovery id, signature by a non-guardian
- wrong emitter address, wrong emitter chain with a right address (cross-chain confusion)
- wrong `to_chain`, wrong `token_chain`
- `fee > amount`, amount above `u128::MAX`, bad payload length, unknown payload id, bad version
- an unrecoverable signature (`r = 0`), which every verifier must reject as its own
  BadSignature rather than compare `ecrecover`'s zero return against a guardian key
- a guardian set upgrade signed by a superseded set that is still inside its grace window
  (`upgrade_signed_by_superseded_set`, `expect: "stale_governance_set"`)
- a transfer whose `token_chain` is not its `emitter_chain`
- rejected releases addressed to the Ethereum endpoint: wrong emitter, wrong `to_chain`,
  `fee > amount`, and a replay of a consumed release
- replay of a consumed digest

The fullnode keeps a copy at `crates/shrugg-core/src/bridge/vectors.json` (`include_str!`);
`tools/vectors --check` re-renders the file from the generator and fails if *either* copy
differs from that output, naming the one that drifted — comparing the two copies to each other
alone would pass on two equally stale files.

### 7.2 Per component

- Foundry: unit tests for `Attestation`, the base rules with 6- and 18-decimal mock tokens and a
  USDT-style no-return-value token, custody counter, caps, pause, admin transfer, guardian
  rotation, and the vector file via `vm.parseJson`.
- Solana: `solana-program-test` integration tests covering lock, release, replay, caps, pause,
  rotation, and the vector file.
- Fullnode: ledger unit tests for both transaction kinds, state root determinism with and without
  the bridge section, storage round trip, RPC, and one cluster test that mints on every node.
- Existing fullnode tests must keep passing unchanged, and a chain built from the current
  `deploy/genesis.json` must produce the same genesis hash as before.

## 8. Security notes

- The guardian set is the trust root on every chain. Deployment must place the six keys with
  distinct operators and hardware; no host may hold five.
- Custody counters bound the loss on each chain to what is actually held there, whatever an
  attestation says.
- Guardian upgrades cannot skip indices and old sets expire after a day, limiting the window in
  which a leaked old key set matters.
- The Rand recipient field has no checksum (base58 of 32 raw bytes). Wallets must verify the
  32-byte round trip before calling lock; the contracts can only reject zero.
- **Residual: a 2/3 leader coalition can stop the bridge's clock.** On a bridged chain the block
  `timestamp_ms` is consensus input, but it is only bounded from below by "not earlier than the
  parent" — equal timestamps are legal (Section 6.3), because two blocks can honestly land in
  the same millisecond and a proposer sets `max(now, parent)`. A colluding two thirds of leaders
  can therefore hold `timestamp_ms` constant indefinitely: outbound burn messages all carry the
  frozen timestamp, and a superseded guardian set never leaves its 86400 s grace window, so a
  set the guardians have rotated away from keeps minting transfers for as long as the coalition
  holds. Making equal timestamps invalid would not fix this (a coalition can advance the clock
  by one millisecond per block just as easily) and would stall an honest chain whose clock has
  not ticked. The exposure is bounded by what the guardian quorum can do in the first place, and
  a chain whose leaders are 2/3 dishonest has lost more than its bridge; it is recorded here as
  a known consequence of the timestamp rule, not as a defended property.
- Attestations are ECDSA and therefore not post-quantum, as the paper states (`thm:bridgepq`).
  The Rand-side verifier is the natural place to add ML-DSA later since Rand already verifies
  Dilithium.
