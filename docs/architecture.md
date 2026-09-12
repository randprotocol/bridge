# Rand bridge: architecture

This is the end-to-end description of the Rand bridge as built: the four source-chain endpoints
(Ethereum, BNB Smart Chain, Tron, Solana), the guardian attestation they share, and the Rand
fullnode's bridge code that mints and burns bridged assets. It covers what each component holds,
what it checks, in which order, and how the pieces are kept in agreement.

Companion documents:

| document | what it is |
|---|---|
| `spec/ATTESTATION.md` | the attestation wire format, normative, with a worked byte-by-byte example |
| `docs/superpowers/specs/2026-09-10-rand-bridge-design.md` | the design this was built from; amended during implementation |
| `README.md` | layout, build, deployment order, status |
| `evm/README.md`, `tron/README.md`, `solana/README.md` | per-endpoint build and deployment notes |
| `../fullnode/docs/bridge.md` | the fullnode's own description of its bridge code |
| `../fullnode/docs/rpc.md`, `../fullnode/docs/cli.md` | RPC method shapes and wallet commands |

Revision described: bridge repo `fca2229` and later, fullnode `main` at `dbea18c` (bridge code
unchanged since `273e13d`).

---

## 1. What the bridge is

A user locks USDT or USDC on Ethereum, BNB Smart Chain, Tron, or Solana and receives the same
amount, 1:1, as a bridged asset on Rand. A holder of a bridged asset burns it on Rand and receives
the locked tokens back on the asset's home chain. Value flows source chain -> Rand -> that same
source chain, never between two source chains, and there are no wrapped tokens on source chains.

The mechanism is a guardian-attestation bridge in the Wormhole shape. A fixed committee of six
secp256k1 keys observes a lock or burn once it has cleared the emitting chain's confirmation
depth, signs a digest over the message, and any relayer submits the resulting attestation to the
destination's verifier. Five verifiers parse and check the same bytes identically: three Solidity
contracts (Ethereum, BSC, Tron), one Solana program, and the Rand fullnode.

```mermaid
flowchart LR
    subgraph SRC["Source chain (2 Ethereum, 3 BSC, 4 Tron, 5 Solana)"]
        L[lock] --> C[(custody)]
        C --> R[release]
    end
    subgraph G["Guardians (6 keys, 5-of-6)"]
        S[sign mu = keccak256²(body)]
    end
    subgraph RAND["Rand fullnode (chain 1)"]
        A[BridgeAttest tx] --> B[(BridgeState)]
        B --> BU[BridgeBurn tx]
    end
    L -- "MessagePublished / PostedMessage" --> S
    S -- "attestation, payload 1" --> A
    BU -- "BridgeBurnRecord over RPC" --> S
    S -- "attestation, payload 1" --> R
    GOV[governance emitter] -- "payload 2, signed by current set" --> S
    S -. "rotation, submitted to every chain" .-> R
    S -. "rotation" .-> A
```

The guardians are not the Rand validator set. Rand validators sign with Dilithium2, which no
source chain can verify at acceptable cost, so authorisation on every chain including Rand is a
quorum of guardian ECDSA signatures. Guardians are neither bonded nor slashable; a valid quorum
signature is the whole authorisation.

### 1.1 Trust model and its bounds

The guardian committee is the trust root on every chain. If `n*2/3 + 1` guardians collude they
can mint arbitrary value on Rand or authorise an illegitimate rotation; nothing detects or resists
that. Three independent bounds sit under the guardians on each source chain:

- **Per-token whitelist.** Only tokens the admin has enabled can be locked or released.
- **Custody counter.** Each endpoint counts what it holds per token and never releases more,
  whatever an attestation says. A compromised committee can drain what an endpoint holds, not
  more.
- **Release caps.** Per-transfer and rolling daily caps, on releases only. Locks are not capped:
  releases are the loss surface.

On Rand there is no custody to bound. A mint credits a per-account balance keyed by
`(home chain, token)`; the bound is that a burn back to the home chain can only release what
that chain's endpoint actually custodies.

Two more rules harden against a partially compromised committee:

- A guardian-set rotation must be signed by the *current* set. The grace window after a rotation
  covers transfers only, so a set the guardians have just rotated away from cannot rotate the
  bridge back.
- Rotations cannot skip indices, and a superseded set expires 86,400 seconds after being replaced.

Every component here is reviewed but unaudited, and the guardian and relayer daemons that would
run the format end to end are not built. Nothing has watched a real chain or moved real funds.

---

## 2. Repository map

Two repositories. The bridge repo holds the source-chain endpoints, the shared vectors and their
generator, and the spec. The fullnode repo holds the wire-format crate and the Rand-side ledger
code; the Solana program depends on the wire-format crate by path.

```
bridge/
  spec/ATTESTATION.md            wire format reference
  evm/
    src/RandBridgeBase.sol       every Section 5.1 rule; abstract
    src/EthereumRandBridge.sol   chain 2, consistency 1
    src/BscRandBridge.sol        chain 3, consistency 15
    src/TronRandBridge.sol       chain 4, consistency 19, fork guard off
    src/lib/Attestation.sol      parse, digest, signature verification
    src/lib/SafeTransfer.sol     ERC20 calls tolerant of missing return values
    src/interfaces/IRandBridge.sol
    script/Deploy.s.sol          one endpoint, chosen by CHAIN
    test/                        Foundry tests, including the shared vectors
  tron/                          TronBox wiring around the same source
  solana/programs/rand-bridge/
    src/state.rs                 accounts and PDA seeds
    src/instruction.rs           BridgeInstruction and client builders
    src/processor.rs             the rules
    src/attestation.rs           digest, secp256k1_recover, quorum
    src/error.rs                 BridgeError
    tests/                       solana-program-test suites, including the vectors
  tools/vectors/                 generator for the shared vectors
  vectors/attestations.json      the vectors (39)

fullnode/crates/
  bridge-codec/                  no_std, zero-dependency wire codec
    src/lib.rs                   constants, quorum, check_indices, is_low_s
    src/envelope.rs              Signature, Body, Attestation
    src/payload.rs               Transfer, GuardianSetUpgrade, Payload
  shrugg-core/src/bridge/
    mod.rs                       keccak, digest, asset_id, recover, verify
    state.rs                     BridgeConfig, BridgeState, check/apply, root
    vectors.json                 byte-identical copy of the vectors
  shrugg-core/src/ledger.rs      TxKind dispatch, state root, block timestamp rule
  shrugg-core/src/genesis.rs     the bridge genesis section and its validation
  shrugg-node/src/storage.rs     RocksDB column families
  shrugg-node/src/rpc.rs         five bridge RPC methods
  shrugg-client/                 wallet CLI commands
```

---

## 3. The attestation

`spec/ATTESTATION.md` is normative. This section summarises what every verifier depends on.

### 3.1 Bytes

All integers are big-endian, every field fixed width except the payload, which runs to the end
of the body. No length prefixes.

```
envelope   version(1)=1 | guardian_set_index(4) | n_sigs(1) | signatures(66 x n_sigs) | body
signature  guardian_index(1) | r(32) | s(32) | recovery_id(1)
body       timestamp(4) | nonce(4) | emitter_chain(2) | emitter_address(32) | sequence(8) | consistency_level(1) | payload
payload 1  id(1)=1 | amount(32) | token_address(32) | token_chain(2) | to(32) | to_chain(2) | fee(32)     exactly 133 bytes
payload 2  id(1)=2 | new_index(4) | n(1) | keys(20 x n)
```

The digest guardians sign is `mu = keccak256(keccak256(body))`, over the body bytes exactly as
they appear on the wire. Signatures are secp256k1 ECDSA over `mu` with no prefix, low-s only.
A guardian's identity is the Ethereum-style address `keccak256(pubkey)[12..]`.

### 3.2 Quorum

For a set of `n` keys the quorum is `q = n*2/3 + 1` (integer division), so 5 of 6 at launch. A
verifier requires `n_sigs >= q`, guardian indices strictly increasing and each `< n`, every
recovered address equal to `keys[index]`, and the named guardian set to be either current or a
superseded set still inside its 86,400 second grace window. The grace window applies to transfer
payloads only.

### 3.3 Chain ids and emitters

| id | chain | emitter address | token address |
|---|---|---|---|
| 1 | Rand | genesis `bridge.emitter` | none |
| 2 | Ethereum | contract address, left-padded to 32 | ERC20 address, left-padded |
| 3 | BNB Smart Chain | contract address, left-padded | BEP20 address, left-padded |
| 4 | Tron | 20-byte TVM address without the `0x41` prefix, left-padded | TRC20 address, same |
| 5 | Solana | program id | mint pubkey |

These are bridge-network ids, unrelated to EVM `chainid`. A second emitter exists on chain 1 for
governance: `GOVERNANCE_EMITTER = keccak256("rand-bridge-governance")`, pinned as a literal in
`bridge-codec` and cross-checked against the string by tests in the fullnode and the Solana
program. Only a payload-2 message may claim `(1, GOVERNANCE_EMITTER)`; a burn message from the
Rand emitter can never satisfy a governance check or the reverse.

### 3.4 Amounts

Attestations carry value at 8 decimals. An endpoint locking a token with `d` decimals computes

```
d > 8:   attested = amount / 10^(d-8);  locked = attested * 10^(d-8)   (dust stays with the user)
d <= 8:  attested = amount * 10^(8-d);  locked = amount
```

and pulls only `locked`, so every custodied unit is covered by an attestation. Release
denormalises the same way. The three implementations differ in their integer width:

| verifier | wire amount | native amount | overflow behaviour |
|---|---|---|---|
| EVM | `uint256` | `uint256` | none needed; `MAX_DECIMALS = 36` bounds `10**(d-8)` |
| Solana | `u256` unpacked to `u128` | `u64` | `AmountOverflow` if the native value exceeds `u64` |
| Rand | `u256` unpacked to `u128` | `u128`, no denormalisation | `AmountOverflow` if the top 16 bytes are non-zero |

---

## 4. Message lifecycles

### 4.1 Source chain to Rand

```mermaid
sequenceDiagram
    participant U as User
    participant E as Endpoint (chain k)
    participant G as Guardians
    participant R as Relayer
    participant N as Rand fullnode
    U->>E: lock(token, amount, randRecipient, relayerFee, nonce)
    E->>E: normalise, pull `locked`, custody += locked
    E-->>G: MessagePublished(seq, nonce, consistency, payload) / PostedMessage PDA
    G->>G: wait `consistency_level` depth, rebuild body, sign mu (5 of 6)
    G-->>R: attestation
    R->>N: BridgeAttest { attestation } (SHRUGG fee, min 0)
    N->>N: check_attest: cheap checks, then signatures
    N->>N: spent += mu; balances[asset][to] += amount - fee; balances[asset][relayer] += fee
```

The body the guardians sign is rebuilt from the event plus the block timestamp, the endpoint's
chain-id constant, and its address. On Solana the full body is written to a `PostedMessage` PDA
so guardians read it durably rather than from logs.

### 4.2 Rand to home chain

```mermaid
sequenceDiagram
    participant H as Holder
    participant N as Rand fullnode
    participant G as Guardians
    participant R as Relayer
    participant E as Endpoint (home chain)
    H->>N: BridgeBurn { asset, amount, to_chain, to, fee }
    N->>N: check_burn: registered asset, to_chain == home, recipient shape, fee <= amount, balance
    N->>N: balance -= amount; burn_sequence += 1; record BridgeBurnRecord { body, digest }
    G->>N: shrugg_getBridgeBurn(sequence)
    G->>G: sign digest (5 of 6)
    G-->>R: attestation
    R->>E: release(attestation)
    E->>E: verify, emitter == (1, randEmitter), to_chain == token_chain == self
    E->>E: consumed[mu] = true; custody -= amount; caps
    E->>H: amount - fee to `to`, fee to relayer
```

The burn body has `emitter_chain = 1`, `emitter_address = genesis emitter`, `timestamp = block
timestamp_ms / 1000`, `nonce = 0`, `consistency_level = 0`, and a payload-1 transfer whose
`token_chain` and `token_address` come from the asset registry.

### 4.3 Guardian rotation

A payload-2 message signed by the current set, carrying `(1, GOVERNANCE_EMITTER)`,
`sequence = new_index`, `nonce = 0`, `consistency_level = 0`. It is submitted to each chain
independently; each checks `new_index == current + 1`, installs the new set with no expiry,
gives the old set `expires_at = now + 86_400`, and marks the digest consumed. In-flight transfers
signed by the old set stay redeemable for a day; a second rotation signed by the old set is
refused on every chain.

---

## 5. Verification: the shared rule set and where each verifier orders it

Only the accept/reject decision is normative across verifiers: for any attestation, all five must
agree on whether it is valid. Which rejection is reported first is allowed to differ, and does,
because the cost model differs. On the EVM and Solana the submitter pays for signature recovery,
so the endpoints verify signatures early. On Rand the minimum fee for `BridgeAttest` is zero, so
the fullnode runs every check that needs no recovery first.

| step | EVM `release` | Solana `Release` | Rand `check_attest` |
|---|---|---|---|
| 1 | fork guard, not paused | account and PDA checks, custody account shape, not paused | size cap (16 KiB), bridge enabled |
| 2 | parse envelope | read `guardian_set_index` from the envelope | decode envelope once |
| 3 | guardian set exists; current or in grace | guardian set PDA exists and matches; current or in grace | guardian set exists (`UnknownGuardianSet`) |
| 4 | quorum, low-s, recover, compare | decode, expiry, quorum, low-s, recover, compare | replay (`spent` contains `mu`) |
| 5 | not consumed | not consumed (`["spent", mu]` PDA empty) | payload decodes |
| 6 | emitter `(1, randEmitter)` | emitter `(1, rand_emitter)` | emitter is the registered one for `emitter_chain` |
| 7 | payload 1, `to_chain == token_chain == self`, `fee <= amount` | payload 1, `to_chain == token_chain == 5`, `fee <= amount` | `token_chain == emitter_chain`, `to_chain == 1`, amounts fit `u128`, `fee <= amount`, `amount != 0` |
| 8 | token enabled, recipient shape, denormalise, `amount != 0` | mint matches, token enabled, recipient and relayer ATAs, denormalise, `amount != 0` | credited balances do not overflow |
| 9 | custody, per-transfer cap, daily cap | custody, per-transfer cap, daily cap | set expiry, quorum, low-s, recover, compare |
| effects | consumed, custody, window | consumed PDA, custody, window | spent, assets registry, balances |
| interactions | fee to submitter, rest to `to` | fee to relayer ATA, rest to recipient ATA | none |

Every path writes its effects before any external call. On the EVM the digest is marked consumed
and custody decremented before the token transfers, so a token with a transfer hook cannot
re-enter a second release of the same attestation; the Solana program does the same before its
token CPIs.

The signature half is the same algorithm in all three: set expiry (`now > expires_at` with
`expires_at == 0` meaning current), then `check_indices` (quorum count, strictly increasing
indices, each in range), then per signature low-s, recovery, and comparison against
`keys[index]`. The Rand and Solana implementations share `bridge-codec`'s `check_indices` and
`is_low_s`; `Attestation.sol` reimplements them.

---

## 6. The EVM endpoints

Solidity 0.8.20, compiled for the Paris EVM so the same bytecode target works on the TVM, which
lacks `PUSH0`. One abstract base holds every rule; the three concrete contracts pin two constants
and, on Tron, drop the fork guard.

| contract | chain id | consistency level | fork guard |
|---|---|---|---|
| `EthereumRandBridge` | 2 | 1 (finalized) | on |
| `BscRandBridge` | 3 | 15 blocks | on |
| `TronRandBridge` | 4 | 19 (solidified) | off: the TVM's `chainid` is not dependable |

### 6.1 Storage

| field | meaning |
|---|---|
| `DEPLOY_CHAIN_ID` (immutable) | `block.chainid` at construction; `lock` and `release` revert `WrongFork` if it changes |
| `randEmitter` (immutable) | the one registered emitter: chain 1's burn emitter from Rand genesis |
| `admin`, `pendingAdmin`, `pauser`, `paused` | roles |
| `currentGuardianSetIndex`, `_guardianSets[index]` | keys plus `expirationTime` (0 = current) |
| `_tokenConfigs[token]` | `enabled`, `decimals`, `perTransferCap`, `dailyCap`, `windowStart`, `windowUsed` |
| `custody[token]` | what this endpoint holds, by its own count |
| `consumed[digest]` | replay set |
| `sequence` | next outbound message number, from 0 |

### 6.2 Roles

- **admin** (a multisig): `setToken`, `setPauser`, `unpause`, two-step `transferAdmin` /
  `acceptAdmin`. `acceptAdmin` is where the zero check lives, so a cancelled transfer
  (`transferAdmin(0)`) has nothing to accept.
- **pauser**: `pause` only. The pauser or the admin can stop both lock and release; only the admin
  restarts. This is the design's separate pause quorum.
- **guardians**: authorise releases and their own replacement. Anyone may submit an attestation.

`submitGuardianSetUpgrade` is deliberately not gated on `paused` or on the fork guard: neither
should stand between the guardians and rotating away from a compromised set.

### 6.3 Token configuration

`setToken(token, enabled, perTransferCap, dailyCap)` whitelists a token and records its
`decimals()` at that moment, read through a defensive `staticcall`: a token that does not answer,
or answers above `MAX_DECIMALS = 36`, cannot be whitelisted. `decimals()` is read only when
enabling, so disabling a token that has stopped answering, or lost its code, always works. The
daily window counters are left untouched on reconfiguration so changing a cap cannot reset the
day's usage. Caps are in the token's native units; 0 means unlimited.

### 6.4 `lock`

1. fork guard, not paused, token enabled, `randRecipient != 0`, `relayerFee <= amount`
2. normalise `amount`; `attested != 0`; normalise `relayerFee` the same way (it rounds down with
   the amount, so it stays `<= attested`)
3. pull `locked` and measure the balance delta; a mismatch reverts `TransferAmountMismatch`, so a
   fee-on-transfer token is rejected rather than mis-accounted
4. `custody[token] += locked`
5. emit `MessagePublished(sequence, nonce, consistencyLevel, payload)` and `Locked(...)` with
   `to_chain = 1`, `token_chain = this chain`; `sequence += 1`

The Rand recipient is 32 raw bytes with no checksum; the contract can only reject zero. Wallets
must verify the round trip before calling.

### 6.5 `release`

Steps as in the table in Section 5. Two decoding rules are specific to EVM-family chains: a
`token_address` or `to` with anything in its upper 12 bytes names a different address space and
reverts `BadTokenAddress` or `BadRecipient`, and a zero recipient reverts `ZeroRecipient`. Attested
dust that denormalises to zero native units reverts `ZeroAmount` rather than consuming the digest
for nothing, which leaves the burn re-submittable if the token is later reconfigured. The daily
window is `block.timestamp / 1 days`.

### 6.6 Deployment

`script/Deploy.s.sol` reads `CHAIN` (`ethereum`, `bsc`, `tron`), `ADMIN`, `PAUSER`, `RAND_EMITTER`,
`GUARDIANS` (comma-separated, in index order), and optionally `EXPECTED_CHAIN_ID`. Because
`DEPLOY_CHAIN_ID` is baked in and guards every later call, the script refuses to deploy the
Ethereum or BSC contract to a network whose `chainid` is not the expected one (1 and 56 by default).
Tron is compiled here but deployed with TronBox from the same source; see `tron/README.md` for the
base58check-to-20-byte conversion, the migration's environment, and the post-deploy steps.

---

## 7. The Solana program

A native `solana-program` crate, no Anchor. Tests run under `solana-program-test`, which compiles
the program natively against a real bank and the real SPL token program, so the suite needs no
SBF toolchain. The deployable `.so` has never been built here: `cargo build-sbf` is unavailable
on the development machine. `lib.rs` pins a vanity program id with no known secret; a real
deployment re-declares its own before building, since every PDA derives from it.

### 7.1 Accounts

Every account the program owns is a one-byte discriminator followed by a Borsh body; `load`
checks the program owns the account and the discriminator matches before deserialising.

| account | seeds | discriminator | holds |
|---|---|---|---|
| `Config` | `["config"]` | 1 | admin, pending admin, pauser, paused, `rand_emitter`, `current_guardian_set`, `sequence`, bump |
| `GuardianSetAccount` | `["guardian", index u32 LE]` | 2 | index, keys, `expiration_time` (0 = current) |
| `TokenRegistry` | `["token", mint]` | 3 | mint, enabled, decimals, per-transfer cap, daily cap, window start (day index), window used, custody |
| custody authority | `["authority"]` | none (no data) | the SPL signer for custody accounts |
| custody | `["custody", mint]` | SPL token account | owned by the authority PDA |
| `Consumed` | `["spent", digest]` | 4 | existence marks the digest consumed |
| `PostedMessage` | `["msg", sequence u64 LE]` | 5 | the full body bytes of one outbound message |

Every account passed to an instruction is re-derived and compared; the wrong one fails with
`InvalidPda`, or `InvalidAta` for the two associated token accounts a release pays into. The
custody token account is additionally unpacked and checked on every path that reads or moves it:
SPL-owned, authority equal to the authority PDA, mint equal to the named mint.

### 7.2 Instructions

| instruction | signer | notes |
|---|---|---|
| `Initialize { admin, pauser, rand_emitter, guardians }` | the program's **upgrade authority** | one-shot; creates `Config` and guardian set 0 |
| `SetToken { enabled, per_transfer_cap, daily_cap }` | admin | creates the registry and the custody token account the first time |
| `Lock { amount, rand_recipient, relayer_fee, nonce }` | token owner | writes a `PostedMessage` at the config's current `sequence` |
| `Release { attestation }` | relayer | pays into the recipient's and relayer's associated token accounts |
| `GuardianSetUpgrade { attestation }` | any payer | allowed while paused |
| `Pause` | pauser or admin | |
| `Unpause` | admin | |
| `TransferAdmin { to }` | admin | `to == default` cancels |
| `AcceptAdmin` | pending admin | |

`Initialize` has no config to check a role against, so it authenticates against the program's
ProgramData account under the upgradeable loader: the payer must be the recorded upgrade
authority, or anyone watching the mempool could initialise a freshly deployed program and own the
bridge. Deploy, initialise with the same key, then hand the authority to a multisig; a program
made immutable before initialisation can never be initialised.

### 7.3 Behaviour specific to Solana

- **Griefing-resistant PDA creation.** Every PDA the program creates is derived from public data,
  so anyone can send it a lamport first, and `CreateAccount` refuses a funded account. The program
  therefore tops up, allocates and assigns instead when an account already holds lamports; it
  still requires the account to be empty and system-owned.
- **Two locks in the same slot** name the same `["msg", sequence]` PDA. The second fails with
  `InvalidPda`, nothing is locked, and the client re-reads `sequence` and retries.
- **Compute budget.** Five recoveries cost about 125k compute units; clients prepend a
  compute-unit-limit instruction.
- **`u64` native amounts.** Denormalising an 18-decimal mint's amount can overflow `u64` and is
  rejected as `AmountOverflow`.
- **Upgrade guardian set index** is read straight from the envelope before decoding, because it
  selects which guardian set account must have been passed.

---

## 8. The Rand fullnode

Everything bridge-related is gated on an optional `bridge` section in genesis. A chain without
one has the same transaction encodings, the same state roots, and the same genesis hash as a
pre-bridge node, byte for byte. Enabling the bridge is a hard fork.

### 8.1 `bridge-codec`

A `no_std` + `alloc` crate with zero dependencies: the single source of truth for the byte layout,
shared by path with the Solana program. It deliberately performs no hashing and no ECDSA; callers
inject keccak256 and a secp256k1 recoverer.

| item | role |
|---|---|
| `CHAIN_RAND..CHAIN_SOLANA`, `VERSION = 1`, `TRANSFER_PAYLOAD_LEN = 133`, `GUARDIAN_GRACE_SECS = 86_400` | constants |
| `GOVERNANCE_EMITTER`, `SECP256K1_HALF_N` | pinned literals |
| `Signature`, `Body`, `Attestation` with `encode` / `decode` | envelope |
| `Attestation::body_bytes(bytes)` | the wire body slice, exactly what is hashed, never a re-encoding |
| `Transfer`, `GuardianSetUpgrade`, `Payload` with `encode` / `decode` | payloads; `amount_u128` / `fee_u128` return `None` above `u128` |
| `quorum(n)`, `check_indices(sigs, n)`, `is_low_s(s)` | the arithmetic every verifier shares |
| `CodecError` | `BadVersion`, `Truncated`, `BadPayloadId`, `BadPayloadLength`, `TooManyGuardians`, `ZeroGuardians`, `TrailingBytes` |

The codec does not check `new_index == current + 1`, key uniqueness, or non-zero keys, and does
not enforce left-padding: those are policy, owned by the verifiers.

### 8.2 `shrugg-core::bridge`

`mod.rs` supplies what the codec leaves out: `keccak256`, `digest`, `asset_id`,
`recover_address` (rejects `v > 1`), `sign_digest` and `guardian_address` for tests and the
vector generator, and the verifier. `verify_decoded` takes an already-decoded envelope plus the
wire body bytes so `check_attest` decodes once; `verify` is the thin wrapper used by tests and
the vector self-check.

`state.rs` is the bridge ledger, pure state-transition logic with no persistence:

```rust
pub struct BridgeState {
    pub emitter: [u8; 32],                              // Rand's outbound emitter
    pub emitters: BTreeMap<u16, [u8; 32]>,              // registered emitter per source chain
    pub guardian_sets: BTreeMap<u32, GuardianSet>,      // keys + expires_at (0 = current)
    pub current_set: u32,
    pub balances: BTreeMap<(AssetId, Address), u128>,   // bridged units, 8 decimals
    pub assets: BTreeMap<AssetId, (u16, [u8; 32])>,     // asset -> (home chain, token)
    pub spent: BTreeSet<Hash>,                          // consumed digests
    pub burn_sequence: u64,
    pub burns: BTreeMap<u64, BridgeBurnRecord>,         // outbound log; not in the root
}
```

`AssetId = blake3("shrugg-bridge-asset" || token_chain BE || token_address)`, so USDT from
Ethereum and USDT from Tron are distinct assets with distinct custody. The registry is populated
lazily by the first mint of each asset and read by burns to rebuild the payload.

The four transition functions:

- `check_attest(bytes, submitter, now) -> (Attestation, mu, Payload)` runs the Rand column of the
  Section 5 table. For a transfer it also pre-computes the credited balances so a `u128` overflow
  is caught before any state changes. For a rotation it requires `guardian_set_index ==
  current_set`, `new_index == current_set + 1`, and unique non-zero keys.
- `apply_attest` calls `check_attest` and then, for a transfer, inserts `mu` into `spent`,
  registers the asset if new, and writes the credited balances (`amount - fee` to `to`, `fee` to
  the submitter). For a rotation it inserts `mu`, sets the old current set's `expires_at = now +
  86_400`, installs the new set with `expires_at = 0`, and advances `current_set`.
- `check_burn(from, asset, amount, to_chain, to, fee)` requires a registered asset, `to_chain`
  equal to the asset's home chain, a non-zero recipient, zero upper 12 bytes when `to_chain` is
  2, 3 or 4, `fee <= amount`, `amount != 0`, and a sufficient balance. The recipient screening
  happens here because a burn is irreversible once guardians sign it.
- `apply_burn` debits the balance (removing the row at zero), builds the Section 4.2 body,
  records `BridgeBurnRecord { sequence, body, digest, tx, height }`, and increments
  `burn_sequence`.

`root()` is the consensus commitment:

```
blake3("shrugg-bridge-state"
    || bincode(emitter, emitters, current_set, guardian_sets)
    || merkle(blake3("shrugg-asset-balance" || asset || addr || balance BE))   // zero balances pruned
    || merkle(blake3("shrugg-asset-registry" || asset || chain BE || token))
    || merkle(sorted spent digests)
    || burn_sequence BE)
```

`burns` is excluded because it is derivable from transaction history. A test pins the root of a
fixed state to a constant; changing it is a hard fork, never a test to re-baseline. `BridgeMeta`
is the whole-state half (everything but `balances`, `spent`, `burns`), split here so a new field
must be classified as meta or per-row or the build breaks.

### 8.3 Ledger integration

Two `TxKind` variants appended after `Call`, so existing tags keep their bincode encoding:

| tag | variant | fields |
|---|---|---|
| 4 | `BridgeAttest` | `attestation: Vec<u8>` |
| 5 | `BridgeBurn` | `asset: AssetId, amount: u128, to_chain: u16, to: [u8; 32], fee: u128` |

Both pay the flat SHRUGG fee only, minimum 0 like `Transfer`; the value they move is a bridged
asset. `validate_inner` checks `attestation.len() <= MAX_ATTESTATION_BYTES` (16,384) before
parsing anything, then bridge presence (`BridgeError::Disabled`), then `check_attest` or
`check_burn`. `apply_tx_with_receipt` debits the fee and calls `apply_attest` or `apply_burn`.
Bridged balances are a separate per-asset ledger; moving one never touches a SHRUGG account
balance.

When a bridge exists the state root becomes `blake3(accounts_root || programs_root ||
bridge_root)`; without one it stays the 64-byte pre-bridge form. The genesis hash appends
`bincode(BridgeCommit)`, a plain-bytes twin of the human-readable `BridgeConfig`, only when the
section is present.

### 8.4 Genesis

```json
"bridge": {
  "emitter":   "<64 hex>",
  "guardians": ["<40 hex>", "..."],
  "emitters":  { "2": "<64 hex>", "3": "<64 hex>", "4": "<64 hex>", "5": "<64 hex>" }
}
```

Built with `shrugg-node genesis --bridge bridge.json`. `check_bridge` rejects an empty guardian
set, a duplicate or zero guardian, a zero emitter, an emitter equal to the governance emitter,
chain 1 in `emitters`, a source emitter equal to the governance emitter, and a zero source
emitter. `emitters` may be partial: a chain without an entry can accept locks but cannot mint on
Rand. Guardian set 0 is installed as current with `expires_at = 0`.

### 8.5 Block time on a bridged chain

Guardian-set expiry and burn timestamps read the block's `timestamp_ms`, so on a bridged chain it
becomes consensus input: `apply_block` rejects a block whose timestamp is lower than its
parent's (`TimestampRewind`), a validator rejects a proposal more than 30 seconds ahead of its
own clock, and proposers set `max(now, parent)`. Equal timestamps are allowed. Every ledger built
from a head block carries that block's timestamp, so expiry is never evaluated at `now = 0`.
Chains without a bridge keep their previous rules unchanged.

### 8.6 Storage, RPC, wallet

Storage adds three RocksDB column families and one meta key:

| location | key | value |
|---|---|---|
| `bridge_balances` | `asset \|\| address` | `bincode(u128)`; row deleted at zero |
| `bridge_spent` | digest | empty |
| `bridge_burns` | sequence BE | `bincode(BridgeBurnRecord)` |
| `meta["bridge_state"]` | | `bincode(BridgeMeta)`; its presence marks a bridged database |

A block commit touches only the rows its bridge transactions moved. An undecodable payload on the
commit path is a `Corrupt` error, never a silent skip. The startup integrity check compares the
stored bridge with the replayed one separately from the root, because the root omits the burn
log. A database predating the bridge initialises its state fresh from genesis.

RPC methods, all in `docs/rpc.md` of the fullnode:

| method | params | result |
|---|---|---|
| `shrugg_getAssetBalance` | `[address, asset]` | decimal string of bridged units; `"0"` if unknown |
| `shrugg_getAssets` | `[address]` | every non-zero bridged holding |
| `shrugg_getBridgeState` | `[]` | emitter, emitters, guardian set, assets, `burn_sequence`; `{"enabled": false}` without a bridge |
| `shrugg_getBridgeBurn` | `[sequence]` | one outbound record, or `null` |
| `shrugg_bridgeAssetId` | `[token_chain, token_address]` | the asset id; a pure function, answers on any chain |

Wallet commands: `bridge-mint <attestation hex or @file>`, `bridge-burn <asset> <amount>
<to_chain> <to> [--bridge-fee]`, `asset-balance [address] <asset>`, `bridge-status`. The wallet
applies the same recipient checks as `check_burn` before signing. Bridged amounts are plain
integers of 8-decimal units, not SHRUGG's 9-decimal strings.

---

## 9. Shared test vectors

`tools/vectors` is a Rust binary that depends on `shrugg-core` by path and writes
`vectors/attestations.json` plus the fullnode copy at
`crates/shrugg-core/src/bridge/vectors.json`. `cargo run --release -- --check` re-renders from the
generator and fails if either file differs, naming the one that drifted; comparing the two files
to each other would pass on two equally stale copies.

File layout: `guardians` (six test secrets and addresses), `governance_emitter`, `rand_emitter`,
`emitters` (a registered address per source chain), `now`, and 39 `vectors`. Each vector carries
its name, attestation hex, digest, `verifier_chain`, `guardian_set_index`, the guardian `sets` in
force, `current_set`, `expect`, the decoded body and payload, and `replay_of` when it is a replay.

`expect` names the rule, not any verifier's error code:

| expect | count | what it exercises |
|---|---|---|
| `ok` | 13 | transfers in from chains 2 to 5 at 6 and 18 decimals, releases out to each, a rotation, transfers by the new set and by the old set inside its grace window, quorums of 5 and 6 |
| `no_quorum`, `index_order`, `index_out_of_range` | 4 | quorum of 4, duplicate and decreasing indices, index 6 |
| `high_s`, `bad_signature`, `wrong_guardian` | 4 | malleated signature, `r = 0`, wrong recovery id, non-guardian signer |
| `set_expired`, `unknown_set`, `stale_governance_set` | 3 | old set past grace, unknown index, a rotation signed by a superseded set |
| `wrong_emitter`, `wrong_to_chain`, `wrong_token_chain` | 7 | wrong address, right address on the wrong chain, and the release-side variants |
| `fee_exceeds_amount`, `amount_overflow`, `bad_payload`, `bad_version` | 6 | fee above amount, amount above `u128`, 132-byte payload, payload id 9, version 2 |
| `replay` | 2 | a consumed mint and a consumed release |

How each side consumes them:

- **Fullnode.** `shared_vectors_match_verify` re-verifies the 23 signature-level vectors
  against `bridge::verify` with the vector's own set; `vectors_ledger_level` drives the other 21
  through a live `Ledger` as real `BridgeAttest` transactions. Both assert an exact count so a
  vector that stops matching fails the build instead of being skipped. `unknown_set` is
  ledger-level only: `verify` takes a resolved set, so an unknown index is a resolution concern
  only `check_attest` can raise.
- **EVM.** `Vectors.t.sol` runs every vector through the `Attestation` library;
  `BridgeVectors.t.sol` releases `release_to_eth_ok` through a deployed `EthereumRandBridge` and
  rejects `upgrade_signed_by_superseded_set`.
- **Solana.** `tests/attestation.rs` runs the vectors against the verifier; `tests/bridge.rs`
  releases `release_to_sol_ok` end to end.
- **Generator self-check.** `every_signature_level_vector_matches_verify` runs in the generator's
  own tests before the file is written.

---

## 10. Deployment order

1. **Rand genesis first.** Choose the six guardian keys and the Rand emitter value; build the
   genesis with a `bridge` section. These values are what every endpoint constructor takes next.
2. **Deploy the endpoints** with the same guardian set and Rand emitter. Ethereum and BSC through
   `Deploy.s.sol`; Tron through TronBox; Solana through `cargo build-sbf`, `solana program
   deploy`, then `Initialize` signed by the upgrade authority, then hand the authority to a
   multisig.
3. **Register the endpoints back into genesis** under `bridge.emitters`, keyed by bridge chain id
   and left-padded to 32 bytes, before the chain launches. The emitter table is the other half of
   the trust binding and must be in genesis, not added to a live chain.
4. **Whitelist tokens** on each endpoint with `setToken` / `SetToken` and set the pauser.

The bridge's fullnode changes are on fullnode `main`. Nothing on `main` after the zkVM
constraint-set change can run the current chain, so bridge activation is bundled into the next
chain cut-over as a fork item, together with the consensus and zkVM changes, and is not rolled out
node by node.

---

## 11. Invariants to preserve when changing anything

These are the rulings that have to change in every verifier and in the vector generator at once,
or not at all:

- `mu = keccak256(keccak256(body))` over wire bytes, on every chain.
- Quorum `n*2/3 + 1`; indices strictly increasing and in range; low-s only; recovery id 0 or 1.
- A rotation is signed by the current set; the grace window covers transfers only.
- `new_index == current + 1`; keys unique and non-zero; a superseded set expires after 86,400 s.
- Emitter binding is on the pair `(emitter_chain, emitter_address)`; the governance emitter is
  distinct from the Rand burn emitter.
- On Rand a transfer's `token_chain` equals its `emitter_chain`; on an endpoint a release's
  `to_chain` and `token_chain` both equal the endpoint's own chain.
- EVM-family addresses are 20 bytes left-padded to 32 in `to`, `token_address` and
  `emitter_address`; the upper 12 bytes are checked on the way out of Rand and on the way into an
  endpoint.
- `fee <= amount`; zero attested or denormalised amounts are refused everywhere.
- Effects before interactions on every release.

And the consensus-facing constants on Rand: `TxKind` tags 4 and 5, `MAX_ATTESTATION_BYTES`,
the bridge root's domain tags and field order, the genesis commit's `BridgeCommit` encoding, and
the block-timestamp rules. Changing any of these is a hard fork on every bridged chain.

---

## 12. Known gaps

- **No guardian daemon, no relayer daemon.** The format is fixed so they can be built against it;
  nothing runs it end to end yet.
- **No shielded notes.** Rand mints a transparent per-account balance. A future shielded design
  would have to shield bridged balances too.
- **`BridgeState.burns` is unbounded in memory** and cloned on every speculative block execution.
  It must be drained into storage per block before a chain approaches roughly 100k burns; the
  change is not a fork because the map is outside the root.
- **A 2/3 leader coalition can freeze the bridge's clock.** Equal block timestamps are legal, so
  colluding leaders can hold `timestamp_ms` constant, keeping a superseded guardian set inside its
  grace window indefinitely. Forbidding equal timestamps would not fix this and would stall an
  honest chain; it is recorded as a consequence of the timestamp rule, not a defended property.
- **No rate limiting on Rand** beyond the flat fee and the 16 KiB cap.
- **The Rand recipient has no checksum**; wallets must verify the 32-byte round trip.
- **Attestations are ECDSA**, not post-quantum. The Rand verifier is the natural place to add
  ML-DSA later.
- **Tron and Solana are built and tested but not deployed** by this pass; no Tron toolchain or
  Solana CLI is installed on the build machine.
