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

Revision described: bridge repo as of 2026-09-17, fullnode `main` at `756fa80` (2026-09-17). Two
fullnode changes since the previous revision (`dbea18c`) shape this document: the SHRUGG to RAND
rename (`ed96c39`: crate names, RPC prefix, address prefix and every hash domain), and the shielded
pool's phase S3, under which a bridged holding on Rand is a **note** in the pool rather than a
per-account balance. The wire format, the guardian rules and the endpoints' verification are
unchanged by both.

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

On Rand there is no custody to bound. A mint appends one deposit note of the bridged asset to
the shielded pool (the asset is `(home chain, token)`, carried in the note as a dense registry
index); the bound is that a burn back to the home chain can only release what that chain's
endpoint actually custodies. A note's amount is a `u64`, so every endpoint refuses to lock an
attested amount above `u64::MAX` (§3.4): nothing can be custodied that Rand could never mint.

Two more rules harden against a partially compromised committee:

- A guardian-set rotation must be signed by the *current* set. The grace window after a rotation
  covers transfers only, so a set the guardians have just rotated away from cannot rotate the
  bridge back.
- Rotations cannot skip indices, and a superseded set expires 86,400 seconds after being replaced.

Every component here is reviewed internally (`docs/audit/2026-09-17-predeploy-audit.md`) but not
externally audited, and the guardian and relayer daemons that would run the format end to end are
not built. Nothing has watched a real chain or moved real funds.

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
  solana/cli/                    rand-bridge-cli: Initialize and the admin instructions from the command line
  tools/vectors/                 generator for the shared vectors (examples/asset_ids.rs prints §10.1)
  vectors/attestations.json      the vectors (39)
  deploy/                        one deploy script per chain, keys from deploy/.env (deploy/README.md)

fullnode/crates/
  bridge-codec/                  no_std, zero-dependency wire codec
    src/lib.rs                   constants, quorum, check_indices, is_low_s
    src/envelope.rs              Signature, Body, Attestation
    src/payload.rs               Transfer, GuardianSetUpgrade, Payload
  randprotocol-core/src/bridge/
    mod.rs                       keccak, digest, asset_id, recover, verify
    state.rs                     BridgeConfig, BridgeState, check/apply, root
    vectors.json                 byte-identical copy of the vectors
  randprotocol-core/src/ledger/
    bridge_notes.rs              the deposit note an attestation creates, the two-bundle burn
    mod.rs                       Action dispatch, state root, block timestamp rule
  randprotocol-core/src/genesis.rs   the bridge genesis section and its validation
  randprotocol-node/src/storage.rs   RocksDB column families
  randprotocol-node/src/rpc.rs       four bridge RPC methods
  randprotocol-client/               wallet CLI commands
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
| Rand | `u256` unpacked to `u128`, then `u64` | `u64` (a note's amount field), no denormalisation | `AmountOverflow` if the top 16 bytes are non-zero; `AmountTooLarge` above `u64::MAX` |

Because Rand keeps a bridged amount in a note's `u64`, every endpoint's lock refuses an attested
amount above `u64::MAX` (`AmountTooLarge` on the EVM, `AmountOverflow` on Solana) before pulling
anything: a lock Rand could never mint would sit in custody with no burn able to release it. At 8
decimals the bound is about 1.8 x 10^11 whole tokens per lock.

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
    R->>N: BridgeAttest { attestation, recipient, r, time, asset, envelope } + RAND fee bundle
    N->>N: check_attest: cheap checks, then signatures; recipient hash and asset index bound
    N->>N: spent += mu; register asset if new; append deposit note { recipient, amount (gross), asset index }
```

The body the guardians sign is rebuilt from the event plus the block timestamp, the endpoint's
chain-id constant, and its address. On Solana the full body is written to a `PostedMessage` PDA
so guardians read it durably rather than from logs.

Three things about the Rand side follow from the shielded pool (fullnode `docs/bridge.md` §5):

- **`to` is a hash.** The 32-byte recipient the depositor names on the source chain is
  `blake3("rand-shielded-recipient", pk || kem_ek)` of the recipient's shielded address, which the
  Rand wallet prints. The relayer submits the full address in the action and the ledger recomputes
  the hash; a mismatch is refused, so a relayer cannot redirect a deposit.
- **The relayer needs more than the attestation.** The action also carries the note's blinding
  `r`, its `time` (held to a window around the current height) and the asset **index** the
  registry will resolve, plus an envelope sealed to the recipient. A first sighting of a token has
  to name the index it will be given; losing that race to another first sighting costs a re-proof.
- **The relayer fee is not paid on Rand.** The deposit note carries the gross `amount` the
  guardians signed; the payload's `fee` is carried for the record only, because a shielded chain
  has no submitter identity to pay. Front ends should pass a zero `relayerFee` to `lock`.

### 4.2 Rand to home chain

```mermaid
sequenceDiagram
    participant H as Holder
    participant N as Rand fullnode
    participant G as Guardians
    participant R as Relayer
    participant E as Endpoint (home chain)
    H->>N: BridgeBurn { asset_bundle, asset (index), amount, relayer_fee, to_chain, to } + RAND fee bundle
    N->>N: check_burn: registered index, to_chain == home, recipient shape, relayer_fee <= amount != 0
    N->>N: asset bundle's proof burns exactly `amount`; burn_sequence += 1; record BridgeBurnRecord { body, digest }
    G->>N: rand_getBridgeBurn(sequence)
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
| 7 | payload 1, `to_chain == token_chain == self`, `fee <= amount` | payload 1, `to_chain == token_chain == 5`, `fee <= amount` | `token_chain == emitter_chain`, `to_chain == 1`, amounts fit `u128`, `fee <= amount`, `amount != 0`, `amount` fits `u64` |
| 8 | token enabled, recipient shape, denormalise, `amount != 0` | mint matches, token enabled, recipient and relayer ATAs, denormalise, `amount != 0` | asset registry index resolved (then, in the ledger: the action's `asset` and recipient hash match) |
| 9 | custody, per-transfer cap, daily cap | custody, per-transfer cap, daily cap | set expiry, quorum, low-s, recover, compare |
| effects | consumed, custody, window | consumed PDA, custody, window | spent, asset registry, one deposit note in the pool |
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

The Rand recipient is the 32-byte hash of a shielded address (§4.1), which the Rand wallet
prints; it has no checksum and the contract can only reject zero. Step 2 also refuses an attested
amount above `u64::MAX` (`AmountTooLarge`, §3.4). `relayerFee` is carried for the record only:
Rand mints the gross amount and pays no relayer.

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
The script signs with `DEPLOYER_PRIVATE_KEY` from the environment when it is set, so the key never
appears on a command line. `deploy/eth.sh` and `deploy/bnb.sh` wrap it: they load `deploy/.env`,
check the connected chain id first, run the script, and record the address and its 32-byte emitter
wire form under `deploy/deployments/` (`deploy/README.md`). Tron is compiled here but deployed with
TronBox from the same source through `deploy/trx.sh`; see `tron/README.md` for the
base58check-to-20-byte conversion, the migration's environment, and the post-deploy steps.

---

## 7. The Solana program

A native `solana-program` crate, no Anchor. Tests run under `solana-program-test`, which compiles
the program natively against a real bank and the real SPL token program, so the suite needs no
SBF toolchain. The deployable `.so` has never been built here: `cargo build-sbf` is unavailable
on the development machine. `lib.rs` pins a vanity program id with no known secret; a real
deployment re-declares its own before building, since every PDA derives from it. `deploy/sol.sh`
does exactly that once the Solana CLI is installed (generate or load the program keypair, rewrite
`declare_id!`, `cargo build-sbf`, `solana program deploy`, then `Initialize`), and `solana/cli`
(`rand-bridge-cli`) is the command-line client for `Initialize` and the admin instructions, with
the signer loaded from a keypair file or an inline secret in the environment.

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
  rejected as `AmountOverflow`. The same error refuses a lock whose *attested* amount exceeds
  `u64::MAX` (§3.4), mirroring the EVM `AmountTooLarge`.
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

### 8.2 `randprotocol-core::bridge`

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
    pub assets: BTreeMap<AssetId, AssetInfo>,           // asset -> { chain, token, index }
    pub next_index: u32,                                // the index the next new asset gets (from 1)
    pub spent: BTreeSet<Hash>,                          // consumed digests
    pub burn_sequence: u64,
    pub burns: BTreeMap<u64, BridgeBurnRecord>,         // outbound log; not in the root
}
```

**There are no balances.** A bridged holding is a note in the pool's commitment tree, and the tree
commits to it; what is left here is the public half of the bridge. A note's `asset` word is one
`u32`, so the registry hands each asset a dense **index** at its first sighting (`1, 2, ...`; 0 is
RAND and never registered), and the index never changes. `next_index` is consensus state.

`AssetId = blake3("rand-bridge-asset" || token_chain BE || token_address)`, so USDT from Ethereum
and USDT from Tron are distinct assets with distinct custody. The registry is populated lazily by
the first mint of each asset and read by burns to rebuild the payload; `rand_getAssets` maps
between ids and indices.

The four transition functions:

- `check_attest(bytes, now) -> CheckedAttestation` runs the Rand column of the Section 5 table and
  returns a token only it can build: the digest, `now`, and the plan (a `BridgeTransfer { asset,
  info, amount: u64, to_hash, relayer_fee }` or a `GuardianSetUpgrade`). An amount above `u64::MAX`
  is `AmountTooLarge`. For a rotation it requires `guardian_set_index == current_set`,
  `new_index == current_set + 1`, and unique non-zero keys.
- `apply_attest(checked)` is infallible: it inserts `mu` into `spent`, registers the asset if new
  (under the index the plan already named), and hands the transfer back for the ledger to turn
  into a deposit note. For a rotation it sets the old current set's `expires_at = now + 86_400`,
  installs the new set with `expires_at = 0`, and advances `current_set`. The quorum is therefore
  verified exactly once per attestation, in the ledger's validate step.
- `check_burn(asset_index, amount, to_chain, to, relayer_fee) -> AssetId` requires a registered
  index, `to_chain` equal to the asset's home chain, a non-zero recipient, zero upper 12 bytes when
  `to_chain` is 2, 3 or 4, `relayer_fee <= amount`, and `amount != 0`. There is no balance to
  check: the asset bundle's zkVM proof is what bounds a burn (`burn == amount` in that bundle).
  The recipient screening happens here because a burn is irreversible once guardians sign it.
- `apply_burn(tx, asset_index, amount, to_chain, to, relayer_fee, height, timestamp)` builds the
  Section 4.2 body, records `BridgeBurnRecord { sequence, body, digest, tx, height }` with the
  transaction hash in the sender slot (a burn is funded by notes, so there is no sender identity),
  and increments `burn_sequence`.

`root()` is the consensus commitment:

```
blake3("rand-bridge-state"
    || bincode(emitter, emitters, current_set, guardian_sets)
    || merkle(blake3("rand-asset-registry" || asset || chain BE || token || index BE))
    || merkle(sorted spent digests)
    || burn_sequence BE || next_index BE)
```

`burns` is excluded because it is derivable from transaction history. A test pins the root of a
fixed state to a constant; changing it is a hard fork, never a test to re-baseline (it was re-pinned
once, in S3, when the balance leaves left and the registry leaf gained its index). `BridgeMeta` is
the whole-state half (everything but `spent` and `burns`), split here so a new field must be
classified as meta or per-row or the build breaks.

### 8.3 Ledger integration

Two `Action` variants, bincode tags 7 and 8, after the three staking actions:

| tag | variant | fields |
|---|---|---|
| 7 | `BridgeAttest` | `attestation: Vec<u8>, recipient: ShieldedAddress, r, time: u32, asset: u32, envelope` |
| 8 | `BridgeBurn` | `asset_bundle: Bundle, asset: u32, amount: u64, relayer_fee: u64, to_chain: u16, to: [u8; 32]` |

Both ride on an ordinary shielded transaction and pay their fee in RAND out of the transaction's
own bundle: an attest pays one bundle's base fee, a burn two (its asset bundle is the second). The
inbound side: the ledger recomputes the recipient hash from `recipient` and requires it to equal
the payload's `to`; `asset` must equal the index the registry resolves (or would assign to a first
sighting); `time` must fall in the window a bundle's time gets; the deposit note is then computed
by the chain from the attested gross amount, so a relayer can neither inflate nor redirect a mint.
The outbound side: a burn is one transaction with two bundles, a RAND bundle paying the fee and an
asset bundle whose proof burns exactly `amount` of the bridged asset (the `relayer_fee` is a
portion of `amount`, paid on the destination chain by the release). `validate_inner` checks
`attestation.len() <= MAX_ATTESTATION_BYTES` (16,384) before parsing anything, then bridge
presence, then `check_attest` or `check_burn`, all before the bundle proofs are verified.
`apply_tx` consumes the `CheckedAttestation` that validation produced, so the quorum is never
verified twice.

When a bridge exists the state root becomes `blake3("rand-state-2" || tree_root || nullifier_root
|| validators_root || programs_root || bridge_root)`; without one the fifth word is absent and the
chain is byte-identical to an unbridged one. The genesis hash appends `bincode(BridgeCommit)`, a
plain-bytes twin of the human-readable `BridgeConfig`, only when the section is present.

### 8.4 Genesis

```json
"bridge": {
  "emitter":   "<64 hex>",
  "guardians": ["<40 hex>", "..."],
  "emitters":  { "2": "<64 hex>", "3": "<64 hex>", "4": "<64 hex>", "5": "<64 hex>" }
}
```

`rand-node genesis` has no `--bridge` flag: cut the genesis, then add the section to the file by
hand before distributing it (fullnode `docs/cli.md`). `check_bridge` rejects an empty guardian
set, a duplicate or zero guardian, a zero emitter, an emitter equal to the governance emitter,
chain 1 in `emitters`, a source emitter equal to the governance emitter, and a zero source
emitter. `emitters` may be partial: a chain without an entry can accept locks but cannot mint on
Rand. Guardian set 0 is installed as current with `expires_at = 0`. A genesis registers no assets;
the first attestation naming a token puts it in the registry under index 1.

### 8.5 Block time on a bridged chain

Guardian-set expiry and burn timestamps read the block's `timestamp_ms`, so on a bridged chain it
becomes consensus input: `apply_block` rejects a block whose timestamp is lower than its
parent's (`TimestampRewind`), a validator rejects a proposal more than 30 seconds ahead of its
own clock, and proposers set `max(now, parent)`. Equal timestamps are allowed. Every ledger built
from a head block carries that block's timestamp, so expiry is never evaluated at `now = 0`.
Chains without a bridge keep their previous rules unchanged.

### 8.6 Storage, RPC, wallet

Storage adds two RocksDB column families and one meta key:

| location | key | value |
|---|---|---|
| `bridge_spent` | digest | empty |
| `bridge_burns` | sequence BE | `bincode(BridgeBurnRecord)` |
| `meta["bridge_state"]` | | `bincode(BridgeMeta)`; its presence marks a bridged database |

A block commit touches only the rows its bridge transactions moved. An undecodable payload on the
commit path is a `Corrupt` error, never a silent skip. The startup integrity check compares the
stored bridge with the replayed one separately from the root, because the root omits the burn
log. A database predating the bridge initialises its state fresh from genesis.

RPC methods, all in `docs/rpc.md` of the fullnode; none is per-address, because balances are
notes only a viewing key can total:

| method | params | result |
|---|---|---|
| `rand_getBridgeState` | `[]` | emitter, emitters, current guardian set, the registry, `next_index`, `burn_sequence`; `{"enabled": false}` without a bridge |
| `rand_getAssets` | `[]` | the registry, ascending by index: `{ index, chain, token, asset_id }` |
| `rand_bridgeAssetId` | `[token_chain, token_address]` | the asset id; a pure function, answers on any chain |
| `rand_getBridgeBurn` | `[sequence]` | one outbound message (`body_hex`, `digest`, `tx`, `height`), or `null` |

Wallet commands (`rand`): `bridge-mint <attestation hex or @file>` (seals the recipient's
envelope and pays with a RAND bundle), `bridge-burn <asset index> <amount> <to_chain> <to>` (proves
two bundles), `asset-balance [index]` (this wallet's own notes), `bridge` (the public state), and
`bridge-message <sequence>` (one outbound message for a guardian to sign). Bridged amounts are plain
integers of 8-decimal units, not RAND's 9-decimal strings.

---

## 9. Shared test vectors

`tools/vectors` is a Rust binary that depends on `randprotocol-core` by path and writes
`vectors/attestations.json` plus the fullnode copy at
`crates/randprotocol-core/src/bridge/vectors.json`. `cargo run --release -- --check` re-renders from the
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
  against `bridge::verify` with the vector's own set, asserting the exact count so a vector that
  stops matching fails the build instead of being skipped. The account-era `vectors_ledger_level`
  pass, which drove the remaining vectors through a live `Ledger`, went with the accounts in S1
  and has not been rebuilt on the note pool; those refusals (`wrong_emitter`, `replay`,
  `unknown_set`, ...) are covered by hand-written unit tests in `bridge/state.rs` and
  `ledger/bridge_notes.rs`, and by the EVM and Solana vector suites. `unknown_set` was
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
2. **Deploy the endpoints** with the same guardian set and Rand emitter, from the command line:
   `deploy/eth.sh`, `deploy/bnb.sh`, `deploy/trx.sh`, `deploy/sol.sh`, each loading its chain's
   private key from `deploy/.env` (`deploy/README.md`). Underneath: Ethereum and BSC through
   `Deploy.s.sol`; Tron through TronBox; Solana through `cargo build-sbf`, `solana program
   deploy`, then `rand-bridge-cli initialize` signed by the upgrade authority, then hand the
   authority to a multisig.
3. **Register the endpoints back into genesis** under `bridge.emitters`, keyed by bridge chain id
   and left-padded to 32 bytes, before the chain launches. The emitter table is the other half of
   the trust binding and must be in genesis, not added to a live chain.
4. **Whitelist tokens** on each endpoint with `setToken` / `SetToken` and set the pauser. The
   approved list is in §10.1; nothing outside it is enabled.

The bridge's fullnode changes are on fullnode `main`, and the fleet's chain 10 (cut 2026-09-16,
the RAND rename) runs a build that contains them but has **no `bridge` section**. The guardian
set, emitter table and asset registry are genesis state, so a bridge cannot be added to a running
chain: activation means cutting the next chain with a `bridge` section that names the guardian
keys and the four emitter addresses the scripts above print (fullnode `deploy/README.md`).

### 10.1 Approved tokens

Two tokens are approved for bridging, USDT and USDC, each on all four source chains. These are
the only addresses `setToken` / `SetToken` enable at launch; the allowlist is enforced on the
endpoints (§6.3, §7.1), and Rand's registry (§8.2) fills in from the first attestation it sees,
so an address absent from this table can neither be locked nor minted. Each row is a distinct
Rand asset: the same ticker on two chains is two assets with separate custody (§8.2).

| chain | token | contract address | decimals | issuer |
|---|---|---|---|---|
| 2 Ethereum | USDT | `0xdAC17F958D2ee523a2206206994597C13D831ec7` | 6 | Tether |
| 2 Ethereum | USDC | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | 6 | Circle |
| 3 BNB Smart Chain | USDT | `0x55d398326f99059fF775485246999027B3197955` | 18 | Binance-Peg (BSC-USD) |
| 3 BNB Smart Chain | USDC | `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d` | 18 | Binance-Peg |
| 4 Tron | USDT | `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` (hex `41a614f803b6fd780986a42c78ec9c7f77e6ded13c`) | 6 | Tether |
| 4 Tron | USDC | `TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8` (hex `413487b63d30b5b2c87fb7ffa8bcfade38eaac1abe`) | 6 | Circle, discontinued |
| 5 Solana | USDT | `Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB` | 6 | Tether |
| 5 Solana | USDC | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` | 6 | Circle |

Notes on the rows:

- **BSC.** Both tokens are Binance-issued pegs, not Tether's or Circle's own contracts, and carry
  18 decimals, so they take the `d > 8` normalisation path in §3.4: the low 10 digits of a lock
  are dust that stays with the user and only the covered amount is pulled.
- **Tron.** `setToken` takes the 20-byte form (the hex above without its `41` prefix); the
  base58 string is what explorers and wallets show. See `tron/README.md` §3 for the conversion.
- **Tron USDC.** Circle stopped minting USDC on Tron in February 2024 and ended redemption in
  February 2025. The contract still exists and trades, but there is no issuer behind it. It is on
  the list because the launch policy is "USDT and USDC on every chain"; give it a tight per-transfer
  and daily cap, or leave it disabled, until that policy is revisited.
- **Everything else.** Bridging a token that is not on this list means adding it here first,
  then enabling it on exactly one endpoint, the one for its home chain.

The same rows in the forms the verifiers compare on. `token_address` is the 32-byte wire field
(§3.3; 20-byte addresses left-padded, Solana mint pubkeys as-is), and the asset id is
`blake3("rand-bridge-asset" || token_chain BE u16 || token_address)` (the domain was
`shrugg-bridge-asset` before the rename, so every id below changed on 2026-09-16), which is what
`rand_getAssets` and `rand_bridgeAssetId` report. The note **index** an asset gets on Rand is not
in this table: it is assigned by the first accepted attestation, in order of arrival. Regenerate
with `cd tools/vectors && cargo run --release --example asset_ids`:

| chain | token | `token_address` (32 bytes) | Rand asset id |
|---|---|---|---|
| 2 | USDT | `0x000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7` | `0xfb0877ed2d2914e5e120d23d57a04125b44897dd57071259883f71a8cac153cf` |
| 2 | USDC | `0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48` | `0x00fc5cb39e645801faaa3bc253d1b0f845187b06bf44961788c389b0e280d1ff` |
| 3 | USDT | `0x00000000000000000000000055d398326f99059ff775485246999027b3197955` | `0x4798ab7e34f187ca6bfc96ebfbf1df308354f13e352d5efc8aec53566ae86afb` |
| 3 | USDC | `0x0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d` | `0x7a7acd6751668de71015424b6e6e00cb2af6e51b1e64c9fbe9027ad2aa05d8c3` |
| 4 | USDT | `0x000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c` | `0xe913fd240badfd891c609efad7b6d7e3382da081b889a4fa2697ac53bddbf1f0` |
| 4 | USDC | `0x0000000000000000000000003487b63d30b5b2c87fb7ffa8bcfade38eaac1abe` | `0x3bd0440eaa091e78ff625eebc416aa598bac41ffedee15682fb4bc5589fb67b1` |
| 5 | USDT | `0xce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264` | `0x6fbe3acd18b78cdcf435e9964385e22f60fb74fd472a9d215545b8a52babbdf1` |
| 5 | USDC | `0xc6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61` | `0x4a3587528f24107c4a7fef4180ed083dbf7cfee922542b985828f08937c7aa8f` |

The addresses were checked on 2026-09-13 against the issuers' own pages (Tether's supported
protocols list, Circle's multi-chain USDC page) and BscScan / TronScan. Re-verify against those
sources before calling `setToken` on a real deployment; this table is for the humans running it,
nothing in the repo reads it.

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
- An attested amount fits a `u64`: refused by every lock (`AmountTooLarge` / `AmountOverflow`) and
  by Rand's `check_attest` (`AmountTooLarge`).
- On Rand the payload's `to` is `blake3("rand-shielded-recipient", pk || kem_ek)` of the
  recipient's shielded address; the endpoints treat it as opaque.
- Effects before interactions on every release.

And the consensus-facing constants on Rand: `Action` tags 7 and 8, `MAX_ATTESTATION_BYTES`, the
hash domains `rand-bridge-asset`, `rand-bridge-state`, `rand-asset-registry` and
`rand-shielded-recipient`, the bridge root's field order, `FIRST_ASSET_INDEX = 1`, the genesis
commit's `BridgeCommit` encoding, and the block-timestamp rules. Changing any of these is a hard
fork on every bridged chain (the rename already was one: chain 10).

---

## 12. Known gaps

- **No guardian daemon, no relayer daemon.** The format is fixed so they can be built against it;
  nothing runs it end to end yet.
- **No relayer is paid on Rand.** The deposit is minted gross and the submitter pays a RAND fee
  bundle for the privilege; relaying to Rand is altruistic or paid out of band until the pool can
  pay an identity-less submitter.
- **A first sighting can lose a race.** A deposit of a token the registry has never seen must
  name the index it will get; two relayers racing two different new tokens cost the loser a fee
  bundle and a re-proof.
- **A burn costs two zkVM proofs**, minutes on a laptop today, and about 600 KB of block space.
- **`BridgeState.burns` is unbounded in memory** and cloned on every speculative block execution.
  It must be drained into storage per block before a chain approaches roughly 100k burns; the
  change is not a fork because the map is outside the root.
- **A 2/3 leader coalition can freeze the bridge's clock.** Equal block timestamps are legal, so
  colluding leaders can hold `timestamp_ms` constant, keeping a superseded guardian set inside its
  grace window indefinitely. Forbidding equal timestamps would not fix this and would stall an
  honest chain; it is recorded as a consequence of the timestamp rule, not a defended property.
- **No rate limiting on Rand** beyond the flat fee and the 16 KiB cap.
- **The Rand recipient has no checksum**; it is a hash the wallet prints, and front ends must
  accept and carry it exactly.
- **Attestations are ECDSA**, not post-quantum. The Rand verifier is the natural place to add
  ML-DSA later.
- **Tron and Solana are built and tested but not deployed.** Tron now compiles under TronBox
  (`deploy/trx.sh --dry-run`); the Solana SBF build still needs the Solana CLI, which is not
  installed on the build machine. Neither program has been deployed to any network.
