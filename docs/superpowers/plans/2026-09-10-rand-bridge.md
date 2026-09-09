# Rand Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Four source-chain custody contracts (Ethereum, BSC, Tron, Solana) plus fullnode support so locked USDT/USDC mint 1:1 on Rand and burn back to their home chain, all verifying one attestation format.

**Architecture:** A dependency-free `bridge-codec` crate in the fullnode defines the wire format and the quorum rule; the fullnode's `shrugg-core` adds ECDSA/keccak on top for a `BridgeAttest`/`BridgeBurn` ledger. This repo holds the vector generator (uses the fullnode crates by path), the Foundry project for the three EVM-family contracts, and the native Solana program (uses `bridge-codec` by path with syscall hashing). Shared JSON vectors bind every verifier to the same bytes.

**Tech Stack:** Rust 1.91 (fullnode pins 1.98.1 via `rust-toolchain.toml`; rustup installs it), `k256 0.13` + `sha3 0.10`, Foundry 1.5.1 / Solidity 0.8.20 (Paris), `solana-program 2.x` + `solana-program-test 2.x` + `spl-token 7`, `serde_json`.

**Spec:** `docs/superpowers/specs/2026-09-10-rand-bridge-design.md` (this repo). Fullnode at `/Users/dendisuhubdy/Github/randprotocol/fullnode` (rev `92c9684`).

## Global Constraints

- All attestation integers are big-endian; envelope/body/payload layouts exactly as spec Section 3.
- Digest `mu = keccak256(keccak256(body))`; ECDSA secp256k1 over `mu`, low-s required, guardian key = last 20 bytes of `keccak256(uncompressed pubkey[1..])`.
- Quorum `q = n * 2 / 3 + 1`, strictly increasing indices, every index `< n`.
- Chain ids: Rand 1, Ethereum 2, BSC 3, Tron 4, Solana 5.
- `GOVERNANCE_EMITTER = keccak256("rand-bridge-governance")`; pin the 32-byte value in Rust, Solidity, and the Solana program and test it against the string in each.
- Guardian grace period after an upgrade: 86400 seconds. Upgrade must set `new_index == current + 1`.
- Amounts in attestations are u256 at 8 decimals; Rand balances are u128 at 8 decimals; `fee <= amount`.
- Transfer payload is exactly 133 bytes. Payload ids: 1 transfer, 2 guardian set upgrade.
- `AssetId = blake3("shrugg-bridge-asset" || token_chain BE u16 || token_address 32)`.
- Fullnode changes must leave chains without a genesis `bridge` section byte-for-byte unchanged (same tx encoding for tags 0..3, same state root, same genesis hash). `cargo test --release` in the fullnode must stay green.
- Fullnode `TxKind` variants are appended: `BridgeAttest` tag 4, `BridgeBurn` tag 5.
- Commit after every task. Fullnode commits go to the fullnode repo; everything else to this repo. Commit messages end with the attribution lines given in the session.

## File map

Fullnode (`../fullnode`):

| path | responsibility |
|---|---|
| `crates/bridge-codec/` (new, `no_std` + `alloc`, zero deps) | wire types, encode/decode, payloads, quorum + index rule, constants. Hash/ECDSA injected by caller. |
| `crates/shrugg-core/src/bridge/mod.rs` (new) | re-exports, `asset_id`, `keccak256`, ECDSA `recover_address`/`sign_digest`, `verify_quorum` |
| `crates/shrugg-core/src/bridge/state.rs` (new) | `BridgeState`, `GuardianSet`, `BridgeBurnRecord`, `BridgeError`, apply/validate for attest and burn, `root()` |
| `crates/shrugg-core/src/bridge/vectors.json` (new) | copy of shared vectors, `include_str!` in tests |
| `crates/shrugg-core/src/types/transaction.rs` | two new `TxKind` variants + constructors + `total_cost` |
| `crates/shrugg-core/src/ledger.rs` | `bridge: Option<BridgeState>`, `timestamp_ms`, validation/apply arms, state root |
| `crates/shrugg-core/src/genesis.rs` | optional `bridge` section, genesis commit, ledger init |
| `crates/shrugg-node/src/storage.rs` | new CFs, commit/load/truncate of bridge state |
| `crates/shrugg-node/src/rpc.rs` | five new methods |
| `crates/shrugg-node/src/node.rs` | pass `bridge` genesis into ledger on load |
| `crates/shrugg-client/src/lib.rs`, `main.rs` | client methods + CLI commands |
| `crates/shrugg-node/tests/cluster.rs` | one bridge cluster test |
| `docs/rpc.md`, `docs/cli.md`, `README.md` | document the additions |

This repo:

| path | responsibility |
|---|---|
| `tools/vectors/` | Rust bin: generates `vectors/attestations.json`, `--check` compares the fullnode copy |
| `vectors/attestations.json` | shared vectors |
| `evm/` | Foundry project: `Attestation.sol`, `SafeTransfer.sol`, `RandBridgeBase.sol`, three chain contracts, tests, deploy script |
| `solana/` | Cargo workspace: `programs/rand-bridge` native program + program-test tests |
| `tron/README.md` | TronBox deployment steps using the Foundry artifact |
| `spec/ATTESTATION.md` | wire-format reference for guardian/relayer authors (extract of spec Section 3) |
| `README.md` | repo overview, layout, build/test commands |

---

## Part A: fullnode codec and verifier

### Task A1: `bridge-codec` crate (wire format)

**Files:**
- Create: `../fullnode/crates/bridge-codec/Cargo.toml`, `src/lib.rs`, `src/envelope.rs`, `src/payload.rs`
- Modify: `../fullnode/Cargo.toml` (workspace members + `bridge-codec = { path = "crates/bridge-codec" }`)

**Interfaces:**
- Produces:

```rust
#![no_std]
extern crate alloc;
pub const CHAIN_RAND: u16 = 1; pub const CHAIN_ETHEREUM: u16 = 2; pub const CHAIN_BSC: u16 = 3;
pub const CHAIN_TRON: u16 = 4; pub const CHAIN_SOLANA: u16 = 5;
pub const VERSION: u8 = 1;
pub const TRANSFER_PAYLOAD_LEN: usize = 133;
pub const GUARDIAN_GRACE_SECS: u64 = 86_400;
pub const GOVERNANCE_EMITTER: [u8; 32] = [/* keccak256("rand-bridge-governance"), pinned in Step 3 */];
pub type GuardianKey = [u8; 20];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature { pub index: u8, pub r: [u8; 32], pub s: [u8; 32], pub v: u8 }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body { pub timestamp: u32, pub nonce: u32, pub emitter_chain: u16, pub emitter_address: [u8; 32],
                  pub sequence: u64, pub consistency_level: u8, pub payload: Vec<u8> }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation { pub guardian_set_index: u32, pub signatures: Vec<Signature>, pub body: Body }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer { pub amount: [u8; 32], pub token_address: [u8; 32], pub token_chain: u16,
                      pub to: [u8; 32], pub to_chain: u16, pub fee: [u8; 32] }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianSetUpgrade { pub new_index: u32, pub keys: Vec<GuardianKey> }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload { Transfer(Transfer), GuardianSetUpgrade(GuardianSetUpgrade) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError { BadVersion, Truncated, BadPayloadId, BadPayloadLength, TooManyGuardians, ZeroGuardians, TrailingBytes }

impl Body { pub fn encode(&self) -> Vec<u8>; pub fn decode(bytes: &[u8]) -> Result<Body, CodecError>; }
impl Attestation { pub fn encode(&self) -> Vec<u8>; pub fn decode(bytes: &[u8]) -> Result<Attestation, CodecError>;
                   /// body bytes as they appear in the envelope (what gets hashed)
                   pub fn body_bytes(bytes: &[u8]) -> Result<&[u8], CodecError>; }
impl Payload { pub fn encode(&self) -> Vec<u8>; pub fn decode(bytes: &[u8]) -> Result<Payload, CodecError>; }
impl Transfer { pub fn amount_u128(&self) -> Option<u128>; pub fn fee_u128(&self) -> Option<u128>;
                pub fn u256_from_u128(v: u128) -> [u8; 32]; }
pub fn quorum(n: usize) -> usize { n * 2 / 3 + 1 }
/// strictly increasing indices, all < n, and at least quorum(n) of them
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexError { NoQuorum { have: usize, need: usize }, IndexOrder, IndexOutOfRange }
pub fn check_indices(sigs: &[Signature], n: usize) -> Result<(), IndexError>;
/// s <= n/2 for secp256k1
pub fn is_low_s(s: &[u8; 32]) -> bool;
```

- [ ] **Step 1: Create the crate and workspace entry**

`crates/bridge-codec/Cargo.toml`:

```toml
[package]
name = "bridge-codec"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
description = "Rand bridge attestation wire format (no_std, no dependencies)"

[dependencies]
```

Add `"crates/bridge-codec"` to `members` in `../fullnode/Cargo.toml` and `bridge-codec = { path = "crates/bridge-codec" }` under `[workspace.dependencies]`.

- [ ] **Step 2: Write failing round-trip and layout tests** in `src/lib.rs` `#[cfg(test)]`:

```rust
#[test]
fn transfer_payload_is_133_bytes_and_round_trips() {
    let t = Transfer { amount: Transfer::u256_from_u128(123_456_789), token_address: [7; 32], token_chain: CHAIN_ETHEREUM,
                       to: [9; 32], to_chain: CHAIN_RAND, fee: Transfer::u256_from_u128(5) };
    let bytes = Payload::Transfer(t.clone()).encode();
    assert_eq!(bytes.len(), TRANSFER_PAYLOAD_LEN);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..33], &t.amount);
    assert_eq!(&bytes[65..67], &CHAIN_ETHEREUM.to_be_bytes());
    assert_eq!(Payload::decode(&bytes), Ok(Payload::Transfer(t)));
}
#[test]
fn envelope_round_trips_and_body_bytes_are_the_tail() {
    let body = Body { timestamp: 1, nonce: 2, emitter_chain: 3, emitter_address: [4; 32], sequence: 5, consistency_level: 6, payload: vec![1, 2, 3] };
    let att = Attestation { guardian_set_index: 9, signatures: vec![Signature { index: 0, r: [1; 32], s: [2; 32], v: 1 }], body: body.clone() };
    let bytes = att.encode();
    assert_eq!(bytes[0], VERSION);
    assert_eq!(&bytes[1..5], &9u32.to_be_bytes());
    assert_eq!(bytes[5], 1);
    assert_eq!(bytes.len(), 6 + 66 + 51 + 3);
    assert_eq!(Attestation::body_bytes(&bytes).unwrap(), &body.encode()[..]);
    assert_eq!(Attestation::decode(&bytes), Ok(att));
}
#[test]
fn rejects_bad_version_truncation_and_bad_payloads() {
    assert_eq!(Attestation::decode(&[2, 0, 0, 0, 0, 0]), Err(CodecError::BadVersion));
    assert_eq!(Attestation::decode(&[1, 0, 0, 0, 0, 1, 0]), Err(CodecError::Truncated));
    assert_eq!(Payload::decode(&[3]), Err(CodecError::BadPayloadId));
    assert_eq!(Payload::decode(&[1; 132]), Err(CodecError::BadPayloadLength));
    assert_eq!(Payload::decode(&[2, 0, 0, 0, 1, 0]), Err(CodecError::ZeroGuardians));
    let mut up = vec![2, 0, 0, 0, 1, 1]; up.extend([0u8; 20]); up.push(0xff);
    assert_eq!(Payload::decode(&up), Err(CodecError::TrailingBytes));
}
#[test]
fn quorum_and_index_rules() {
    assert_eq!(quorum(6), 5); assert_eq!(quorum(4), 3); assert_eq!(quorum(1), 1);
    let sig = |i| Signature { index: i, r: [0; 32], s: [0; 32], v: 0 };
    assert_eq!(check_indices(&[sig(0), sig(1), sig(2), sig(3), sig(4)], 6), Ok(()));
    assert_eq!(check_indices(&[sig(0), sig(1), sig(2), sig(3)], 6), Err(IndexError::NoQuorum { have: 4, need: 5 }));
    assert_eq!(check_indices(&[sig(0), sig(0), sig(0), sig(0), sig(0)], 6), Err(IndexError::IndexOrder));
    assert_eq!(check_indices(&[sig(0), sig(1), sig(2), sig(3), sig(6)], 6), Err(IndexError::IndexOutOfRange));
    assert!(is_low_s(&[0; 32]));
    let mut half_n = hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"); assert!(is_low_s(&half_n));
    half_n[31] += 1; assert!(!is_low_s(&half_n));
}
```

(`hex` is a tiny test helper decoding a hex string into `[u8; 32]`.)

- [ ] **Step 3: Pin `GOVERNANCE_EMITTER`**

Run `cast keccak "rand-bridge-governance"` and paste the 32 bytes into the constant. Add the test `governance_emitter_matches_string` in `shrugg-core` (Task A2) since the codec crate has no keccak.

- [ ] **Step 4: Run tests, expect compile failure**

Run: `cd ../fullnode && cargo test -p bridge-codec`

- [ ] **Step 5: Implement `envelope.rs` and `payload.rs`**

Encoding is a plain byte walk. Decoding uses a cursor helper:

```rust
struct Cur<'a> { b: &'a [u8], p: usize }
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.p + n > self.b.len() { return Err(CodecError::Truncated); }
        let s = &self.b[self.p..self.p + n]; self.p += n; Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CodecError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, CodecError> { let s = self.take(2)?; Ok(u16::from_be_bytes([s[0], s[1]])) }
    fn u32(&mut self) -> Result<u32, CodecError> { let s = self.take(4)?; Ok(u32::from_be_bytes(s.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, CodecError> { let s = self.take(8)?; Ok(u64::from_be_bytes(s.try_into().unwrap())) }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError> { Ok(self.take(N)?.try_into().unwrap()) }
}
```

`Attestation::decode`: version must be `VERSION` else `BadVersion`; read `guardian_set_index`, `n_sigs`, then `n_sigs` signatures, then `Body::decode(rest)`. `Body::decode` requires at least 51 bytes and takes the rest as payload. `Payload::decode`: id 1 requires exactly 133 bytes; id 2 requires `n >= 1` (`ZeroGuardians`), exactly `6 + 20n` bytes (`Truncated` if short, `TrailingBytes` if long). `Transfer::amount_u128` returns `None` if any of the top 16 bytes is non-zero. `is_low_s` compares against `7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0`.

- [ ] **Step 6: Run tests, expect pass**

Run: `cd ../fullnode && cargo test -p bridge-codec`

- [ ] **Step 7: Commit** (fullnode repo)

```bash
cd ../fullnode && git add Cargo.toml crates/bridge-codec && git commit -m "Add bridge-codec: attestation wire format"
```

### Task A2: `shrugg-core::bridge` hashing, ECDSA, quorum verification

**Files:**
- Create: `../fullnode/crates/shrugg-core/src/bridge/mod.rs`
- Modify: `../fullnode/crates/shrugg-core/Cargo.toml` (add `bridge-codec`, `k256 = { version = "0.13", features = ["ecdsa"] }`, `sha3 = "0.10"`), `src/lib.rs` (`pub mod bridge;`), workspace `Cargo.toml` (`k256`, `sha3` under workspace deps)

**Interfaces:**
- Consumes: everything from Task A1.
- Produces:

```rust
pub use bridge_codec::*;
pub type AssetId = Hash;
pub fn keccak256(data: &[u8]) -> [u8; 32];
pub fn digest(body_bytes: &[u8]) -> [u8; 32];              // keccak(keccak(body))
pub fn asset_id(token_chain: u16, token_address: &[u8; 32]) -> AssetId;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSet { pub keys: Vec<GuardianKey>, pub expires_at: u64 }   // 0 = current, never expires
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum VerifyError { Codec(CodecError), Index(IndexError), UnknownGuardianSet(u32), SetExpired,
                       HighS(u8), BadSignature(u8), WrongGuardian(u8) }
/// Full envelope check: decode, quorum/index rule, low-s, recover each signer, compare to the set. Returns (attestation, digest).
pub fn verify(bytes: &[u8], set: &GuardianSet, now: u64) -> Result<(Attestation, [u8; 32]), VerifyError>;
pub fn recover_address(digest: &[u8; 32], sig: &Signature) -> Option<GuardianKey>;
pub fn sign_digest(secret: &[u8; 32], index: u8, digest: &[u8; 32]) -> Signature;   // low-s, recovery id 0|1
pub fn guardian_address(secret: &[u8; 32]) -> GuardianKey;
```

- [ ] **Step 1: Write failing tests** in `bridge/mod.rs`:

```rust
#[test]
fn governance_emitter_matches_string() { assert_eq!(keccak256(b"rand-bridge-governance"), GOVERNANCE_EMITTER); }
#[test]
fn keccak_known_answer() {
    assert_eq!(hex::encode(keccak256(b"")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}
#[test]
fn sign_recover_round_trip_and_quorum() {
    let secrets: Vec<[u8; 32]> = (1u8..=6).map(|i| { let mut s = [0u8; 32]; s[31] = i; s }).collect();
    let set = GuardianSet { keys: secrets.iter().map(guardian_address).collect(), expires_at: 0 };
    let body = Body { timestamp: 1, nonce: 0, emitter_chain: 2, emitter_address: [1; 32], sequence: 0, consistency_level: 1,
        payload: Payload::Transfer(Transfer { amount: Transfer::u256_from_u128(100), token_address: [2; 32], token_chain: 2, to: [3; 32], to_chain: 1, fee: [0; 32] }).encode() };
    let d = digest(&body.encode());
    let sigs: Vec<Signature> = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
    for s in &sigs { assert_eq!(recover_address(&d, s), Some(set.keys[s.index as usize])); assert!(is_low_s(&s.s)); }
    let att = Attestation { guardian_set_index: 0, signatures: sigs.clone(), body: body.clone() };
    let (parsed, got) = verify(&att.encode(), &set, 1_000).unwrap();
    assert_eq!(got, d); assert_eq!(parsed, att);
    let four = Attestation { signatures: sigs[..4].to_vec(), ..att.clone() };
    assert_eq!(verify(&four.encode(), &set, 1_000).unwrap_err(), VerifyError::Index(IndexError::NoQuorum { have: 4, need: 5 }));
    let mut forged = att.clone(); forged.signatures[2] = sign_digest(&[9; 32], 2, &d);
    assert_eq!(verify(&forged.encode(), &set, 1_000).unwrap_err(), VerifyError::WrongGuardian(2));
    let mut high = att.clone(); high.signatures[0].s = [0xff; 32];
    assert_eq!(verify(&high.encode(), &set, 1_000).unwrap_err(), VerifyError::HighS(0));
    let expired = GuardianSet { expires_at: 999, ..set.clone() };
    assert_eq!(verify(&att.encode(), &expired, 1_000).unwrap_err(), VerifyError::SetExpired);
}
#[test]
fn asset_id_is_domain_separated_blake3() {
    let mut buf = b"shrugg-bridge-asset".to_vec(); buf.extend(2u16.to_be_bytes()); buf.extend([5u8; 32]);
    assert_eq!(asset_id(2, &[5; 32]), Hash(*blake3::hash(&buf).as_bytes()));
}
```

- [ ] **Step 2: Run, expect failure**: `cargo test -p shrugg-core bridge::`

- [ ] **Step 3: Implement**

`recover_address`: build `k256::ecdsa::Signature::from_scalars(r, s)`, `RecoveryId::from_byte(v)`, `VerifyingKey::recover_from_prehash(digest, &sig, recid)`, then `keccak256(&pk.to_encoded_point(false).as_bytes()[1..])[12..]`. `sign_digest`: `SigningKey::from_bytes(secret)`, `sign_prehash_recoverable(digest)`, then `sig.normalize_s()` (if normalisation changes `s`, flip the recovery id bit 0). `verify`: decode; `if set.expires_at != 0 && now > set.expires_at { SetExpired }`; `check_indices`; for each sig: `is_low_s` else `HighS(index)`; recover else `BadSignature(index)`; compare else `WrongGuardian(index)`. `asset_id`: `Hash::digest_domain(b"shrugg-bridge-asset", chain BE || address)`. `GuardianSet` gets `Serialize, Deserialize` (bincode-stable: `Vec<[u8;20]>` + `u64`).

- [ ] **Step 4: Run, expect pass**: `cargo test -p shrugg-core bridge::`

- [ ] **Step 5: Commit**: `git add -A crates/shrugg-core Cargo.toml Cargo.lock && git commit -m "Add bridge verifier: keccak digest, secp256k1 quorum"`

---

## Part B: shared vectors

### Task B1: vector generator and vector file

**Files:**
- Create: `tools/vectors/Cargo.toml`, `tools/vectors/src/main.rs`, `vectors/attestations.json`, `../fullnode/crates/shrugg-core/src/bridge/vectors.json`, `.gitignore` (`target/`)

**Interfaces:**
- Consumes: `shrugg_core::bridge::*` (path dep `../../../fullnode/crates/shrugg-core`).
- Produces the JSON schema every verifier test reads:

```json
{
  "guardians": [{ "secret": "<64 hex>", "address": "<40 hex>" }],
  "governance_emitter": "<64 hex>",
  "rand_emitter": "<64 hex>",
  "emitters": { "2": "<64 hex>", "3": "<64 hex>", "4": "<64 hex>", "5": "<64 hex>" },
  "now": 1800000000,
  "vectors": [{
    "name": "transfer_eth_usdt_6dp_ok",
    "attestation": "<hex>",
    "digest": "<64 hex>",
    "verifier_chain": 1,
    "sets": [{ "index": 0, "keys": ["<40 hex>", ...], "expires_at": 0 }],
    "current_set": 0,
    "expect": "ok",
    "body": { "timestamp": 1799999000, "nonce": 7, "emitter_chain": 2, "emitter_address": "<64 hex>", "sequence": 3, "consistency_level": 1 },
    "payload": { "id": 1, "amount": "100000000", "token_address": "<64 hex>", "token_chain": 2, "to": "<64 hex>", "to_chain": 1, "fee": "1000" }
  }]
}
```

`expect` values (shared across verifiers): `ok`, `bad_version`, `no_quorum`, `index_order`, `index_out_of_range`, `bad_signature`, `high_s`, `wrong_guardian`, `unknown_set`, `set_expired`, `wrong_emitter`, `wrong_to_chain`, `wrong_token_chain`, `fee_exceeds_amount`, `amount_overflow`, `bad_payload`, `replay`. A vector with `"replay_of": "<name>"` is the same bytes as that vector, to be submitted twice. Guardian secrets are `[0u8; 31] ++ [i]` for `i = 1..=6`. Fixed constants: `rand_emitter = keccak256("rand-bridge-emitter-test")`, source emitters `keccak256("emitter-<chain>")` left as 32 bytes, token addresses `keccak256("usdt-<chain>")`, recipient `[0x11; 32]`.

- [ ] **Step 1: Write the generator**

`main.rs` builds each case with `sign_digest` from Task A2 and writes JSON with `serde_json`. Case list (names are the test names every verifier uses):

```
transfer_eth_usdt_6dp_ok, transfer_bsc_usdt_18dp_ok, transfer_tron_usdt_ok, transfer_sol_usdc_ok   (to_chain 1, verifier 1)
release_to_eth_ok, release_to_bsc_ok, release_to_tron_ok, release_to_sol_ok                        (emitter chain 1 / rand_emitter, verifier 2..5)
upgrade_set1_ok (payload 2, GOVERNANCE_EMITTER, new_index 1, keys = guardians 2..=6 + a 7th secret [..,7])
transfer_signed_by_set1_ok (sets: 0 expires now-1, 1 current; guardian_set_index 1)
transfer_old_set_in_grace_ok (set 0 expires_at now+100; index 0)
transfer_old_set_expired (set 0 expires_at now-1) -> set_expired
transfer_unknown_set (guardian_set_index 5) -> unknown_set
quorum_four -> no_quorum; quorum_five_ok; quorum_six_ok
dup_index -> index_order; decreasing_index -> index_order; index_six -> index_out_of_range
high_s -> high_s; wrong_recovery_id -> wrong_guardian; non_guardian_signer -> wrong_guardian
wrong_emitter_address -> wrong_emitter; wrong_emitter_chain_right_address (emitter_chain 3 with chain-2 address) -> wrong_emitter
wrong_to_chain (to_chain 2 submitted to verifier 1) -> wrong_to_chain
wrong_token_chain (release to eth with token_chain 3) -> wrong_token_chain
fee_gt_amount -> fee_exceeds_amount; amount_over_u128 -> amount_overflow
payload_132_bytes -> bad_payload; payload_id_9 -> bad_payload; version_2 -> bad_version
replay_eth (replay_of transfer_eth_usdt_6dp_ok) -> replay
```

`--check` mode: read both files, assert equal, exit 1 otherwise. `--out <path>` writes; default writes both `vectors/attestations.json` and `../fullnode/crates/shrugg-core/src/bridge/vectors.json`.

- [ ] **Step 2: Run** `cd tools/vectors && cargo run --release` then `cargo run --release -- --check`. Expected: both files exist and check passes.

- [ ] **Step 3: Add a fullnode test that consumes the copy**: in `bridge/mod.rs` tests, `include_str!("vectors.json")`, for every vector with `expect` in {`ok`, `no_quorum`, `index_order`, `index_out_of_range`, `bad_signature`, `high_s`, `wrong_guardian`, `unknown_set`, `set_expired`, `bad_version`} call `verify` against the vector's sets and assert the mapped result. (The remaining expectations are ledger-level and are asserted in Task C2.) Run `cargo test -p shrugg-core bridge::`.

- [ ] **Step 4: Commit** both repos: `git commit -m "Add shared attestation vectors"` here; `git commit -m "Add bridge vectors and vector test"` in the fullnode.

---

## Part C: fullnode ledger

### Task C1: `BridgeState` and `TxKind` variants

**Files:**
- Create: `../fullnode/crates/shrugg-core/src/bridge/state.rs`
- Modify: `types/transaction.rs:60-73` (variants), `:118-131` (constructors), `:159-165` (`total_cost` -> fee only for both), `ledger.rs`

**Interfaces:**
- Produces:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeConfig { pub emitter: [u8; 32], pub guardians: Vec<GuardianKey>, pub emitters: BTreeMap<u16, [u8; 32]> }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeBurnRecord { pub sequence: u64, pub body: Vec<u8>, pub digest: [u8; 32], pub tx: Hash, pub height: u64 }
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BridgeState { pub emitter: [u8; 32], pub emitters: BTreeMap<u16, [u8; 32]>, pub guardian_sets: BTreeMap<u32, GuardianSet>,
    pub current_set: u32, pub balances: BTreeMap<(AssetId, Address), u128>, pub assets: BTreeMap<AssetId, (u16, [u8; 32])>,
    pub spent: BTreeSet<Hash>, pub burn_sequence: u64, pub burns: BTreeMap<u64, BridgeBurnRecord> }
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum BridgeError { Disabled, Verify(VerifyError), WrongEmitter, WrongToChain, WrongTokenChain, FeeExceedsAmount, AmountOverflow,
    BadPayload, Replay, BadUpgradeIndex { expected: u32, got: u32 }, DuplicateGuardian, UnknownAsset, InsufficientAsset { have: u128, need: u128 }, Overflow }
pub enum AttestOutcome { Minted { asset: AssetId, to: Address, amount: u128, fee: u128 }, GuardianSetUpgraded(u32) }
impl BridgeState {
    pub fn from_config(cfg: &BridgeConfig) -> BridgeState;
    pub fn balance(&self, asset: &AssetId, addr: &Address) -> u128;
    pub fn check_attest(&self, bytes: &[u8], now: u64) -> Result<(Attestation, [u8; 32], Payload), BridgeError>;
    pub fn apply_attest(&mut self, bytes: &[u8], submitter: Address, now: u64) -> Result<AttestOutcome, BridgeError>;
    pub fn check_burn(&self, from: &Address, asset: &AssetId, amount: u128, to_chain: u16, fee: u128) -> Result<(), BridgeError>;
    pub fn apply_burn(&mut self, from: Address, asset: AssetId, amount: u128, to_chain: u16, to: [u8; 32], fee: u128, tx: Hash, height: u64, timestamp: u32) -> Result<BridgeBurnRecord, BridgeError>;
    pub fn root(&self) -> Hash;   // spec 6.3; burns excluded
}
```

`TxKind::BridgeAttest { attestation: Vec<u8> }` and `TxKind::BridgeBurn { asset: AssetId, amount: u128, to_chain: u16, to: [u8; 32], fee: u128 }` with `Transaction::bridge_attest(key, chain_id, nonce, attestation, fee)` and `Transaction::bridge_burn(key, chain_id, nonce, asset, amount, to_chain, to, bridge_fee, fee)`.

- [ ] **Step 1: Write failing tests** in `state.rs`:

```rust
fn cfg() -> (BridgeConfig, Vec<[u8; 32]>) { /* 6 secrets, emitters {2: [2;32], 3: [3;32], 4: [4;32], 5: [5;32]}, emitter [1;32] */ }
fn attest(secrets: &[[u8;32]], set_index: u32, body: Body) -> Vec<u8> { /* sign with first 5, encode */ }
fn transfer_body(emitter_chain: u16, amount: u128, fee: u128, to_chain: u16) -> Body { /* token [0xaa;32], token_chain = emitter_chain, to = key(1).address().0 */ }

#[test] fn mint_credits_recipient_and_fee_to_submitter() {
    let (c, s) = cfg(); let mut st = BridgeState::from_config(&c);
    let out = st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 10, 1)), key(9).address(), 1).unwrap();
    let asset = asset_id(2, &[0xaa; 32]);
    assert_eq!(out, AttestOutcome::Minted { asset, to: key(1).address(), amount: 990, fee: 10 });
    assert_eq!(st.balance(&asset, &key(1).address()), 990); assert_eq!(st.balance(&asset, &key(9).address()), 10);
    assert_eq!(st.assets[&asset], (2, [0xaa; 32])); assert_eq!(st.spent.len(), 1);
}
#[test] fn replay_wrong_emitter_wrong_chain_fee_overflow() {
    let (c, s) = cfg(); let mut st = BridgeState::from_config(&c);
    let a = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
    st.apply_attest(&a, key(9).address(), 1).unwrap();
    assert_eq!(st.apply_attest(&a, key(9).address(), 1).unwrap_err(), BridgeError::Replay);
    let mut b = transfer_body(2, 1, 0, 1); b.emitter_address = [9; 32];
    assert_eq!(st.check_attest(&attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
    let mut b = transfer_body(2, 1, 0, 1); b.emitter_chain = 3;   // chain-2 address presented as chain 3
    assert_eq!(st.check_attest(&attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
    assert_eq!(st.check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 2)), 1).unwrap_err(), BridgeError::WrongToChain);
    assert_eq!(st.check_attest(&attest(&s, 0, transfer_body(2, 1, 2, 1)), 1).unwrap_err(), BridgeError::FeeExceedsAmount);
    let mut b = transfer_body(2, 1, 0, 1); b.payload[1] = 1;   // amount top byte
    assert_eq!(st.check_attest(&attest(&s, 0, b), 1).unwrap_err(), BridgeError::AmountOverflow);
}
#[test] fn burn_debits_and_records_message() {
    let (c, s) = cfg(); let mut st = BridgeState::from_config(&c);
    st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 0, 1)), key(9).address(), 1).unwrap();
    let asset = asset_id(2, &[0xaa; 32]);
    let rec = st.apply_burn(key(1).address(), asset, 400, 2, [0x22; 32], 5, Hash::ZERO, 12, 1_700).unwrap();
    assert_eq!(rec.sequence, 0); assert_eq!(st.burn_sequence, 1); assert_eq!(st.balance(&asset, &key(1).address()), 600);
    let body = Body::decode(&rec.body).unwrap();
    assert_eq!((body.emitter_chain, body.emitter_address, body.sequence, body.timestamp, body.nonce, body.consistency_level), (1, [1; 32], 0, 1_700, 0, 0));
    match Payload::decode(&body.payload).unwrap() { Payload::Transfer(t) => { assert_eq!(t.amount_u128(), Some(400)); assert_eq!(t.fee_u128(), Some(5)); assert_eq!((t.token_chain, t.token_address, t.to_chain, t.to), (2, [0xaa; 32], 2, [0x22; 32])); } _ => panic!() }
    assert_eq!(rec.digest, digest(&rec.body));
    assert_eq!(st.check_burn(&key(1).address(), &asset, 601, 2, 0).unwrap_err(), BridgeError::InsufficientAsset { have: 600, need: 601 });
    assert_eq!(st.check_burn(&key(1).address(), &asset, 1, 3, 0).unwrap_err(), BridgeError::WrongTokenChain);
    assert_eq!(st.check_burn(&key(1).address(), &Hash::ZERO, 1, 2, 0).unwrap_err(), BridgeError::UnknownAsset);
}
#[test] fn guardian_upgrade_rotates_with_grace_and_rejects_skips() {
    let (c, s) = cfg(); let mut st = BridgeState::from_config(&c);
    let new_keys: Vec<GuardianKey> = s[1..].iter().map(guardian_address).chain([guardian_address(&[7; 32])]).collect();
    let up = |idx: u32| Body { timestamp: 100, nonce: 0, emitter_chain: 1, emitter_address: GOVERNANCE_EMITTER, sequence: idx as u64, consistency_level: 0,
                                payload: Payload::GuardianSetUpgrade(GuardianSetUpgrade { new_index: idx, keys: new_keys.clone() }).encode() };
    assert_eq!(st.check_attest(&attest(&s, 0, up(2)), 100).unwrap_err(), BridgeError::BadUpgradeIndex { expected: 1, got: 2 });
    assert_eq!(st.apply_attest(&attest(&s, 0, up(1)), key(9).address(), 100).unwrap(), AttestOutcome::GuardianSetUpgraded(1));
    assert_eq!(st.current_set, 1); assert_eq!(st.guardian_sets[&0].expires_at, 100 + GUARDIAN_GRACE_SECS); assert_eq!(st.guardian_sets[&1].keys, new_keys);
    // old set still mints inside grace, not after
    assert!(st.check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 1)), 100 + GUARDIAN_GRACE_SECS).is_ok());
    assert_eq!(st.check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 1)), 101 + GUARDIAN_GRACE_SECS).unwrap_err(), BridgeError::Verify(VerifyError::SetExpired));
}
#[test] fn root_changes_with_balances_spent_and_sequence_but_not_burn_records() { /* apply mint -> root changes; clone, clear burns map only -> root equal */ }
```

- [ ] **Step 2: Run, expect failure**: `cargo test -p shrugg-core bridge::state`

- [ ] **Step 3: Implement `state.rs`**

`check_attest`: `let set = self.guardian_sets.get(&index).ok_or(Verify(UnknownGuardianSet))`; `verify` (map to `BridgeError::Verify`); `Payload::decode` else `BadPayload`; for `Transfer`: `emitters.get(&body.emitter_chain) == Some(&body.emitter_address)` else `WrongEmitter`; `to_chain == CHAIN_RAND` else `WrongToChain`; `amount_u128`/`fee_u128` else `AmountOverflow`; `fee <= amount` else `FeeExceedsAmount`; `!spent.contains(digest)` else `Replay`. For `GuardianSetUpgrade`: emitter must be `(CHAIN_RAND, GOVERNANCE_EMITTER)` else `WrongEmitter`; `new_index == current_set + 1` else `BadUpgradeIndex`; keys unique and non-zero else `DuplicateGuardian`; not spent. `apply_attest` calls `check_attest` then mutates: insert spent; mint: `assets.entry(asset).or_insert((token_chain, token_address))`, credit `to` with `amount - fee` and `submitter` with `fee` (skip zero credits so pruning stays clean); upgrade: set old `expires_at = now + GUARDIAN_GRACE_SECS`, insert new set with `expires_at: 0`, `current_set = new_index`. `apply_burn`: `check_burn`, debit (remove the entry when it reaches 0), build the body with `sequence = burn_sequence`, `burn_sequence += 1`, store the record. `root()` as spec 6.3 using `merkle_root` from `crypto`.

`TxKind` variants: append after `Call`; `total_cost` returns `Some(fee)` for both.

- [ ] **Step 4: Run, expect pass**; also `cargo test -p shrugg-core` to confirm nothing else broke.

- [ ] **Step 5: Commit**: `git commit -m "Add BridgeState and bridge transaction kinds"`

### Task C2: ledger integration, genesis section, state root

**Files:**
- Modify: `ledger.rs` (struct fields `bridge: Option<BridgeState>`, `timestamp_ms: u64`; `validate_inner` arms; `apply_tx_with_receipt` arms; `state_root`; `PartialEq`), `genesis.rs` (`bridge: Option<BridgeConfig>` with `#[serde(default)]`, commit bytes, `ledger.set_bridge`), `crates/shrugg-node/src/main.rs` genesis command (`--bridge <file.json>` reads a `BridgeConfig` JSON)

**Interfaces:**
- Produces on `Ledger`: `set_bridge(Option<BridgeState>)`, `bridge() -> Option<&BridgeState>`, `bridge_mut()`, `set_timestamp_ms(u64)`, `asset_balance(&AssetId, &Address) -> u128`. `TxError::Bridge(#[from] BridgeError)`.

- [ ] **Step 1: Write failing tests** in `ledger.rs`:

```rust
fn bridged() -> (Ledger, Vec<[u8; 32]>, Keypair, Address) { /* Ledger::new(1) + credit alice 1_000 + set_bridge(Some(BridgeState::from_config(&cfg))) */ }
#[test] fn bridge_attest_mints_and_burn_emits() {
    let (mut l, s, alice, proposer) = bridged();
    let att = attest(&s, 0, transfer_body(2, 1_000, 10, 1));            // to = alice
    let tx = Transaction::bridge_attest(&alice, 1, 0, att, 1);
    l.apply_tx(&tx, &proposer, &StubExecutor).unwrap();
    let asset = asset_id(2, &[0xaa; 32]);
    assert_eq!(l.asset_balance(&asset, &alice.address()), 1_000);      // 990 + 10 fee (alice submitted)
    assert_eq!(l.balance(&alice.address()), 999); assert_eq!(l.nonce(&alice.address()), 1);
    let burn = Transaction::bridge_burn(&alice, 1, 1, asset, 400, 2, [0x22; 32], 5, 1);
    l.set_timestamp_ms(1_700_000);
    l.apply_tx(&burn, &proposer, &StubExecutor).unwrap();
    assert_eq!(l.asset_balance(&asset, &alice.address()), 600);
    let rec = &l.bridge().unwrap().burns[&0]; assert_eq!(rec.tx, burn.hash()); assert_eq!(Body::decode(&rec.body).unwrap().timestamp, 1_700);
}
#[test] fn bridge_txs_rejected_without_bridge_section() {
    let (l, alice, _, _) = funded();
    let tx = Transaction::bridge_attest(&alice, 1, 0, vec![1], 0);
    assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::Bridge(BridgeError::Disabled)));
}
#[test] fn state_root_unchanged_without_bridge_and_covers_bridge_with() {
    let (a, ..) = funded(); let mut b = a.clone(); b.set_bridge(None); assert_eq!(a.state_root(), b.state_root());
    let (mut l, s, alice, proposer) = bridged(); let before = l.state_root();
    l.apply_tx(&Transaction::bridge_attest(&alice, 1, 0, attest(&s, 0, transfer_body(2, 1, 0, 1)), 0), &proposer, &StubExecutor).unwrap();
    assert_ne!(l.state_root(), before);
}
#[test] fn vectors_ledger_level() { /* include_str! vectors.json; build a ledger from the file's emitters/guardians; for each vector with expect in {ok, wrong_emitter, wrong_to_chain, fee_exceeds_amount, amount_overflow, bad_payload, replay} where verifier_chain == 1, submit as BridgeAttest and assert the mapped TxError */ }
```

And in `genesis.rs`:

```rust
#[test] fn genesis_hash_unchanged_without_bridge_and_changes_with() {
    let g = Genesis::from_json(include_str!("../../../deploy/genesis.json")).unwrap();
    assert_eq!(g.build().unwrap().hash().to_hex(), "7e6271a3aa38f11a43a6b3ad4c2262860cc8fa4b1f5c7b3b37dd6aebae01e917");
    let mut with = g.clone(); with.bridge = Some(BridgeConfig { emitter: [1; 32], guardians: vec![[2; 20]], emitters: BTreeMap::new() });
    assert_ne!(with.build().unwrap().hash(), g.build().unwrap().hash());
    assert!(with.build().unwrap().ledger.bridge().is_some());
}
```

- [ ] **Step 2: Run, expect failure**: `cargo test -p shrugg-core`

- [ ] **Step 3: Implement**

`validate_inner`: `TxKind::BridgeAttest { attestation } => { let b = self.bridge.as_ref().ok_or(BridgeError::Disabled)?; b.check_attest(attestation, self.timestamp_ms / 1000)?; Ok(None) }`, `TxKind::BridgeBurn { asset, amount, to_chain, fee, .. } => { b.check_burn(&sender, asset, *amount, *to_chain, *fee)?; Ok(None) }`. `apply_tx_with_receipt`: after debiting cost/nonce, `BridgeAttest` -> `bridge_mut().apply_attest(attestation, sender, now)`; `BridgeBurn` -> `apply_burn(sender, *asset, *amount, *to_chain, *to, *fee, tx.hash(), self.height, (self.timestamp_ms / 1000) as u32)`. `apply_block` calls `scratch.set_timestamp_ms(block.header.timestamp_ms)` next to `set_height`. `state_root`: if `bridge.is_some()`, hash `accounts_root || programs_root || bridge.root()` (96 bytes) under the same `shrugg-state` domain; else unchanged 64 bytes. `Genesis::build`: `if let Some(b) = &self.bridge { commit.extend(bincode::serialize(b)) }` and `ledger.set_bridge(self.bridge.as_ref().map(BridgeState::from_config))`. `GenesisState` gets `pub bridge: Option<BridgeConfig>`. `shrugg-node genesis --bridge bridge.json` reads a `BridgeConfig` with hex strings (add `serde` hex helpers: `emitter`/`emitters` values as 64-hex, `guardians` as 40-hex) — implement `BridgeConfig`'s serde with `#[serde(with = ...)]` helpers in `state.rs` so the JSON is human-readable while bincode stays bytes. Note: bincode of a `serde(with)` hex string would change the genesis commit; keep the commit as `bincode` of a plain-bytes twin struct `BridgeCommit { emitter, guardians, emitters }` built from the config.

- [ ] **Step 4: Run, expect pass**: `cargo test -p shrugg-core`

- [ ] **Step 5: Commit**: `git commit -m "Wire bridge state into ledger, state root, and genesis"`

### Task C3: storage, node, RPC, client, CLI, cluster test, docs

**Files:**
- Modify: `crates/shrugg-node/src/storage.rs` (CFs `bridge_balances`, `bridge_spent`, `bridge_burns`; meta key `bridge_state`; `init`, `commit`, `load_ledger`, `truncate_to`, integrity check), `node.rs:153-154` (`ledger.set_bridge` from genesis if storage has none), `rpc.rs` (five methods), `crates/shrugg-client/src/lib.rs`, `main.rs`, `crates/shrugg-node/tests/cluster.rs`, `docs/rpc.md`, `docs/cli.md`, `README.md`

**Interfaces:**
- Produces RPC exactly as spec 6.4; client: `asset_balance(&Address, &AssetId)`, `assets(&Address)`, `bridge_state()`, `bridge_burn_record(u64)`, `bridge_attest(&Keypair, Vec<u8>, fee)`, `bridge_burn(&Keypair, AssetId, u128, u16, [u8;32], u128 bridge_fee, u128 fee)`; CLI: `bridge-mint`, `bridge-burn`, `asset-balance`, `bridge-status`.

- [ ] **Step 1: Storage tests** in `storage.rs` tests: init a genesis with a bridge section, commit one block containing a `BridgeAttest`, reopen, `load_ledger()` equals the in-memory ledger (`assert_eq!` uses `Ledger: PartialEq`, which now includes `bridge`), `truncate_to(0)` restores the genesis bridge state. Run, expect failure.

- [ ] **Step 2: Implement storage**: `commit` collects `(asset, addr)` pairs touched by bridge txs (attest: decode payload `to` + sender; burn: sender) and writes their balances; writes each new burn record; writes the `bridge_state` meta blob (`bincode` of `(emitters, guardian_sets, current_set, assets, spent, burn_sequence, emitter)`) whenever the block had a bridge tx. `load_ledger` rebuilds `BridgeState` from the blob + CF scans (returns `None` bridge if the blob is absent). `truncate_to` deletes and rewrites all three CFs from the replayed ledger. Run tests, expect pass.

- [ ] **Step 3: RPC + client + CLI**: add the five methods to `dispatch` following the `shrugg_getAccount` pattern (`parse_address`, `parse_hash`; asset id parsed as 64 hex); `shrugg_getBridgeState` returns `Value::Null` fields when disabled with `"enabled": false`. Client wrappers and CLI subcommands following `Send`/`Faucet`. `bridge-mint` reads `@file` or hex, signs `Transaction::bridge_attest`, waits with `wait_for_transaction`. Unit-test the RPC handlers the way existing RPC tests do (grep `fn rpc_` in `rpc.rs` tests for the pattern).

- [ ] **Step 4: Cluster test** `bridge_mint_reaches_every_node` in `tests/cluster.rs`: copy the `faucet_mint_via_rpc_reaches_every_node` setup (lines 402-433), give the genesis a bridge section with the six vector guardians, submit `transfer_eth_usdt_6dp_ok` from the vectors via `shrugg_sendTransaction`, then poll `shrugg_getAssetBalance` on every node until it equals `amount - fee`. Run: `cargo test --release -p shrugg-node --test cluster bridge_mint`.

- [ ] **Step 5: Docs**: add the RPC table rows to `docs/rpc.md`, CLI commands to `docs/cli.md`, a "Bridged assets" paragraph and the genesis `bridge` section to `README.md`.

- [ ] **Step 6: Full run**: `cd ../fullnode && cargo test --release`. Expected: all green, counts increase from 58 core / 18 node / 10 cluster.

- [ ] **Step 7: Commit**: `git commit -m "Persist and expose bridge state: storage, RPC, wallet, cluster test"`

---

## Part D: EVM-family contracts (Ethereum, BSC, Tron)

### Task D1: Foundry project and `Attestation` library

**Files:**
- Create: `evm/foundry.toml`, `evm/src/lib/Attestation.sol`, `evm/test/Attestation.t.sol`, `evm/test/Vectors.t.sol`, `evm/test/utils/VectorLoader.sol`, `evm/.gitignore` (`out/ cache/ lib/`)
- Run once: `cd evm && forge init --no-git --no-commit --force . && forge install foundry-rs/forge-std --no-git` (only `forge-std` is needed; no OpenZeppelin).

**Interfaces:**
- Produces:

```solidity
library Attestation {
    uint16 constant CHAIN_RAND = 1; uint16 constant CHAIN_ETHEREUM = 2; uint16 constant CHAIN_BSC = 3; uint16 constant CHAIN_TRON = 4; uint16 constant CHAIN_SOLANA = 5;
    bytes32 constant GOVERNANCE_EMITTER = 0x...;   // pinned value from Task A1 step 3
    uint256 constant GUARDIAN_GRACE = 86400;
    uint256 constant SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    struct Signature { uint8 index; bytes32 r; bytes32 s; uint8 v; }
    struct Parsed { uint32 guardianSetIndex; Signature[] signatures; uint32 timestamp; uint32 nonce; uint16 emitterChain;
                    bytes32 emitterAddress; uint64 sequence; uint8 consistencyLevel; bytes payload; bytes32 digest; }
    struct Transfer { uint256 amount; bytes32 tokenAddress; uint16 tokenChain; bytes32 to; uint16 toChain; uint256 fee; }
    struct GuardianUpgrade { uint32 newIndex; address[] keys; }
    error BadVersion(); error Truncated(); error BadPayloadId(); error BadPayloadLength(); error NoQuorum(uint256 have, uint256 need);
    error IndexOrder(); error IndexOutOfRange(); error HighS(uint8 index); error BadSignature(uint8 index); error WrongGuardian(uint8 index);
    function parse(bytes calldata data) internal pure returns (Parsed memory p);          // digest = keccak256(abi.encodePacked(keccak256(body)))
    function quorum(uint256 n) internal pure returns (uint256) { return n * 2 / 3 + 1; }
    function verifySignatures(bytes32 digest, Signature[] memory sigs, address[] memory keys) internal pure;   // reverts on failure
    function parseTransfer(bytes memory payload) internal pure returns (Transfer memory);
    function parseGuardianUpgrade(bytes memory payload) internal pure returns (GuardianUpgrade memory);
    function encodeTransfer(Transfer memory t) internal pure returns (bytes memory);    // used by lock() to build the payload
}
```

`foundry.toml`: `solc = "0.8.20"`, `evm_version = "paris"`, `optimizer = true`, `optimizer_runs = 200`, `fs_permissions = [{ access = "read", path = "../vectors" }]`.

- [ ] **Step 1: Write failing tests** `Attestation.t.sol` (a thin harness contract exposes the library): `test_parse_layout` (hand-built bytes, assert every field and digest = `keccak256(abi.encodePacked(keccak256(body)))`), `test_quorum_values` (6->5, 4->3, 1->1), `test_rejects_bad_version_and_truncation`, `test_transfer_payload_exact_length` (132 and 134 bytes revert `BadPayloadLength`), `test_verify_signatures_with_vm_sign` (use `vm.addr`/`vm.sign` on 6 keys, 5 sigs pass, 4 revert `NoQuorum(4,5)`, duplicate revert `IndexOrder`, index 6 revert `IndexOutOfRange`, forged key revert `WrongGuardian(2)`, `s = type(uint256).max` revert `HighS(0)`).

`Vectors.t.sol`: `VectorLoader` reads `../vectors/attestations.json` with `vm.readFile` + `vm.parseJson*`; for each vector whose `expect` is in {`ok`, `no_quorum`, `index_order`, `index_out_of_range`, `high_s`, `wrong_guardian`, `bad_version`, `bad_payload`} and whose `sets` contains the vector's `guardian_set_index`, call `parse` + `verifySignatures` against that set's keys and assert the mapped revert (or success + digest match). Loop by index over `vm.parseJsonUint(json, ".vectors.length")`-style access: use `stdJson` and a fixed max of 64 with `vm.keyExists`.

- [ ] **Step 2: Run** `forge test -vv`, expect compile failure.

- [ ] **Step 3: Implement `Attestation.sol`** with manual calldata/memory slicing (no `abi.decode`): read big-endian integers via `uint256(bytes32(data[i:i+32])) >> (256 - 8*width)`; `verifySignatures` enforces strictly increasing `index`, `index < keys.length`, `sigs.length >= quorum(keys.length)`, `uint256(s) <= SECP256K1_HALF_N`, `ecrecover(digest, v + 27, r, s)` non-zero and equal to `keys[index]`.

- [ ] **Step 4: Run** `forge test -vv`, expect pass.

- [ ] **Step 5: Commit**: `git add evm && git commit -m "Add Foundry project and Attestation library"`

### Task D2: `RandBridgeBase` and the three chain contracts

**Files:**
- Create: `evm/src/interfaces/IRandBridge.sol`, `evm/src/lib/SafeTransfer.sol`, `evm/src/RandBridgeBase.sol`, `evm/src/EthereumRandBridge.sol`, `evm/src/BscRandBridge.sol`, `evm/src/TronRandBridge.sol`, `evm/test/mocks/MockERC20.sol` (configurable decimals, optional no-return-value mode, optional fee-on-transfer mode), `evm/test/RandBridge.t.sol`, `evm/test/BridgeVectors.t.sol`, `evm/script/Deploy.s.sol`

**Interfaces:**
- Produces:

```solidity
interface IRandBridge {
    event MessagePublished(uint64 indexed sequence, uint32 nonce, uint8 consistencyLevel, bytes payload);
    event Locked(address indexed token, address indexed from, bytes32 indexed randRecipient, uint256 locked, uint256 attested, uint64 sequence);
    event Released(address indexed token, address indexed to, uint256 amount, uint256 fee, bytes32 digest);
    event TokenConfigured(address indexed token, bool enabled, uint256 perTransferCap, uint256 dailyCap);
    event GuardianSetUpgraded(uint32 indexed index, address[] keys);
    event Paused(address by); event Unpaused(address by);
    event AdminTransferStarted(address indexed to); event AdminTransferred(address indexed to); event PauserSet(address indexed pauser);
    struct TokenConfig { bool enabled; uint8 decimals; uint256 perTransferCap; uint256 dailyCap; uint256 windowStart; uint256 windowUsed; }
    struct GuardianSet { address[] keys; uint256 expirationTime; }
    function lock(address token, uint256 amount, bytes32 randRecipient, uint256 relayerFee, uint32 nonce) external returns (uint64 sequence);
    function release(bytes calldata attestation) external;
    function submitGuardianSetUpgrade(bytes calldata attestation) external;
    function setToken(address token, bool enabled, uint256 perTransferCap, uint256 dailyCap) external;
    function setPauser(address pauser) external; function pause() external; function unpause() external;
    function transferAdmin(address to) external; function acceptAdmin() external;
    function chainId() external view returns (uint16); function randEmitter() external view returns (bytes32);
    function currentGuardianSetIndex() external view returns (uint32); function guardianSet(uint32 index) external view returns (GuardianSet memory);
    function custody(address token) external view returns (uint256); function consumed(bytes32 digest) external view returns (bool);
    function tokenConfig(address token) external view returns (TokenConfig memory); function sequence() external view returns (uint64);
    function normalize(uint256 amount, uint8 decimals) external pure returns (uint256 locked, uint256 attested);
    function denormalize(uint256 attested, uint8 decimals) external pure returns (uint256);
}
```

Constructor: `(address admin, address pauser, bytes32 randEmitter, address[] memory guardians)`. Chain contracts pass `CHAIN_ID`/`CONSISTENCY_LEVEL` via `constant` overrides of two `virtual` getters. `DEPLOY_CHAIN_ID = block.chainid` immutable; `_checkFork()` reverts `WrongFork()` if it differs; `TronRandBridge` overrides `_checkFork` to a no-op. Errors: `NotAdmin, NotPauser, IsPaused, NotPaused, TokenDisabled, ZeroRecipient, FeeExceedsAmount, ZeroAmount, TransferAmountMismatch, WrongEmitter, WrongToChain, WrongTokenChain, AlreadyConsumed, InsufficientCustody, PerTransferCap, DailyCap, BadRecipient, UnknownGuardianSet, GuardianSetExpired, BadUpgradeIndex, DuplicateGuardian, WrongFork, ZeroAddress`.

Lock builds the body itself is NOT required on chain; it emits `MessagePublished(sequence, nonce, consistencyLevel, payload)` where `payload = encodeTransfer({amount: attested, tokenAddress: bytes32(uint256(uint160(token))), tokenChain: CHAIN_ID, to: randRecipient, toChain: 1, fee: relayerFee normalised})`. Sequences start at 0 and increment after use.

- [ ] **Step 1: Write failing tests** `RandBridge.t.sol` against `EthereumRandBridge` with 6 `vm.addr` guardians and a helper `sign(bodyBytes, keys[0..5])` that builds a full attestation; cases: `test_lock_pulls_normalised_amount_6dp` (amount 1_234_567 at 6dp -> attested 123_456_700, locked 1_234_567), `test_lock_truncates_18dp` (1e18+123 -> locked 1e18, attested 1e8, custody 1e18), `test_lock_rejects_zero_recipient_disabled_token_fee_gt_amount_paused_dust` (18dp amount 1 -> `ZeroAmount`), `test_lock_rejects_fee_on_transfer_token` (`TransferAmountMismatch`), `test_lock_emits_payload_matching_encodeTransfer`, `test_release_pays_recipient_and_relayer` (lock 1000, release attested 1000 fee 10 from Rand emitter; recipient +990, relayer +10, custody 0, consumed true), `test_release_rejects_replay_wrong_emitter_wrong_chain_wrong_token_chain_bad_recipient` (recipient with non-zero top bytes -> `BadRecipient`), `test_release_custody_counter_bounds_loss` (attest 2000 with custody 1000 -> `InsufficientCustody`), `test_release_caps` (perTransfer 500 -> `PerTransferCap`; daily 900 across two releases -> `DailyCap`; `vm.warp(+1 days)` resets), `test_release_usdt_style_no_return_token`, `test_guardian_upgrade_and_grace` (upgrade to index 1; old set works until `+86400`, fails after with `GuardianSetExpired`; skip to 2 first -> `BadUpgradeIndex`), `test_pause_roles_and_admin_two_step`, `test_fork_guard_eth_and_not_tron` (`vm.chainId(999)` -> `WrongFork` on Ethereum, ok on Tron), `test_bsc_and_tron_constants` (chainId 3/4, consistency 15/19).

`BridgeVectors.t.sol`: deploy `EthereumRandBridge` with the vector guardians and `rand_emitter`, enable the vector token address (deploy a `MockERC20` at that address with `vm.etch` or, simpler, use `deployCodeTo`), fund custody via a lock, then for each vector with `verifier_chain == 2` assert `release` succeeds for `expect == ok` and reverts with the mapped error otherwise (`wrong_emitter`, `wrong_to_chain`, `wrong_token_chain`, `fee_exceeds_amount`, `replay`).

- [ ] **Step 2: Run** `forge test`, expect failures.

- [ ] **Step 3: Implement** `SafeTransfer` (low-level `call`, success and (no return data or decoded true)), `RandBridgeBase` per spec 5.1 with `TokenConfig.decimals` captured from `IERC20Metadata(token).decimals()` in `setToken`, then the three concrete contracts (each ~15 lines), `Deploy.s.sol` reading `ADMIN`, `PAUSER`, `RAND_EMITTER`, `GUARDIANS` (comma list) from env and choosing the contract by `CHAIN` env.

- [ ] **Step 4: Run** `forge test -vv` and `forge build --sizes`, expect pass and each contract under 24 KiB.

- [ ] **Step 5: Commit**: `git commit -m "Add RandBridgeBase and Ethereum/BSC/Tron bridge contracts"`

### Task D3: Tron deployment notes

**Files:**
- Create: `tron/README.md`, `tron/tronbox.js`, `tron/migrations/2_deploy.js`

- [ ] **Step 1**: Write `tronbox.js` (solc 0.8.20, `evmVersion: "paris"`, networks `shasta`, `nile`, `mainnet` from `PRIVATE_KEY_*` env) and a migration that deploys `TronRandBridge` with admin/pauser/emitter/guardians from env. `README.md`: how to copy `evm/src` into TronBox's `contracts/`, address conversion (`T...` base58check -> hex, drop `41`), USDT `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` and USDC `TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8` mainnet addresses, and that `chainid` is not relied upon.
- [ ] **Step 2: Commit**: `git commit -m "Add Tron deployment notes"`

---

## Part E: Solana program

### Task E1: workspace, state, and attestation verification

**Files:**
- Create: `solana/Cargo.toml` (workspace; `[patch]` none), `solana/programs/rand-bridge/Cargo.toml` (deps: `solana-program = "2"`, `bridge-codec = { path = "../../../../fullnode/crates/bridge-codec" }`, `spl-token = { version = "7", features = ["no-entrypoint"] }`, `spl-associated-token-account = { version = "6", features = ["no-entrypoint"] }`, `borsh = "1"`, `thiserror`; dev: `solana-program-test = "2"`, `solana-sdk = "2"`, `serde_json`, `hex`), `src/{lib,entrypoint,error,state,attestation,instruction,processor}.rs`
- Test: `programs/rand-bridge/tests/attestation.rs`

**Interfaces:**
- Produces (`state.rs`, all `BorshSerialize/BorshDeserialize` with a leading `u8` discriminator):

```rust
pub const CHAIN_ID: u16 = 5; pub const CONSISTENCY_LEVEL: u8 = 1;
pub struct Config { pub admin: Pubkey, pub pending_admin: Pubkey, pub pauser: Pubkey, pub paused: bool, pub rand_emitter: [u8; 32], pub current_guardian_set: u32, pub sequence: u64, pub bump: u8 }
pub struct GuardianSetAccount { pub index: u32, pub keys: Vec<[u8; 20]>, pub expiration_time: u64 }
pub struct TokenRegistry { pub mint: Pubkey, pub enabled: bool, pub decimals: u8, pub per_transfer_cap: u64, pub daily_cap: u64, pub window_start: u64, pub window_used: u64, pub custody: u64 }
pub struct Consumed { pub digest: [u8; 32] }
pub struct PostedMessage { pub sequence: u64, pub body: Vec<u8> }
pub mod seeds { pub const CONFIG: &[u8] = b"config"; pub const GUARDIAN: &[u8] = b"guardian"; pub const TOKEN: &[u8] = b"token"; pub const AUTHORITY: &[u8] = b"authority"; pub const CUSTODY: &[u8] = b"custody"; pub const SPENT: &[u8] = b"spent"; pub const MSG: &[u8] = b"msg"; }
pub fn config_pda(program: &Pubkey) -> (Pubkey, u8);  // and guardian_pda(program, index), token_pda(program, mint), authority_pda, custody_pda(program, mint), spent_pda(program, digest), msg_pda(program, seq)
```

`attestation.rs`: `pub fn verify(bytes: &[u8], set: &GuardianSetAccount, now: u64) -> Result<(Attestation, [u8; 32]), BridgeError>` using `solana_program::keccak::hashv` and `solana_program::secp256k1_recover::secp256k1_recover`; guardian key = `keccak(pubkey 64 bytes)[12..]`. `error.rs`: `BridgeError` enum with the same names as the EVM errors plus `InvalidPda`, `InvalidAta`, mapped to `ProgramError::Custom`.

- [ ] **Step 1: Write failing test** `tests/attestation.rs`: load `../../../vectors/attestations.json`, and for each vector with `expect` in {`ok`, `no_quorum`, `index_order`, `index_out_of_range`, `high_s`, `wrong_guardian`, `bad_version`, `set_expired`, `unknown_set`} call `rand_bridge::attestation::verify` natively (the secp256k1 syscall has a native fallback in `solana-program` off-chain) and assert. Run `cd solana && cargo test -p rand-bridge --test attestation`, expect compile failure.

- [ ] **Step 2: Implement** state, PDAs, error, attestation. Run tests, expect pass.

- [ ] **Step 3: Commit**: `git commit -m "Add Solana rand-bridge program state and attestation verifier"`

### Task E2: instructions and processor

**Files:**
- Modify: `src/instruction.rs`, `src/processor.rs`, `src/entrypoint.rs`
- Test: `programs/rand-bridge/tests/bridge.rs` (program-test)

**Interfaces:**
- Produces `BridgeInstruction` (borsh):

```rust
pub enum BridgeInstruction {
    Initialize { admin: Pubkey, pauser: Pubkey, rand_emitter: [u8; 32], guardians: Vec<[u8; 20]> },
    SetToken { enabled: bool, per_transfer_cap: u64, daily_cap: u64 },
    Lock { amount: u64, rand_recipient: [u8; 32], relayer_fee: u64, nonce: u32 },
    Release { attestation: Vec<u8> },
    GuardianSetUpgrade { attestation: Vec<u8> },
    Pause, Unpause, TransferAdmin { to: Pubkey }, AcceptAdmin,
}
```

Account lists (documented in `instruction.rs` doc comments, with builder fns `initialize(...) -> Instruction` etc.):

- `Initialize`: payer (signer), config PDA (w), guardian set 0 PDA (w), authority PDA, system program.
- `SetToken`: admin (signer), config, mint, token registry PDA (w, create if missing), custody PDA (w, create as token account owned by authority if missing), authority PDA, token program, system program, rent.
- `Lock`: owner (signer), owner token account (w), config (w), mint, token registry (w), custody (w), message PDA (w), token program, system program, clock sysvar. Transfers `locked` via `spl_token::instruction::transfer`, checks the custody balance delta, writes `PostedMessage{ sequence, body }` with `body = Body{ timestamp: clock.unix_timestamp as u32, nonce, emitter_chain: 5, emitter_address: program_id, sequence, consistency_level: 1, payload: transfer(attested, mint, 5, rand_recipient, 1, fee_attested) }.encode()`.
- `Release`: relayer (signer, pays rent), config, guardian set PDA (for the attestation's index), mint, token registry (w), custody (w), authority, recipient ATA (w), relayer ATA (w), consumed PDA (w, create), token program, system program, clock. Checks per spec 5.1; transfers with `invoke_signed` using the authority bump.
- `GuardianSetUpgrade`: payer (signer), config (w), current guardian set PDA (w), new guardian set PDA (w, create), consumed PDA (w, create), system program, clock.
- `Pause`: pauser signer + config. `Unpause`/`TransferAdmin`/`AcceptAdmin`: admin (or pending admin) signer + config.

- [ ] **Step 1: Write failing program-test** `tests/bridge.rs` with `ProgramTest::new("rand_bridge", id, processor!(process_instruction))`: `initialize_and_set_token`, `lock_transfers_and_posts_message` (mint 6dp, amount 1_234_567 -> custody 1_234_567, `PostedMessage.body` decodes with amount 123_456_700, emitter = program id), `lock_truncates_9dp_mint` (amount 1_000_000_001 -> locked 1_000_000_000, attested 100_000_000), `release_pays_recipient_and_relayer` (build a vector-style attestation signed by 5 of the six test secrets with `k256` in dev-deps, from the Rand emitter, `to_chain 5`, `token_chain 5`, `token_address = mint`), `release_rejects_replay_wrong_emitter_caps_paused_and_insufficient_custody`, `guardian_upgrade_then_old_set_grace` (use `context.warp_to_slot` plus a clock override via `set_sysvar` to advance `unix_timestamp`), `vectors_release_to_solana` (every vector with `verifier_chain == 5`; the mint is created at the vector's `token_address` pubkey via `ProgramTest::add_account` with a serialized `spl_token::state::Mint`).

- [ ] **Step 2: Run** `cd solana && cargo test -p rand-bridge`, expect failure.

- [ ] **Step 3: Implement** `processor.rs` (one `fn process_<name>` per instruction, shared helpers `load_config`, `check_pda`, `create_pda_account`, `normalize`/`denormalize` in u128 arithmetic), `entrypoint.rs` (`entrypoint!` guarded by `#[cfg(not(feature = "no-entrypoint"))]`).

- [ ] **Step 4: Run** tests, expect pass. Also `cargo build-sbf` is not available on this machine; note in README that deployment builds need the Solana CLI.

- [ ] **Step 5: Commit**: `git commit -m "Add Solana rand-bridge instructions and processor"`

---

## Part F: repo docs

### Task F1: README and attestation reference

**Files:**
- Create: `README.md`, `spec/ATTESTATION.md`

- [ ] **Step 1**: `README.md`: what the bridge is (two paragraphs), layout table, build/test commands per component (`cd evm && forge test`, `cd solana && cargo test`, `cd tools/vectors && cargo run --release -- --check`, fullnode `cargo test --release`), deployment order (fullnode genesis with `bridge` section -> contracts with the same guardians and emitter -> register each contract address in the genesis `emitters` map before launch), and the security notes from spec Section 8. `spec/ATTESTATION.md`: spec Section 3 verbatim plus a worked example decoded from `transfer_eth_usdt_6dp_ok`.
- [ ] **Step 2: Commit**: `git commit -m "Add README and attestation reference"`

---

## Self-review

- Spec coverage: 3 (A1, A2, D1, E1), 4 (A2 `asset_id`, C1), 5.1 (D2, E2), 5.2-5.4 (D2, D3), 5.5 (E1, E2), 6.1 (C2), 6.2-6.3 (C1, C2), 6.4 (C3), 7.1 (B1), 7.2 (every task's tests), 8 (F1).
- Names used consistently: `verify`, `sign_digest`, `guardian_address`, `asset_id`, `digest`, `check_attest`/`apply_attest`, `check_burn`/`apply_burn`, `BridgeError` variants, `expect` codes, `GOVERNANCE_EMITTER`, `GUARDIAN_GRACE_SECS`/`GUARDIAN_GRACE`.
- Chain 1 verification of `to_chain` happens in `BridgeState::check_attest`; chains 2..5 in the contracts; both use the same vectors.
