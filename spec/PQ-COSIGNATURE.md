# The Dilithium2 co-signature on Rand mints

Status: **proposed 2026-09-19** for the chain-14 cut (the user's decision, from the 18 September
design review's option C). Normative once the fullnode spec adopts it verbatim. It adds a second,
post-quantum authorisation to everything the Rand ledger accepts from the guardians. **It changes
nothing in `ATTESTATION.md`, in the 39 shared vectors, or in any deployed endpoint**: the
co-signatures travel *beside* the attestation, and only the Rand ledger verifies them.

## 1. Scope

Every `BridgeAttest` on Rand — a deposit (transfer payload, `to_chain = 1`) and a guardian-set
rotation (payload 2) alike — must carry, in addition to the attestation's ECDSA quorum, a quorum of
Dilithium2 signatures by the same guardians. Releases on the source chains stay classical: their
loss is bounded by custody and caps, and those chains have no lattice verifier.

## 2. Keys

- Scheme: **Dilithium2, round 3**, exactly the parameter set of `crystals_dilithium::dilithium2`
  (crate `crystals-dilithium` 2.0) that the Rand node already uses for validator keys — *not*
  ML-DSA-44. Public key 1,312 bytes, signature 2,420 bytes.
- A guardian's PQ key is derived from a 32-byte seed: `dilithium2::Keypair::generate(Some(seed))`,
  as `randprotocol_core::crypto::Keypair::from_seed` does. The guardian holds the seed.
- Genesis: `bridge.pq_guardians` is a list of `n` public keys (hex), **index-aligned with
  `bridge.guardians`**: `pq_guardians[i]` belongs to the operator of `guardians[i]`. Both lists have
  the same length. Keys are unique; a key of the wrong length is refused at genesis validation.
- PQ keys are generated **on the operator's host** and never leave it; only the public key is sent.

## 3. What is signed

```
M = "rand-bridge-pq-cosign-1"     23 bytes, ASCII, no terminator
  ‖ rand_chain_id                  u64, big-endian — the Rand chain's `chain_id` (`rand_chainId`)
  ‖ mu                             32 bytes — keccak256(keccak256(body)), ATTESTATION.md §3.3
```

`M` is 63 bytes. Signing is **deterministic** (`randomized = false`, which is what
`dilithium2::SecretKey::sign` does), so a vector reproduces byte for byte.

- `mu` is the same digest the ECDSA quorum signs, over the same wire body: one body, two quorums.
- `rand_chain_id` is there on purpose. An attestation does not name its network
  (`ATTESTATION.md` §3.5), so a testnet ECDSA attestation verifies on mainnet if guardian keys are
  shared. The co-signature does name it: **a testnet co-signature never verifies on a mainnet Rand
  chain**, whatever keys were reused. It costs the guardian one configuration value, which it
  cross-checks against `rand_chainId` at start.
- The guardian-set index is **not** in `M`, exactly as it is not in `mu`: a co-signature stays valid
  across an ECDSA-set rotation, so in-flight deposits need no re-signing.

## 4. The field in `BridgeAttest`

```rust
pub struct PqSignature {
    pub index: u8,            // position in bridge.pq_guardians
    pub signature: Vec<u8>,   // exactly 2,420 bytes
}

Action::BridgeAttest { attestation, recipient, r, time, asset, envelope,
                       pq_signatures: Vec<PqSignature> }   // new, last field
```

Encoded by the ledger's bincode like the rest of the action (it is inside the transaction binding,
so it cannot be stripped or swapped on a copy). Rules, all enforced at admission:

1. `pq_signatures.len() >= quorum(n)` with `quorum(n) = n * 2 / 3 + 1` and `n = pq_guardians.len()`
   — the same formula as the ECDSA quorum — and `<= n`.
2. Indices strictly increasing, each `< n` (so no signer counts twice).
3. Every `signature.len() == 2420`.
4. Every signature verifies `M` under `pq_guardians[index]`. One failure refuses the transaction; a
   relayer therefore sends exactly a quorum of signatures it has verified itself.
5. The PQ signers need **not** be the same indices as the ECDSA signers: each quorum is counted on
   its own, so one guardian with a broken PQ signer does not cost the ECDSA quorum its liveness.

Cost: five signatures are 12,100 bytes plus five index bytes and the length prefixes. The
attestation size cap (`MAX_ATTESTATION_BYTES`) is unchanged; the transaction's own size limit must
admit the extra ~12.2 KB.

Order of checks on Rand: the cheap structural rules (1–3) before any signature work; then the
existing attestation checks; then the Dilithium verifications. Errors: `PqNoQuorum`, `PqIndexOrder`,
`PqIndexOutOfRange`, `PqBadSignatureLength`, `PqBadSignature`.

## 5. Rotation

Chain 14 fixes `pq_guardians` in genesis. A `GuardianSetUpgrade` (payload 2) rotates the **ECDSA**
set on every chain, as today, and on Rand it must itself carry a PQ quorum by the *current* PQ set.
It does not change the PQ set: payload 2 has no room for 1,312-byte keys and the deployed endpoints
must keep accepting it unchanged. Rotating PQ keys is a Rand-only governance message (the deferred
payload id 3), to be specified with it. Until then a guardian that is rotated out of the ECDSA set
keeps a PQ key that counts — so an ECDSA rotation that removes an operator should be followed by the
PQ rotation as soon as that exists, and the launch set should be chosen with that in mind.

## 6. Guardian API and relayer

`GET /v1/signature/{emitter_chain}/{sequence}` gains, for bodies addressed to Rand:

```json
{ "message": { … }, "guardian": "<20-byte hex>", "signature": { "r": …, "s": …, "v": … },
  "pq_signature": "<4840 hex chars>" }
```

The relayer reads `pq_guardians` and the chain id from the Rand node, maps each guardian's ECDSA
address to its index, verifies `pq_signature` over `M` under `pq_guardians[index]`, keeps the lowest
`quorum(n)` indices, and passes them to the wallet:
`rand bridge-mint @attestation.hex --pq @pq.json --to <rand1…>` with
`pq.json = [{"index": 0, "signature": "<hex>"}, …]`.

## 7. Vectors

`vectors/pq-cosignatures.json` (generator: `tools/vectors`, consumed by the fullnode and the
daemons): six test seeds (`seed_i = keccak256("rand-bridge-pq-test-guardian" ‖ u8(i))`), their
public keys, a test `rand_chain_id`, and for each existing *ok* vector addressed to Rand the message
`M`, all six signatures, and the expected verdict; negatives: four of six, a repeated index, an
index out of range, a 2,419-byte signature, a signature by the wrong index, the right signatures
under another `rand_chain_id`, a co-signature over a different `mu`. The 39 attestation vectors are
untouched.

## 8. Rand-only governance messages (agreed 2026-09-19)

Chain 14 also takes three messages that never reach a source-chain endpoint and are not attestation
payloads, so `bridge-codec` and the deployed contracts stay byte-stable. All integers big-endian,
no length prefixes unless stated. The authoritative text is the fullnode's
`docs/superpowers/specs/2026-09-19-bridge-hardening-design.md` §9–§10; this is the signer's copy.

| message | bytes | signed by |
|---|---|---|
| pause minting | `"rand-bridge-pause-1" ‖ rand_chain_id u64 ‖ pause_nonce u64` | the one genesis Dilithium2 `pause_key` — it can pause, never unpause |
| unpause | `"rand-bridge-pq-unpause-1" ‖ rand_chain_id u64 ‖ pause_nonce u64` | a PQ guardian quorum (`PqSignature` list, the five rules of §4) |
| list a backing | `"rand-bridge-pq-list-1" ‖ rand_chain_id u64 ‖ list_nonce u64 ‖ token_index u32 ‖ chain u16 ‖ token [32] ‖ decimals u8` | a PQ guardian quorum |
| register a bridged token | `"rand-bridge-pq-register-1" ‖ rand_chain_id u64 ‖ list_nonce u64 ‖ u8 len ‖ name ‖ u8 len ‖ symbol ‖ salt [32] ‖ chain u16 ‖ token [32] ‖ decimals u8` | a PQ guardian quorum |

`pause` and `unpause` share `pause_nonce`; `list` and `register` share `list_nonce`; each is the
ledger's current value and moves on acceptance. `rand_getBridgeState` serves `mint_paused`,
`pause_nonce`, `list_nonce`, `pause_key` and `pq_guardians`, so a signing tool never guesses.

**Order when adding a coin: list it on Rand first, `setToken` on the endpoint second.** The other
order opens a window in which a lock succeeds on the endpoint and its attestation is refused
`UnlistedToken` on Rand — the funds are safe in custody but stuck until the listing lands.

These are signed by a deliberate, offline-style CLI (with the guardian-set rotation), never by the
guardian daemon. Also decided for chain 14: an inbound mint cap of 100,000 zUSD per backing per day
and a forward bound on block timestamps.
