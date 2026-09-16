# Rand Bridge: attestation wire format

This is Section 3 of `docs/superpowers/specs/2026-09-10-rand-bridge-design.md`, reproduced
verbatim, followed by a worked example decoded from the shared test vectors
(`vectors/attestations.json`). It is the format all five verifiers (Ethereum, BSC, Tron, Solana,
and the Rand fullnode) parse and check identically.

Only the accept/reject decision is normative across verifiers: for any given attestation all
five must agree on whether it is valid. The *error code* a verifier reports for a rejection is
not — each names its own (`GuardianSetExpired` on the EVM and Solana endpoints is
`Verify(SetExpired)` on the Rand fullnode, for instance), and the shared vectors' `expect`
field names the rule, not any one verifier's code.

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
release the contract denormalises the same way. Rand holds a bridged amount directly in attested
units (8 decimals) in a shielded note whose amount field is a `u64`: an attested `amount` whose top
16 bytes are non-zero is rejected as `AmountOverflow`, and one above `u64::MAX` as
`AmountTooLarge`. Every source-chain lock refuses to publish an attested amount above `u64::MAX`
for the same reason, so nothing can be locked that Rand could never mint.

### 3.7a The `to` field on Rand, and the fee

For a transfer to Rand (`to_chain = 1`), `to` is `blake3("rand-shielded-recipient" || pk ||
kem_ek)` of the recipient's shielded address: the address itself is about 1.2 KB and the field has
room for a hash. The Rand wallet prints the hash; the submitter of the attestation supplies the
full address alongside it and the ledger recomputes and compares. `fee` is carried for the record
on this direction only — Rand mints the gross `amount` and pays no relayer, because a shielded
chain has no submitter identity to pay. On the way out of Rand (`to_chain` 2..5) `fee` is paid to
the relayer by the release, as §3.6 describes.

### 3.8 Emitter binding and replay

Every verifier keeps a table `registered_emitter[chain] -> address` fixed at deployment. A
transfer is accepted only if `emitter_address == registered_emitter[emitter_chain]`, looked up
by the attestation's own `emitter_chain` field (paper `def:emitterbinding`). Source contracts
register exactly one entry, chain 1 -> the Rand emitter. The fullnode registers one entry per
source chain from genesis.

Every verifier records consumed digests `mu` and rejects a second submission.

## Worked example: `transfer_eth_usdt_6dp_ok`

Source: `vectors/attestations.json`, vector `transfer_eth_usdt_6dp_ok` (generated by
`tools/vectors`; a byte-identical copy lives at the fullnode's
`crates/randprotocol-core/src/bridge/vectors.json`). It is a valid Ethereum-to-Rand transfer of 1 USDT
(a 6-decimal token), signed by 5 of the launch guardian set's 6 keys (quorum `q = 5`, `n = 6`).
The full attestation is 520 bytes:

```
01000000000500f039b32234a5fefbe118ee8c091acfc6226b39ba8865a7e0e143a0d833451bec10cd36416deb987c7c
59e3ac42cbbbdf134a175635578f984126d3880b3b70c6010163f69a2a9ec9564e68f6f3096c24bce7acdb9678e00fe4
8b10dc5888debb229b3b195f75519709f5045bef75e3ce346246b82fee35a85fb9895d0898dba6866e00025ec38df8b7
76581aee88f6180fe99071f0c38a5e0b9fd821813b5ceeafaacb5e73b3b4880519c36a089c9db4d33046e55ffd183ed9
a8afb2e3d93e98edf13b040103c8a1d0a93c62975ecd5e5619de001d4f6f83eda42ab7b2eeb24c4cd49ef416582ae1c6
563c64ed3141d0255257d3190b860814ffa0272667054c000dbbc63c3e00043082f5195fb2cffda5f9884b8a02fab580
efb2267fc2f49726e8a61e308695bc2ae1dca79839a07b6298a35075fcefaae6200e1b535b628eef092a6c6cae8d1801
6b49ce180000000700020000000000000000000000007be73b644df28af8148b26cf1d401cc806f1c9ba000000000000
000301010000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000
f10befe1e0794722d3baf8bfd5bdac47b2a3314800021111111111111111111111111111111111111111111111111111
111111111111000100000000000000000000000000000000000000000000000000000000000003e8
```

(line-wrapped above for readability; it is one continuous hex string in the vectors file).

### Envelope — bytes `[0:336)`

| offset | bytes | field | value |
|---|---|---|---|
| `[0:1)` | `01` | `version` | 1 |
| `[1:5)` | `00000000` | `guardian_set_index` | 0 (the launch set) |
| `[5:6)` | `05` | `n_sigs` | 5 (meets `q = 5` for `n = 6`) |

Five 66-byte signatures follow at `[6:336)`, indices `0..4` strictly increasing, each
`guardian_index` (1) + `r` (32) + `s` (32) + `recovery_id` (1):

| sig | offset | `guardian_index` | `r` (abbreviated) | `s` (abbreviated) | `recovery_id` |
|---|---|---|---|---|---|
| 0 | `[6:72)` | `00` | `f039b32234a5…a0d833451bec` | `10cd36416deb…d3880b3b70c6` | `01` |
| 1 | `[72:138)` | `01` | `63f69a2a9ec9…5888debb229b` | `3b195f755197…0898dba6866e` | `00` |
| 2 | `[138:204)` | `02` | `5ec38df8b776…5ceeafaacb5e` | `73b3b4880519…3e98edf13b04` | `01` |
| 3 | `[204:270)` | `03` | `c8a1d0a93c62…4cd49ef41658` | `2ae1c6563c64…000dbbc63c3e` | `00` |
| 4 | `[270:336)` | `04` | `3082f5195fb2…a61e308695bc` | `2ae1dca79839…2a6c6cae8d18` | `01` |

Each `guardian_index` is checked against the launch guardian set's recovered signer address; the
recovered addresses for this vector are guardians 0–4 of the 6-key launch set in
`vectors/attestations.json`'s `guardians` array.

### Body — bytes `[336:520)`, 184 bytes

`mu = keccak256(keccak256(body))`, computed over exactly these 184 bytes:

| offset | bytes | field | decoded |
|---|---|---|---|
| `[336:340)` | `6b49ce18` | `timestamp` | 1799999000 |
| `[340:344)` | `00000007` | `nonce` | 7 |
| `[344:346)` | `0002` | `emitter_chain` | 2 (Ethereum) |
| `[346:378)` | `0000000000000000000000007be73b644df28af8148b26cf1d401cc806f1c9ba` | `emitter_address` | left-padded 20-byte `0x7be73b644df28af8148b26cf1d401cc806f1c9ba` — this vector's registered Ethereum bridge contract (matches `emitters["2"]` in the same file) |
| `[378:386)` | `0000000000000003` | `sequence` | 3 |
| `[386:387)` | `01` | `consistency_level` | 1 (Ethereum: finalized) |

### Transfer payload — bytes `[387:520)`, 133 bytes, `payload_id = 1`

| offset | bytes | field | decoded |
|---|---|---|---|
| `[387:388)` | `01` | `payload_id` | 1 (transfer) |
| `[388:420)` | `…0005f5e100` (32 bytes) | `amount` | 100000000, at 8 decimals = 1.00000000 (1 USDT locked; the token has 6 decimals, so on-chain the contract pulled `1_000_000` native units and attested `1_000_000 * 10^(8-6) = 100_000_000`, per Section 3.7) |
| `[420:452)` | `000000000000000000000000f10befe1e0794722d3baf8bfd5bdac47b2a33148` | `token_address` | left-padded 20-byte `0xf10befe1e0794722d3baf8bfd5bdac47b2a33148` (the locked ERC20 token) |
| `[452:454)` | `0002` | `token_chain` | 2 (Ethereum — equals `emitter_chain` above, as required) |
| `[454:486)` | `1111111111111111111111111111111111111111111111111111111111111111` | `to` | Rand recipient: the 32-byte recipient hash `0x11…11` (§3.7a; a test value, not the hash of any real address) |
| `[486:488)` | `0001` | `to_chain` | 1 (Rand) |
| `[488:520)` | `…00000003e8` (32 bytes) | `fee` | 1000, at 8 decimals = 0.00001000 (relayer fee; `fee <= amount` holds: 1000 <= 100000000) |

Minted to `to` on Rand: the gross `amount = 100000000` (8-decimal units, 1.00000000) as one
deposit note; the `fee` of 1000 is carried but not paid (§3.7a). (In the account era Rand credited
`amount - fee = 99999000` and paid the fee to the submitter.)

### Digest

```
mu = keccak256(keccak256(body[336:520)))
   = 000b6791765707ef31724d496b5a8029aaada97162fd018fd7f537ddfeba2c5c
```

This matches the `digest` field recorded alongside this vector in `vectors/attestations.json`.
The five signatures above are each a low-s secp256k1 ECDSA signature over this 32-byte value,
recoverable to guardians 0–4 of the launch set — enough for quorum (`5 >= q = 5`), so every
verifier accepts this attestation and (on Rand, via `BridgeAttest`) deposits a note of
`100000000` units of the asset `blake3("rand-bridge-asset" || 0x0002 || token_address)` for the
shielded address whose recipient hash is `to`.
