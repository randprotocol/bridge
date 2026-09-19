# Notes on "The proposed bridging architecture" (internal design review, 18 September 2026)

Reviewed 2026-09-19 against the bridge as it stands that day. The review itself (a nine-slide
summary for A. Mohammed and D. Suhubdy; its VARA section excluded) is not in this repository;
these notes record what it says, where the bridge already differs from the picture it drew one day
earlier, and the work that follows. cc @zeroknowledge.

## 1. What the review says

It evaluates an outside **proposal** — Wormhole NTT in hub-and-spoke mode (Ethereum hub, Solana
spoke, Wormhole's 19 guardians at quorum 13) with a Boundless / RISC Zero **Groth16** proof of
Ethereum finality as a second verifier, "2-of-2" on the Rand mint — and reaches three verdicts:

1. **It recommends what Rand already built.** A Wormhole-format guardian bridge with source-chain
   custody, caps and a pauser exists here: four chains, five verifiers, 39 shared vectors. The
   proposal would replace it with a third-party dependency covering two chains, leaves the
   Rand → source release path undescribed, and derives the mint commitment over `H(address)`,
   which would make the note unspendable (the ledger must derive it from the recipient's `pk`).
2. **The 2-of-2 overlay buys no post-quantum security.** Groth16 over BN254 falls to the same Shor
   adversary as the guardians' ECDSA keys, the finality it proves rests on BLS signatures, and it
   would put pairings, a trusted setup and a pinned third-party guest image into Rand's consensus,
   with liveness tied to a prover market and Solana, BSC and Tron left at one leg.
3. **A better second leg exists, and S3 fits the bridge.** Have the same guardians **co-sign with
   Dilithium2**, which Rand already verifies natively: a post-quantum mint authorisation with no
   new primitive (~12 KB per deposit, carried beside the attestation). The release path stays
   classical, bounded by custody and caps. The S3 short address's 32-byte receiver id *is* the
   bridge's `to` / `recipient_hash`, now with a checksum.

Its options table: **A** the bridge as built (baseline) · **B** the proposal (reject) · **C** the
bridge + a verifier threshold + the Dilithium co-signature + Rand-side limits + the S3 id
(**recommended**) · **D** C plus Wormhole's guardians as a third verifier (opportunistic) · **E** a
source-chain consensus proof as a verifier, only as a hash-based STARK (defer) · **F** prove Rand's
finality to Ethereum, removing guardians from the release (study; needs validator accountability).

What it says no proposal addresses, and which decides whether a bridged chain is safe to cut:

| id | sev | finding |
|---|---|---|
| BRG-1 | high | No caps or pause on the **Rand** side: a forged or mistaken attestation mints without bound. Every source-chain mitigation is downstream of this. |
| BRG-7 | medium | No forward bound on block timestamps: a leader can expire a guardian set's grace window early (fullnode issue #2). |
| BRG-11 | medium | A deposit's commitment can be front-run (grief only; fullnode issue #3); relayers need automatic re-seal. |
| BR-2, BR-3 | high | The release **destination is unbound**; one key owns the Solana verifier. |
| — | high | No guardian or relayer daemon exists; the external audit is the mainnet gate. |
| OPS-1, STAKE-1 | critical | The chain underneath: releases are attested from Rand's finality, so committed validator seeds and no slashing undermine any bridge. |

Its order of work: (1) Rand-side inbound limits, mint caps, pause · (2) the forward timestamp bound ·
(3) Dilithium2 co-signature, dual quorum on every mint · (4) a verifier set with a per-route
threshold in genesis · (5) S3 Phase B at or before the bridged cut, plus a deposit wallet ·
(6) guardian and relayer daemons with automatic re-seal · (7) four-chain testnet round trips and the
external audit · (8) CS7: bind the release destination; shielded mint. Open decisions B1–B5: own
bridge or Wormhole's; no pairings in consensus; which Dilithium; deposit linkability; one cut for
S3 and the bridge.

## 2. Where the bridge is on 2026-09-19, against that picture

The review's "Rand today" column was accurate on the 18th. One day later:

| review's line | now |
|---|---|
| "Built, tested, **undeployed**" | **Deployed to mainnet** on all four chains (`docs/mainnet-deployment.md`). No token is whitelisted, so nothing can be locked. Decision **B1 is taken in practice: Rand's own bridge.** |
| "No guardian or relayer daemon exists" | **Built** (`daemons/`): signing and assembly reproduce the shared vectors byte for byte; a lock and a release run against the real `EthereumRandBridge` on anvil; guardian 1 has polled mainnet BSC and Tron. Tron / Solana / Rand *submission* paths are still unexercised. Automatic re-seal (BRG-11): **not yet** — see W2. |
| BR-2 "destination unbound" | Rediscovered independently today as a launch blocker (`docs/audit/2026-09-19-reaudit.md` §5): a Rand transaction is unsigned and a bundle proof does not commit to its action, so a copied `BridgeBurn` with a rewritten `to` is valid. The fullnode session is fixing it **without a guest change**: every bundle proof is bound to `H("rand-tx-bind-1", chain_id ‖ bundle ‖ action)` through the proof's public-input segment (branch `feat/rpl`). That is the review's step 8 moved to the front. **No `setToken` until it lands.** |
| BR-3 "one key owns the Solana verifier" | **Still true, and now live:** the mainnet program's upgrade authority is the deployer hot key. Runbook step open (`docs/mainnet-launch.md`). |
| OPS-1 committed validator seeds | The fullnode session has made fresh, never-committed validator and payout keys a precondition of the chain-14 cut. STAKE-1 (slashing): not addressed. |
| BRG-1, BRG-7 | **Open** (fullnode). `feat/rpl` adds per-backing `locked` counters and `InsufficientBacking` on burns, which bounds what can be *redeemed* per coin, but nothing caps or pauses a *mint*. |
| Dilithium co-signature, verifier threshold (steps 3–4) | **Not started** anywhere. |
| S3 receiver id as recipient (step 5) | **Regressed:** chain 11's `ReceiverId` form was reverted at fullnode `17db41d` (chain 12); `to` is again the hash of the full shielded address, with no checksum, and there is no on-chain registry. The relayer therefore keeps an off-chain `recipient_hash → rand1…` table (`POST /v1/recipients`). |
| "zUSDC is a wrapped claim" | The Rand side is becoming **one pooled token, zUSD**, with seven backings (USDT + USDC on Ethereum, BSC, Solana; USDT on Tron) — a user decision of 2026-09-19, after the review. |
| Step 7, testnet round trips before mainnet | **Skipped**: mainnet was deployed directly. The Tron endpoint has still never released on a real TVM. |

Things the review does not know about, because they are newer: the Tron-USDT `transfer`-returns-false
bug (fixed before deployment), the network-separation rule for guardian keys, the fees (deposits
free; 10 bps of the token on release; 0.01 RAND on the burn), `rand-bridge-audit`, and the fact that
**all six mainnet guardian keys currently sit on one machine** — which makes the review's "key
compromise is total on mint" (option A's cost) a description of today, not of a threat model.

## 3. What option C means for endpoints that are already deployed

**Nothing in option C touches a source-chain endpoint.** The Dilithium quorum, the verifier
threshold, the inbound limits, the timestamp bound, the S3 id (still 32 bytes in `to`; the contracts
only refuse zero) and the destination binding are all verified on Rand. The deployed contracts, the
wire format and the 39 vectors stay as they are. Only option F would need new endpoints.

The constraint runs the other way: **these are consensus rules, and a `bridge` section cannot be
changed on a running chain.** Whatever of steps 1–4 is not in the chain-14 genesis waits for another
chain cut — and once custody exists, a re-cut must carry the consumed-attestation set
(`bridge_spent`), the burn sequence and the per-backing `locked` counters across, or every historical
lock attestation can be minted a second time on the new chain. So the question for each step is
"chain 14, or a migration later", not "now or next sprint".

## 4. Design and plan

Two owners: **R** = the fullnode (session `fullnode-fc`, branch `feat/rpl`), **B** = this repository.

### Before any token is whitelisted (gates)

| # | work | owner | notes |
|---|---|---|---|
| G1 | Transaction binding (BR-2) | R | in review on `feat/rpl`; must include the "redirected `BridgeBurn` copy is refused" case |
| G2 | Rand-side inbound limits (BRG-1): per-backing mint cap per window, a pause flag settable by a guardian-signed or validator-governed message, refusal when `locked` would exceed a configured ceiling | R | the ceiling can mirror the endpoint caps the admin sets, so a forged mint is bounded by the same number on both sides |
| G3 | Forward timestamp bound (BRG-7) | R | fullnode #2 |
| G4 | Fresh validator and payout keys for the cut (OPS-1) | R | already a stated precondition |
| G5 | Solana upgrade authority → multisig (BR-3); admin → multisig | B (ops) | one command each; needs the user's multisig addresses |
| G6 | Guardian keys onto separate operators | B | needs W5 (rotation tool); until then the quorum is one laptop |

### W1 — Dilithium2 co-signature (review step 3)

- **Rand (R):** genesis `bridge.pq_guardians` (one Dilithium2 public key per guardian, same index
  order); `BridgeAttest` gains `pq_signatures: Vec<(index, sig)>`; the ledger requires the ECDSA
  quorum **and** a Dilithium quorum over the same `mu`, from the same indices or any quorum (decide);
  size cap raised by ~12 KB. Decision B3: the node already links `crystals-dilithium` 2.0 — use that
  exact parameter set rather than introduce ML-DSA-44 beside it.
- **Guardian daemon (B):** a second key (`GUARDIAN_PQ_KEY`, environment only), sign
  `"rand-bridge-pq-1" ‖ mu`, persist with the ECDSA signature, serve both from
  `GET /v1/signature/{chain}/{sequence}`; only for messages addressed to Rand (`to_chain = 1`) —
  releases stay classical.
- **Relayer (B):** collect both quorums, verify each Dilithium signature against the set read from
  `rand_getBridgeState`, hand them to `rand bridge-mint` (a file argument beside the attestation).
- **Vectors (B):** a PQ section in `tools/vectors` with fixed test keys, consumed by the fullnode and
  the daemons; the 39 existing vectors do not change.
- **Rotation:** a guardian-set rotation must carry the new set's PQ keys to Rand. The endpoints'
  payload 2 has no room for them, so Rand takes them from a Rand-only companion (the deferred payload
  id 3), or PQ keys rotate by chain governance. Decide with W5.

### W2 — Relayer re-seal (BRG-11), W3 — recipients

- **W2 (B):** detect `CommitmentExists` from `rand bridge-mint`, re-run (the wallet draws a fresh
  `r`), bounded retries with backoff, metric for repeated griefing. Today a failed mint is simply
  retried on the next poll; make it explicit and tested.
- **W3 (R then B):** if S3 Phase B returns (on-chain receiver registry, Bech32m short address), the
  relayer resolves `to → (pk, kem_ek)` from the chain and the off-chain table becomes a fallback; the
  front end must check the address's hrp and checksum before a lock (closes "the Rand recipient has
  no checksum"). Decision B4 (deposits linkable to a published handle) is the user's; the mitigation
  the review names is a separate deposit wallet that sweeps.

### W4 — Verifier set with a per-route threshold (review step 4)

Rand-side only (R): genesis lists verifiers per route — T1 Rand's guardians (ECDSA + Dilithium),
later T2 Wormhole's guardians, T3 a hash-based consensus proof — with a threshold per source chain.
The bridge side needs nothing until a second verifier exists; then the relayer carries each
verifier's evidence. Build the genesis shape now only if it is free; otherwise it is a later cut
with the migration in §3.

### W5 — Guardian-set rotation tool (already scheduled for after `feat/rpl` lands)

A deliberate CLI, not a daemon: build the `GuardianSetUpgrade` body, have five of the current six
sign, assemble, check under the verifiers' rules, print the submission for the three EVM-family
endpoints, Solana, and Rand (a `BridgeAttest` carrying payload 2, so all five chains stay on one
index). This is what turns "six keys on one laptop" into operator-held keys.

### W6 — The round trips that were skipped (review step 7)

The testnet configuration exists (`deploy/.env`, six testnet-only guardians). With mainnet idle
until chain 14, run Sepolia, BSC testnet, Nile and devnet end to end with the daemons: it is the
first real-TVM release (Tron-USDT fix, `ecrecover` address form), the first Solana release through
`rand-bridge-cli release`, and the first Tron submission from the relayer. Needs faucet funds only.

### W7 — External audit (bridge #4) and STAKE-1

Unchanged: the audit is still the gate for real caps, and option F stays a study until validators
are accountable.

### Order

```
now            G1 (in review) · W6 testnet round trips · W2 · G5 (needs multisig addresses)
chain-14 cut   G2 G3 G4 in genesis/consensus · decide W1 + W4: in this cut, or a migration later
after it lands W5 rotation → G6 operator-held keys · W1 daemons + vectors (if in the cut) · whitelist
               with small caps · one round trip per chain · rand-bridge-audit · raise caps after W7
```

### Decisions needed from the owners

- **W1/W4 in chain 14 or later?** Later means a second cut with a custody-carrying migration (§3).
- **B3** which Dilithium (recommendation: what the node already verifies, `crystals-dilithium` 2.0).
- **B4** accept deposit linkability with a sweep wallet, or wait for a blinded recipient (CS7).
- **B5** S3 Phase B in the same cut as the bridge, given it was reverted once at chain 12.
- G2's shape: who may pause the Rand side — a guardian quorum, the validators, or both.
