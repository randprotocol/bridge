# Rand bridge: internal pre-deployment audit (2026-09-17)

**Scope.** The three verifiers in this repository as of 2026-09-17: the EVM contracts
(`evm/src/RandBridgeBase.sol`, `EthereumRandBridge.sol`, `BscRandBridge.sol`, `TronRandBridge.sol`,
`lib/Attestation.sol`, `lib/SafeTransfer.sol`), the Solana program
(`solana/programs/rand-bridge/src/*`), the deploy tooling (`evm/script/Deploy.s.sol`,
`tron/`, `deploy/`, `solana/cli`), and their compatibility with the Rand fullnode at `main`
`756fa80` (`bridge-codec`, `randprotocol-core::bridge`, `ledger/bridge_notes.rs`).

**Method.** Line-by-line read of every contract and program path against the design
(`docs/superpowers/specs/2026-09-10-rand-bridge-design.md`), the wire spec (`spec/ATTESTATION.md`)
and the fullnode's current bridge (`fullnode/docs/bridge.md`, `bridge/state.rs`), with the shared
vectors and the three test suites run on this machine. This is an internal review by the same
tooling that wrote the code; it is **not** an external audit, and the readiness verdict below
says so.

**Verdict.** No critical or high finding. One medium (M-1) was a real compatibility gap with the
current fullnode and is fixed in this revision. The endpoints are fit for testnet deployment;
mainnet still needs an external audit, a guardian and relayer daemon, a bridged Rand chain, and
the operational values in §5.

## 1. Test evidence

| suite | result |
|---|---|
| Foundry, `evm/` (`forge test`) | 38 passed (37 + the new `test_lock_rejects_attested_amount_above_u64`) |
| Solana, `solana/` (`cargo test --release`) | 22 unit + 2 attestation + 11 bridge = 35 passed (34 + the new `lock_refuses_an_attested_amount_above_u64`) |
| `rand-bridge-cli` unit tests | 5 passed |
| `tools/vectors -- --check` against fullnode `756fa80` | OK: both copies match the generator, 39 vectors |
| TronBox compile of the mirrored sources (Tron solc 0.8.20, Paris) | 7 artifacts, no warnings |
| `deploy/evm.sh anvil` rehearsal | deployed, `chainId() == 2`, admin set, record written |

## 2. Findings

Severity: **H** funds at risk from an unprivileged party; **M** funds stuck or a privileged-party
hazard; **L** defence in depth or an operational trap; **I** informational.

### M-1 (fixed): a lock could custody an amount Rand can never mint

*Where.* `RandBridgeBase.lock`, `processor.rs::process_lock`.

Since fullnode phase S3 a bridged holding on Rand is a note whose amount is a `u64`, and
`BridgeState::check_attest` refuses any attested amount above `u64::MAX` as `AmountTooLarge`. The
endpoints normalise to 8 decimals and carried `uint256`/`u128` attested amounts with no upper
bound, so a lock of more than about 1.8 x 10^11 whole tokens would have been pulled into custody,
published, and then be unmintable on Rand forever: no attestation could ever be accepted, and
without a Rand burn no release could ever return it. The bound is far above any real supply, but
the invariant "every custodied unit is covered by an attestation Rand can honour" was violated in
principle.

*Fix.* Both locks now refuse `attested > u64::MAX` before pulling anything (`AmountTooLarge` on
the EVM, the existing `AmountOverflow` on Solana), with a test on each side at the exact boundary.
`MAX_ATTESTED_AMOUNT` is a named constant in both.

### L-1: tokens sent directly to an endpoint are unrecoverable

*Where.* `RandBridgeBase`, the Solana custody accounts.

`custody[token]` counts only what `lock` pulled; a plain ERC20/SPL transfer to the contract or
custody account raises the real balance but not the counter, and there is no rescue function. This
is the intended custody-soundness design (nothing lets an admin move tokens), so the cost is only
that mistaken direct transfers are lost. Recommendation: say so in the user-facing documentation;
do not add a sweep function, which would be a privileged withdrawal path.

### L-2: the admin can freeze releases indefinitely

*Where.* `setToken(token, false, ...)`, `SetToken { enabled: false }`, `pause`.

A disabled token or a paused endpoint blocks releases until the admin re-enables; a Rand burn in
flight then waits, its digest unconsumed (the dust and disabled-token paths deliberately leave the
attestation re-submittable). That is the intended admin power, but it means the admin key is a
liveness root as well as a configuration root. Recommendation: the admin is a multisig with a
public runbook; consider a timelock on `setToken` after launch.

### L-3: Solana `Release` needs the recipient's associated token account to exist

*Where.* `process_release`, account 7.

The program transfers into the recipient's ATA and does not create it; a release to a wallet with
no ATA for the mint fails in the SPL CPI, after the consumed marker is written but inside the same
transaction, so the whole transaction reverts and nothing is consumed. The relayer must prepend an
idempotent create-ATA instruction. Recommendation: document this in the relayer's runbook (the
guardian/relayer daemon is not built yet).

### L-4: `Initialize` must follow `solana program deploy` closely

*Where.* `process_initialize`, `check_upgrade_authority`.

Between deploy and `Initialize` the program exists with no config; only the upgrade authority can
initialise it, so nobody can front-run the deployer, but a program whose upgrade authority is
removed before `Initialize` can never be initialised. `deploy/sol.sh` runs the two back to back with
the same key and prints the `set-upgrade-authority` command as the next step, which is the right
order.

### L-5: relayer fee semantics differ by direction

*Where.* `lock(…, relayerFee, …)`, `Transfer.fee`.

On the way to Rand the payload's `fee` is carried but paid to nobody: Rand mints the gross amount
(fullnode `docs/bridge.md` §5). On the way back it is paid to whoever submits the release. A front
end that quotes a relayer fee on `lock` would be promising something nobody collects. Documented
on `lock` and in `docs/architecture.md` §4.1; recommendation: pass 0 until the pool can pay a
submitter.

### I-1: verification order is not identical across verifiers, by design

Only accept/reject is normative. The EVM and Solana endpoints recover signatures before checking
replay and payload rules (the submitter pays), Rand runs every cheap check first (its
attestation-specific surcharge is zero; the fee floor is `BUNDLE_BASE`, fullnode `gas.rs`).
The shared vectors pin the accept/reject decision on all three, not the first error.

### I-2: reentrancy through a lock hook is harmless

An ERC777-style sender hook could re-enter `lock` during `_pull`; the inner call would succeed and
the outer balance-delta check would then see two deposits and revert `TransferAmountMismatch`,
undoing both. Only USDT and USDC are whitelisted, neither of which has hooks.

### I-3: Tron-specific opcodes

`ecrecover`, `staticcall`, `EXTCODESIZE` (`token.code.length`) and `block.timestamp` in seconds are
all available on the TVM; `PUSH0` is avoided by compiling for Paris. TronBox compiled the sources
with Tron's own solc 0.8.20 on this machine. `block.chainid` is not relied on (the fork guard is a
no-op on Tron by design).

### I-4: guardian set bounds

`n_sigs` and each `index` are one byte, so a set holds at most 255 keys; `_checkKeys` is O(n²)
over that, which is fine at 255 and irrelevant at 6.

## 3. Rulings re-verified against the fullnode

Each of these is enforced identically in `Attestation.sol` / `RandBridgeBase`, the Solana program,
and `randprotocol-core::bridge` (fullnode `756fa80`), and pinned by the shared vectors:

- `mu = keccak256(keccak256(body))`; low-s only; recovery id 0 or 1; quorum `n*2/3 + 1`; indices
  strictly increasing and in range.
- A rotation is signed by the *current* set; the grace window (86,400 s) covers transfers only;
  `new_index == current + 1`; keys unique and non-zero.
- Emitter binding on `(emitter_chain, emitter_address)`; governance emitter
  `keccak256("rand-bridge-governance")` is the pinned literal on all three.
- `fee <= amount`; zero amounts refused; EVM addresses left-padded and the upper 12 bytes checked.
- Effects before interactions on every release.
- **New:** an attested amount fits a `u64` (M-1).

What changed on the fullnode and did **not** affect the endpoints: the SHRUGG to RAND rename
(hash domains `rand-bridge-asset`, `rand-bridge-state`, `rand-asset-registry`; RPC prefix
`rand_`), the note-based bridged holdings, the recipient hash in `to`, the asset registry index,
and the two-bundle burn. The wire format and `bridge-codec` are byte-for-byte unchanged and the
39 vectors regenerate identically.

## 4. Deploy tooling review

- `Deploy.s.sol` signs with `DEPLOYER_PRIVATE_KEY` from the environment when set; the wrapper never
  passes a key as an argument. Chain id is checked twice (by the wrapper with `cast chain-id`, by
  the script against `EXPECTED_CHAIN_ID`), because `DEPLOY_CHAIN_ID` is immutable and a wrong
  network would yield a bridge that can never move value.
- A mainnet EVM deployment without `PAUSER` is refused by the wrapper; the Tron migration already
  required it.
- `deploy/.env` is git-ignored and its mode is checked; `deploy/keys/` (Solana program keypairs)
  and `*.keypair.json` are git-ignored.
- `sol.sh` rewrites `declare_id!` to the program keypair before building, since every PDA derives
  from the program id; the change to `lib.rs` must be committed with the deployment record.

## 5. Before mainnet (unchanged from the 2026-09-13 readiness note, plus this review)

1. External audit of the three verifiers.
2. Guardian and relayer daemons (none exist; nothing moves a token end to end).
3. A Rand chain cut with a `bridge` section naming the six guardians and the four emitters
   (chain 10 has none, and a bridge cannot be added to a running chain).
4. Operational values: six guardian keys on distinct operators, admin multisig, pauser, per-token
   caps, whether Tron USDC is enabled at all, and the relayer-fee policy (L-5).
5. Testnet round trip on each chain (Sepolia, BSC testnet, Nile, devnet) through the deploy
   scripts, then one lock-mint-burn-release cycle once a daemon exists.
