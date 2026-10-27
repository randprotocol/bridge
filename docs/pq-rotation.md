# Rotating the post-quantum guardian set and the pause key on Rand

`rand-bridge-gov` rotates the two Rand-only key sets of the bridge (BRG-14): the PQ guardian set
(the Dilithium2 keys whose quorum co-signs every mint) and the pause key. The ECDSA guardian set
is rotated with `rand-bridge-gov rotate` (README, "Governance"); this page is about the other two.

The messages are the fullnode's (`crates/randprotocol-core/src/bridge/gov.rs`, its
`docs/bridge.md` §21), and on chain 20 onward they are genesis-bound (`…-2` tags, the genesis hash
after the tag), so a quorum signed for one chain is valid on no other:

```
M_rotate_pq    = "rand-bridge-pq-rotate-pq-2"    ‖ genesis[32] ‖ chain_id u64 ‖ rotation_nonce u64 ‖ count u32 ‖ key[1312] …
M_rotate_pause = "rand-bridge-pq-rotate-pause-2" ‖ genesis[32] ‖ chain_id u64 ‖ rotation_nonce u64 ‖ key[1312]
M_cancel       = "rand-bridge-cancel-rotation-2" ‖ genesis[32] ‖ chain_id u64 ‖ rotation_nonce u64 ‖ kind u8
```

A rotation is signed by a PQ quorum (`n * 2 / 3 + 1`) of the **current** PQ set at the bridge's
current `rotation_nonce`. On a chain with `bridge.rotation.needs_possession` each **new** key also
signs the same message (proof of possession), and with `bridge.rotation.delay_secs` the rotation
is pending for that long, during which the current pause key can cancel it.

## Before you start

- Read the chain's state: `rand_getBridgeState` gives `rotation_nonce`, `pq_guardians`,
  `pause_key`, `rotation_rules` and any `pending_rotations`. Save `pq_guardians` as
  `current.json` (`{"pq_guardians": [...]}`).
- Each new key holder generates their seed on their own machine and hands over only the public
  key (`rand-bridge-gov pq-public-key --seed-env <VAR>`). Collect them, in the order of the
  current ECDSA guardian set, as `new.json`. A new set has as many keys as the ECDSA set, no
  repeats, and not the pause key.
- Everyone signing compares the printed `message` hex before signing.

## Sign (on each signer's machine)

```sh
rand-bridge-gov pq-rotate-pq --rand-chain-id 21 --rand-rpc http://127.0.0.1:8545 \
    --nonce <rotation_nonce> --pq-guardians-file current.json --new-pq-guardians-file new.json \
    --seed-envs GUARDIAN1_PQ_SEED --out quorum.txt                      # a current guardian
rand-bridge-gov pq-rotate-pq … --possession-seed-envs NEW1_PQ_SEED --possession-out possession.txt   # a new key holder
```

`--rand-rpc` checks that the node serves chain 21, reads its genesis hash, and checks `--nonce`
and `current.json` against the node. Pin the genesis too (`--genesis ca76c276…ca9a` for chain 21):
with both, the node's hash must equal the pinned one, so a node on another chain cannot pick the
message's binding. `--genesis` alone signs offline.
Each run appends `index:signature` lines; concatenate the files from every machine. For the pause
key use `pq-rotate-pause … --new-pause-key <hex or @file>` the same way.

## Submit

```sh
rand-bridge-gov pq-rotate-submit --kind pq --rand-rpc http://127.0.0.1:8545 \
    --new-pq-guardians-file new.json --quorum quorum.txt --possession possession.txt \
    --rand-node /usr/local/bin/rand-node            # add --dry-run to check only
```

It re-reads the chain, rebuilds the message, keeps exactly a quorum (lowest indices first) and
checks it under the ledger's rules, checks every possession line, and only then runs
`rand-node bridge-gov rotate-pq|rotate-pause submit`, which encodes and sends the action. Afterwards
`rand_getBridgeState` shows the rotation under `pending_rotations` (with a delay) or in
`pq_guardians` / `pause_key`, and `rotation_nonce` has moved on: the lines signed for the old
nonce are spent.

## Cancel a pending rotation

Only the current pause key can, before `effective_at_secs`:

```sh
rand-bridge-gov pq-cancel-rotation --rand-chain-id 21 --rand-rpc http://127.0.0.1:8545 \
    --nonce <rotation_nonce> --kind pq --seed-env RAND_BRIDGE_PAUSE_KEY_SEED --out cancel.txt
rand-node bridge-gov cancel-rotation submit --kind pq --signature @cancel.txt --rpc http://127.0.0.1:8545
```

## Afterwards

- Each guardian whose PQ key changed sets its new seed (`pq_seed_env`) and restarts
  `rand-guardian`; until then its co-signatures do not count under the new set.
- Re-make any kept-ready pause signature after a pause-key rotation (`rand-bridge-gov pause`):
  the old key's signature no longer pauses.
- Destroy the old seeds once the new set is in effect.
