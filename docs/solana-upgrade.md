# Upgrading the Solana endpoint

The program `FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu` is upgraded in place and keeps custody
through the upgrade. This file records what each change requires of the clients around it. Nothing
here has been deployed.

## Account layouts

`BridgeAccount::load` uses Borsh's `try_from_slice`, which refuses trailing bytes, so a struct that
gains a field stops loading every account already on chain. No existing struct changes in this
upgrade. `mainnet_accounts_keep_deserialising` in `state.rs` loads the bytes read from mainnet on
2026-10-31 of the config, the message at sequence 6, both token registries and both guardian sets,
and writes the config, the USDT registry and both sets back byte for byte. Only `Consumed` is not pinned: a 32-byte digest
that the program checks for existence and never loads.

## O-1: release fits a packet at n = 10

The release account list loses the clock sysvar (the program uses the clock syscall), which takes a
seven-signature release from 1,264 to 1,231 bytes including its compute-unit limit. `Config.bump`
and one repeated search take it from 237,558 compute units to between 220,928 and 232,928; the
program must still be given the limit, because seven recoveries alone are 175k. These are sBPF v0
figures from random test keys, where each extra step of a bump search costs 1,500: 237,558 is one
run of the old code, 226,929 and 229,928 to 232,928 are runs here, and 220,928 is the final
review's run.

| | old program | new program |
|---|---|---|
| old client (13 accounts) | works | works, the extra account is ignored |
| new client (12 accounts) | fails `NotEnoughAccountKeys` | works |

So the relayer's `rand-bridge-cli` moves after the program does. A release attempted in the wrong
order fails before any effect and can be resubmitted.

## O-2 and O-3

Neither touches an account or an old instruction. `SetPauser` is new, and `MAX_GUARDIANS` only
refuses a future set; the live set 1 has eight keys. `rand-bridge-gov` and `deploy/lib.sh` hold the
same 10, so use the rebuilt tool for any rotation: the EVM endpoints accept 255 and take the
attestation first, and a set Solana refuses stops Solana's releases until a program upgrade. The
difference from EVM is a knowing exception to the parity rule, pending the owner's decision
(`docs/architecture.md` §12). `rand-bridge-cli set-pauser` works from the
moment the program is upgraded.

## O-4: locks keyed by (owner, nonce)

### The constraint

A Solana transaction names every account it writes. Any account whose address depends on the
sequence therefore repeats the griefing, because a client has to guess the sequence before its
transaction lands. So moving the message to `(owner, nonce)` is not enough: guardians walk
sequences and can no longer derive a message's address, and the index that tells them cannot be
sequence-keyed either.

### What was built

- `LockKeyed` (tag 12) writes the same `PostedMessage` to `["keyed-msg", owner, nonce u32 LE]` and
  assigns the sequence inside the instruction.
- It records that address in a **message page** `["msg-page", sequence / 64, u64 LE]`, slot
  `sequence % 64`: discriminator 6, page number, 64 addresses, 2,057 bytes. The page is created by
  its first keyed lock, at about 0.0152 SOL.
- `Lock` and `["msg", sequence]` stay exactly as they are, and a `Lock` leaves its slot zero.
- The guardian source, for each sequence below `Config::sequence`, reads the page; a slot names the
  message, and a zero slot means `["msg", sequence]`. It treats a page the program does not own as
  no page, since anyone can send lamports to the address. It reads the page first because a lamport
  sent to an unused `["msg", sequence]` would otherwise look like an account the program does not
  own, which the source rejects.
- Nothing is found and the cursor stays put if neither address has the message. It never passes a
  sequence it has not read, so a failure here is a stall and never a missed message. A node that
  serves a stale page beside a lamport-funded `["msg", sequence]` makes that poll an error, which
  the daemon retries.

Every sequence below `Config::sequence` is behind one of the two, because each instruction assigns
the sequence, writes the message and writes the slot in one transaction. Old messages stay where
they are: there is nothing to migrate, and `PostedMessage` is unchanged.

### Why this design

| option | why not |
|---|---|
| `["seq", sequence]` stub or any other per-sequence account | the griefing again, as above |
| `getProgramAccounts` with a `memcmp` on the sequence | no new account, and it answered on `api.mainnet-beta.solana.com` on 2026-10-31. But it is a scan per sequence on an endpoint where such calls are rate limited, and any provider may disable it; every guardian uses that one endpoint, so a refusal stalls them all. `getAccountInfo` is already what they depend on |
| transaction or log scanning | needs history retention and parsing, which on-chain `PostedMessage` exists to avoid |
| one head account plus a `prev` link in each message | no page boundary, but the walk runs backwards from the head and costs one read per message of lag, on every restart |
| ring buffer | a burst of dust locks would overwrite slots guardians have not read |

Sixty-four slots: a griefer can now fail a lock only at a page boundary, one failure per boundary,
so each costs 64 dust locks (about 0.145 SOL, against 0.0023 SOL per failure before) and yields one
retry, while a page stays small enough that the unlucky first locker pays
about 0.015 SOL. `MESSAGE_PAGE_SLOTS` is on-chain format and cannot change for existing pages.

### Upgrade order

No flag day: each step leaves the bridge working if the next never happens.

Before step 1, none of which has been done:

- Fix the binary. Build it once with cargo-build-sbf 4.1.0, the toolchain these figures came from,
  and record its SHA-256. Everything below refers to that file as `$SO`.
- Run `sbf_compute` (`solana/README.md`) on the default-architecture build of the same commit, and
  refresh the live bytes in `mainnet_accounts_keep_deserialising`. **`sbf_compute` cannot run on
  the binary that ships:** given a `--arch v3` file, `solana-program-test` 2 fails every test with
  `UnsupportedProgramId`. So it proves sizes and v0 compute, not `$SO`.
- Run a release once with `$SO` on `solana-test-validator`, sized at `n = 10`. This is the only
  execution of the shipping binary, and it is the check of v3 compute. `deploy/sol.sh` ships v3, so
  it has not been done yet, and until it is, a v3 release's compute is unmeasured.

1. **Daemons: all eight guardians and the relayer's `rand-relayer`.** A rebuilt daemon reads the
   same messages from today's program, plus one `getAccountInfo` per page; pages do not exist yet.
   Leave the relayer's `rand-bridge-cli` alone.
2. **The program upgrade**, by the procedure below. `Lock` and the 13-account `Release` behave as
   before, and no account layout changes. From here `LockKeyed` is open to anyone, which
   is why step 1 comes first: a guardian still on the old daemon stops at a keyed message's
   sequence until it is rolled. It does not skip it, and nothing is lost, but with fewer than a
   quorum rolled that lock and everything after it wait.
3. **The relayer's `rand-bridge-cli`**, for the 12-account `Release` (O-1). Before step 2 that
   client's releases fail, harmlessly.
4. **Lock clients**: `rand-bridge-cli lock-keyed`, then `lockInstruction` in randbridge.org's
   `web/lib/chains/solana-ix.ts`. The griefing stops for a client when it moves. It has to pick a
   nonce it has not used and pass the page.

Rollback of step 2 to the old program leaves pages and keyed messages readable, so the daemons
carry on; `LockKeyed` is refused and clients fall back to `Lock`.

`Lock` can be removed by a later upgrade once no client uses it. Nothing depends on that.

### Step 2 in commands

Checked against the `--help` of solana-cli 4.2.2. None of this has been run.

```sh
export P=FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu
export RPC=https://api.mainnet-beta.solana.com
export SO=rand_bridge.so          # the file fixed above
export AUTH=<upgrade authority keypair>   # DvV45t4m…77kX on 2026-10-31; re-read it

# Keep what is running, before anything changes it, and put it in a buffer now,
# so a rollback does not start with an upload.
solana program dump -u $RPC $P pre-upgrade.so
solana program write-buffer pre-upgrade.so -u $RPC -k $AUTH --buffer-authority $AUTH
export ROLLBACK=<the buffer it printed>

# Room. Bytes = size of $SO - the "Data Length" of `solana program show $P`.
solana program show -u $RPC $P
solana program extend -u $RPC -k $AUTH $P $(( $(wc -c < $SO) - <Data Length> ))

# The new program, in a buffer, checked before it goes live.
solana program write-buffer $SO -u $RPC -k $AUTH --buffer-authority $AUTH
export BUFFER=<the buffer it printed>
solana program dump -u $RPC $BUFFER buffer.so && shasum -a 256 buffer.so $SO

# The upgrade.
solana program deploy -u $RPC -k $AUTH --program-id $P --buffer $BUFFER \
  --upgrade-authority $AUTH --no-auto-extend

# What is on chain now. The account is padded, so compare the length of $SO, and
# the rest must be zeroes (the second command prints 0).
solana program dump -u $RPC $P live.so
head -c $(wc -c < $SO) live.so | shasum -a 256; shasum -a 256 $SO
tail -c +$(( $(wc -c < $SO) + 1 )) live.so | tr -d '\0' | wc -c
solana program show -u $RPC $P
```

| `$SO` | size | extend by |
|---|---|---|
| `--arch v3`, what `deploy/sol.sh` builds | 224,608 | **8,152** |
| default architecture | 239,696 | 23,240 |

Those are this commit's sizes against the 216,456 read on 2026-10-31. A rebuild can change the
size, so recompute from the formula. The rent is 6,960 lamports a byte, about 0.057 SOL for 8,152.
`--no-auto-extend` is deliberate: `deploy` would otherwise extend on its own, and a size that does
not match this table should stop the procedure. `solana program show` must still name the same
authority afterwards, and `rand-bridge-cli show` must print the same config.

`write-buffer` checks a program against the cluster's active features. Which architecture the live
ELF is has not been checked. If mainnet refuses v3, use the default architecture, and re-fix `$SO`.

**Rollback**, any time after the upgrade:

```sh
solana program deploy -u $RPC -k $AUTH --program-id $P --buffer $ROLLBACK \
  --upgrade-authority $AUTH --no-auto-extend
```

Then run the hash check against `pre-upgrade.so`. This is the old program in every way: `SetPauser`,
`LockKeyed` and `MAX_GUARDIANS` are gone, and the 12-account `Release` fails, so a relayer already on
step 3 has to go back too. If the buffer is gone, `write-buffer pre-upgrade.so` again.

**If the Squads handover in `docs/governance.md` §4 has run,** the upgrade authority is the vault, no
keypair can sign, and `deploy` above cannot be used. That handover is irreversible. Instead:

- `extend` takes `--payer` and its help lists no authority, so run it as above. If the cluster
  refuses it for want of the authority, it goes through the vault like the upgrade.
- After each `write-buffer`, hand the buffer over, with
  `solana program set-buffer-authority $BUFFER --new-buffer-authority <vault>`. The upgrade requires
  the buffer's authority to be the program's. Check the hash after this, not before.
- The upgrade is a vault transaction: the loader's `Upgrade` of `$BUFFER` for `$P`, signed by the
  vault. `rand-bridge-cli --as` does not build it. `solana program upgrade $BUFFER $P --sign-only
  --dump-transaction-message --upgrade-authority <vault>` prints a message to work from; check it
  in Squads, which has not been tried. It runs after the 48 h time lock.
- **So is the rollback.** Queue it through the same 48 h, which means the pauser, not a rollback, is
  the immediate answer to a bad upgrade. Under this path step 1 must be finished before the proposal
  executes, not before it is proposed.
