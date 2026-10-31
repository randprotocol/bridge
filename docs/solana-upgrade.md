# Upgrading the Solana endpoint

The program `FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu` is upgraded in place and keeps custody
through the upgrade. This file records what each change requires of the clients around it. Nothing
here has been deployed.

## Account layouts

`BridgeAccount::load` uses Borsh's `try_from_slice`, which refuses trailing bytes, so a struct that
gains a field stops loading every account already on chain. No existing struct changes in this
upgrade. `mainnet_accounts_keep_deserialising` in `state.rs` holds the bytes of the live config and
of a live message. It pins only those two: no live `TokenRegistry` or `GuardianSetAccount` bytes
have been loaded by this build, which is a check before the upgrade (below). Those structs are
unchanged in the source.

## O-1: release fits a packet at n = 10

The release account list loses the clock sysvar (the program uses the clock syscall), which takes a
seven-signature release from 1,264 to 1,231 bytes including its compute-unit limit. `Config.bump`
and one repeated search take it from 237,558 compute units to 231,428; the program must still be
given the limit, because seven recoveries alone are 175k.

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

- Load the live `TokenRegistry` and `GuardianSetAccount` bytes with this build, as
  `mainnet_accounts_keep_deserialising` does for the config and a message.
- Run a release once on the sBPF v3 binary on `solana-test-validator`. `deploy/sol.sh` ships v3,
  `solana-program-test` 2 cannot execute it, and the compute figures here are from sBPF v0.

1. **Daemons: all eight guardians and the relayer's `rand-relayer`.** A rebuilt daemon reads the
   same messages from today's program, plus one `getAccountInfo` per page; pages do not exist yet.
   Leave the relayer's `rand-bridge-cli` alone.
2. **The program upgrade**, through the upgrade authority. The live ProgramData account holds an
   ELF of at most 216,456 bytes (read 2026-10-31) and this build is 224,608 at sBPF v3, so run
   `solana program extend` first, with room to spare. `Lock` and the 13-account `Release` behave as
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
