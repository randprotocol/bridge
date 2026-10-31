# Upgrading the Solana endpoint

The program `FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu` is upgraded in place and keeps custody
through the upgrade. This file records what each change requires of the clients around it. Nothing
here has been deployed.

## Account layouts

`BridgeAccount::load` uses Borsh's `try_from_slice`, which refuses trailing bytes, so a struct that
gains a field stops loading every account already on chain. No existing struct changes in this
upgrade. `mainnet_accounts_keep_deserialising` in `state.rs` holds the bytes of the live config and
of a live message.

## O-1: release fits a packet at n = 10

The release account list loses the clock sysvar (the program uses the clock syscall), which takes a
seven-signature release from 1,264 to 1,231 bytes including its compute-unit limit.

| | old program | new program |
|---|---|---|
| old client (13 accounts) | works | works, the extra account is ignored |
| new client (12 accounts) | fails `NotEnoughAccountKeys` | works |

So the relayer's `rand-bridge-cli` moves after the program does. A release attempted in the wrong
order fails before any effect and can be resubmitted.

## O-2 and O-3

Neither touches an account or an old instruction. `SetPauser` is new, and `MAX_GUARDIANS` only
refuses a future set; the live set 1 has eight keys. `rand-bridge-cli set-pauser` works from the
moment the program is upgraded.
