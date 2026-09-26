# Mainnet deployment — addresses and transaction hashes (2026-09-19)

All four endpoints carry the same configuration: guardian set 0 (six keys, quorum 5), admin,
`RAND_EMITTER = keccak256("rand-bridge-mainnet-burn-emitter")`, protocol fee 10 bps. **No token is
whitelisted yet**, so nothing can be locked. Each was read back on-chain after deployment.

| chain | contract | address | deployment transaction | block |
|---|---|---|---|---|
| Ethereum (2) | `EthereumRandBridge` | [`0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892`](https://etherscan.io/address/0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892) | [`0x5d6d2e7f27bf64951112fa12df0863176671f234d7ec4ce6bec2d475e9eacee8`](https://etherscan.io/tx/0x5d6d2e7f27bf64951112fa12df0863176671f234d7ec4ce6bec2d475e9eacee8) | 26010199 |
| BNB Smart Chain (3) | `BscRandBridge` | [`0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892`](https://bscscan.com/address/0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892) | [`0xd9995f323ac3851115dd755432fef4ac786fb47990daa34e8003e33c302334af`](https://bscscan.com/tx/0xd9995f323ac3851115dd755432fef4ac786fb47990daa34e8003e33c302334af) | 122760747 |
| Tron (4) | `TronRandBridge` | [`TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU`](https://tronscan.org/#/contract/TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU) (hex `410992df85dcce77ded2c0387f1fa9cf98ac859700`) | [`ac53e3a666eea6ac71be8fa51418858328e023a529740696b7bbb9415df00dda`](https://tronscan.org/#/transaction/ac53e3a666eea6ac71be8fa51418858328e023a529740696b7bbb9415df00dda) | 86377422 |
| Solana (5) | `rand-bridge` program | [`FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu`](https://solscan.io/account/FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu) | deploy `5tk97GtjCmHqzTsrjfjmnRUM6RA5HGggX8WntdcnWGgwUthMZxv62EZR7A8XH1ciDg3GxT6FUSUjwtKveT27Xo4w`, initialize `2XZ473mSGpomaqE2jT6BZtomAEG7M1YxFnAEbomuoPdULWhYnawJXHh66R6vQhtfhTHbriVRHGXqAfotq2t8S87q` | — |

Admin / pauser: `0xe49Bd2571A549e8797bE649229F62891Fe300d0e` on the EVM family; Solana admin
`HLc2AjnRTGvH4ZK6YjPmizJ3m8wGJr5qJ3T38rkdN2P2`, pauser `8bYjGxCUK4aUJmDr1D5i2fV1fPzhQEU2wtkTAeF2jwES`.
The Solana upgrade authority is still the deployer `DvV45t4mfWKJvUXvFLoEuYgRqzmL1m6DaHbn8ZLw77kX`.
Deployers: `0xFC991f95e4C686035646dF1229E73995E51C27c1` (Ethereum, BSC), `THCaN39DSwpr6w62DmvjE5WqJC3WPf1x2a`
(Tron). Built from bridge commit `681f2e8` + the mainnet `declare_id!`. The machine-readable records
are `deploy/deployments/{ethereum,bsc,tron-mainnet,solana-mainnet-beta}.json`; the daemons' mainnet
configuration is `daemons/mainnet/`.

Guardian set 0, in index order: `0x5B5C007b5638B643a1f6b3C18AFB2a7784a9a2aa`,
`0x3fACDAf6Ea59Bc75cD18B4CA1844344005e66453`, `0x8CD7478ECa7235E8A5265d4B7F638086f25cC9F5`,
`0x76845347679B878c0016491B19defc59C83E20fB`, `0x62fA3e39F56636955DF228917EDD2e9e68F3a957`,
`0xb3F1409AE0D5b2467229fA74a92c51b15f980445`.

## The `bridge` section of the Rand genesis that matches these endpoints

Exactly these values: every endpoint has them baked in, and a bridge cannot be added to or changed
on a running chain.

```json
"bridge": {
  "emitter": "c02df6ba70c2457a7406780da97492a6acb57dc40751e6279f003a570559d15f",
  "guardians": [
    "5b5c007b5638b643a1f6b3c18afb2a7784a9a2aa",
    "3facdaf6ea59bc75cd18b4ca1844344005e66453",
    "8cd7478eca7235e8a5265d4b7f638086f25cc9f5",
    "76845347679b878c0016491b19defc59c83e20fb",
    "62fa3e39f56636955df228917edd2e9e68f3a957",
    "b3f1409ae0d5b2467229fa74a92c51b15f980445"
  ],
  "emitters": {
    "2": "000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892",
    "3": "000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892",
    "4": "0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700",
    "5": "d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a"
  }
}
```

## Whitelist and the first round trip (2026-09-20)

`setToken(token, true, 100, 1000)` (per transfer / per day, in whole tokens) on every endpoint:
Ethereum USDT `0x421ddbfff8fdbd56ec77037140b6e41bfe037bb9760721bd0789e1865428b662`, USDC
`0xb2d52c0f7ff7cf88dd47dd731f4278a374e193cd6af579017c4303c06c53bea7`; BSC USDT
`0x94748817ea25551910fedcaffc5b7a031f79f4ab46a4998197a5e063565b6125`, USDC
`0xf8fd863c6052c93fec7c2b3ddb7596c9bc93cb1c66e653356107a685e0f039f6` (one of each pair, in block
order); Tron USDT `ac15bfb1052dfb0178b7655ea638fcc7e902e26bb7766a752717f3817739ca5f`; Solana USDT
`4guM6o7VHoVq6GpF6dDtJ7YzJduocb7Snt3P9FF4975qAno7K4oMLf4jrUJfBoHdcYvsgpapLHexZCTzPkvQfTTz`, USDC
`3y5grrxuZvh5rJX8D85CuxmeH7RUK8qbEQEFCF1Qt5wY9oy4d3ypv66iZjkukEorzKB6nhjCPxprMx81tFCb6srd`.

Round 1 — 1 USDT per chain to Rand chain 14 and back (relayer fee 0; release pays 0.999):

| chain | lock | Rand mint (`BridgeAttest`) | Rand burn (`BridgeBurn`) | release |
|---|---|---|---|---|
| Ethereum | `0xd3a28422a53f455d2c5b9bfeb490aae4cfc1c7386fbfec567e462d3c5b6ceb76` | block 3430 `8ac6c497…31ec9` | seq 3 `7da01f410cf2726b79c7626cb6d9f2a3fa1cd9362487de216f266764c3f88840` | `0x88f9d430f933aa2fe1ea708e40ba9890e04889b5c4b08a8960fe250ee83e7429` |
| BSC | `0xd1706d0f752374ccb5ce64b6d246897a0018101cf043a5b3835c651ac9e3f945` | block 2572 `f2f24d75…4851d` | seq 0 `f9f365ca170a5fb51ff9381d7b5cc39538c1a621e5f6e8c1bd74d8751c7bbc49` | `0xbe38fd0592def630d4f7fecdd6a354530307a6296b0b8d96ca9729afeef22fc8` |
| Tron | `4bba90b365bd6c3ae64557f4774640075066cc3d06afcff88f39f1269fdeaa12` | block 2793 `16ea7cbdacb5261829b43b223f3d486ab0fc43cc7b8d85755de6987ddaeecd90` | seq 1 `013ac7b74c02842ea9516c81570fbc9e0edac4c201a560baedb3d70c7020a038` | `9c07d3f2626046316cc52a1678eec3f701cb1cefb5f43bad71bf5c3fbd2b6262` |
| Solana | `63mjiakBorqYg6oMBwtSJn3KGdh6AhLLxMMvwKKWmg7EWL3A3qYctB9VmbhdkVxMxBKcSBBE8Bt1Lhk9ftZmhRbu` | block 2684 `1bb5a046f2faf1cff48830c4ea8e51c6e36db05c5c8ee38d4dbc5cd1cba6c85e` | seq 2 `7548f330e0f26dbb0011e66096ae9e1859930103b91259883c7e757612a19285` | `5Fy65G7KiZZzadqRV8sdNissR2th8Yr1hyBXw8PhKe4ADGTZnmi6sbWrxyaJkFTvbJQKGrc34jv68a6wBSnZyUTz` |

`rand-bridge-audit` afterwards: custody 0 on all seven tokens, accrued fees exactly 10 bps of each
release, every endpoint's balance == custody + fees, Rand total supply 0 == Σ locked.

Round 2 — 9 USDT per chain, minted and **left on Rand** (the owner's ruling: the bridge is known to
work, keep 36 zUSD against 36 USDT in custody). Locks: Ethereum
`0xf9bb33bdc89fec2ee82b4dd02226ec9d0b63d27ae50fb341af6e8b95ec937d0a`, BSC
`0xc329ea06440bf4a84383da39b9c67e2484ac96e168558b1a86905242c165c1ff`, Tron
`b0fc155a2264b9dbf5b7cbeac899ae918b3a976aa7af21e003f37435eb9f3269`, Solana
`2iAUL44wjhE7pcYeznAwGix5RMb28eTgXVwSRy7qixGASUcwqXx7EhVsrZATyNAjzAKXw2sRNXhQiaLF6ps6w6K3`.
`rand-bridge-audit` afterwards: custody 9 USDT on each endpoint == `locked` on Rand, total supply
3600000000 == Σ locked, custody − locked = 0. The zUSD is held by the chain-14 "tester" wallet
(`~/.rand-chain14/wallets/`, the fullnode session's).

## Guardian set 1 (2026-09-25)

Set 0 (six keys on one laptop) was rotated to **set 1: eight guardians, quorum 6**, as the first step
of BR-4 (key custody). Indices 0–5 run on six DigitalOcean droplets (`rand-guardian-1..6`: nyc3,
sfo3, ams3, fra1, lon1, sgp1), each with its own ECDSA key generated on that droplet and its own
non-validator chain-14 node, so no guardian takes its view of Rand from a shared RPC. Indices 6–7 run
on the operator laptop. Losing the laptop leaves 6 of 8 (the bridge keeps running); stealing it yields
2. Host layout and operation: `docs/guardian-hosts.md`.

Set 1, in index order: `0x29851d77B4b5b095Cd10F85ad76EE917dCf0F0aC`,
`0xBA56d1cec76b461b7aeB04a559350962070b5f7f`, `0xc0A9FC250cfe2AE8EbFb6704777E6bE4fbe3E374`,
`0x6F7196e8448415F667B32CF162e8689f98e6A987`, `0x4dC932582668DBfEB24c03B22701F7e93Ad53320`,
`0x6d63947627CAc07bB863D36E015a714099A57359` (droplets 1–6), `0x849f4e9e2420e115FA6E6715f53279af0a679C39`,
`0x98fFfdEC75284D77433404C1c0Fc9f90AbB58A9c` (laptop).

One attestation (`rand-bridge-gov rotate`, signed by set 0 indices 0–4, digest
`0x3ee6a6096430ba52ce3d1511c317684abfffa13696e6639c98c884e071b5224b`) applied everywhere:

| chain | transaction |
|---|---|
| Ethereum | `0x32dba04944bfec4ea6efe1a9f4df2476535a5fea80d1ce8c1d12cfd872321ec1` |
| BSC | `0xe96e76ec01f0ebe2383750c563f567d6ab0de58ec88498cd378f3846e2365dbc` |
| Tron | `79be29dc9c91d14e3c2dced5beff174a7b122c02c36fd74564601e3c7eca046d` |
| Solana | `2LZrAjC9WvzZrNFdoXZr5nF3ZXx9UkRwqSDAqgJXTp4NCU7no9fbQ1sibbnhJy6pixsvJd14byoG4pEPYfDgQw9J` |
| Rand chain 14 | `rand bridge-rotate` with the PQ quorum (indices 0–4), tx `05431f36987a460b86eeafedce78e35d88fc809b1b3b27f0550067e9b64cfec0` |

Set 0 keeps verifying transfers for 86,400 s after each rotation (until about 2026-09-26 03:35 UTC),
then its keys are worthless.

**Not changed by this rotation:** the chain-14 Dilithium2 set (`pq_guardians`, six keys generated on
the laptop). Chain 14 cannot rotate it; bridge rules v2 (`RotatePqGuardians`, fullnode `39f3f35`)
can, from the next chain cut. Until then each droplet also holds the chain-14 PQ seed at its own index,
so mints reach the 5-of-6 PQ quorum without the laptop, and the laptop still holds all six seeds.
Each droplet has already generated its successor Dilithium2 seed (`/etc/rand-guardian/pq-next.seed`,
public key in `pq-next.pub`) for that rotation.

## BR-3 on Tron: timelock deployed, pauser moved, admin handover proposed (2026-09-26)

Steps 0–3 of the Tron sequence in `docs/governance.md` §4 (user go in the bridge session).

| step | what | transaction | block |
|---|---|---|---|
| 1 | `TimelockController` [`TKmds8i5UPQDaV3YghCVJUMomHeQzJzV7k`](https://tronscan.org/#/contract/TKmds8i5UPQDaV3YghCVJUMomHeQzJzV7k), deployed by `THCaN…x2a`: runtime keccak `0xfcb7…5d5b` (the pin), `getMinDelay()` 172800, proposer = executor = canceller `TXbkkf…Rjp` only, `DEFAULT_ADMIN_ROLE` the timelock only; 1,603,010 energy, 172.553 TRX | `f2f0b40da0662c05633c5d6fd3581d4290c19ec0e0ec2ec92404dfcfef897f5a` | 86582871 |
| 2 | `setPauser(TCimv6…LG58)` from the admin `TWoyj…9mh` | `14b3ced340061ef24260241ace1a20be9c4ca5a3a8668866a2e1f52bf7fefd1b` | 86582898 |
| 3 | `transferAdmin(TKmds8…V7k)` from the admin: `pendingAdmin()` = the timelock, `admin()` is still `TWoyj…9mh` | `b7cc251c030ec1e707ee11614ecbc44ba1ac8f673de7b6ee9946b0c2d34d20ed` | 86582920 |

The two multi-signature accounts are children of one xpub (`TRON_MSIG_XPUB` in `~/.zshrc`, depth 4 =
`m/44'/195'/a'/0`, address `/i` = child `i`):

| role | index | address |
|---|---|---|
| admin multisig account (the timelock's only proposer/executor/canceller) | /0 | `TXbkkfTiCAJWsTZcBnyemQZsgfKJr2SRjp` |
| pause multisig account (the bridge `pauser()`) | /1 | `TCimv6fBNmPNi16QvrGgUjJWQYTnmpLG58` |
| signers 1–5 | /2–/6 | `TCCm5ui5kHeqxgYF69pmb7GF8RcdP5fccG`, `TWk2QEXwM42qAQ5TFKwWo66eg5G2m9v82P`, `TYbQ16vcbRY34gLN5AN25miEZJR29pCqme`, `TBqXBmWnUKeat3Fpgx8e8YKNEVSXXgWe6F`, `TW4M3My781kRpUFZwYBUQfkd1FqEMq3Xrn` |

Multi-signature since 2026-09-26 (funded 110 TRX each from the deployer, `2ff489dc…af20`,
`f2bb477e…bc22`; each `AccountPermissionUpdate` signed by the account's own key and burning 100 TRX):
admin `TXbkkf…Rjp` owner 3/5, active id 2 3/5 (TriggerSmartContract only), tx
`97889ff03ae5f25689944d14cd757c7d0d4d5fb37d6d9d16ffe03ab705ceecfc` (block 86584583); pause `TCimv6…LG58`
owner 3/5, active id 2 2/5, tx `8675613036534d4903a86492716abf2af8417d76d69314e4be7b1621f803779b`
(block 86584610). Signers `/2`–`/6`.

**All of them share one seed**, so the Tron multisigs are nominal (one key in substance) until the
signers move to separate people and devices (BR-4). Not done yet, in order:

1. ~~Fund `/0` and `/1`~~ (done).
2. ~~`node deploy/tron-ops.js multisig-permissions <account> --signers <the five> --owner-threshold 3
   --active-threshold 3` (pause account: `--active-threshold 2`) writes the unsigned
   `AccountPermissionUpdate`; the account's own key (`/0`, `/1`) signs it with permission id 0. After
   it lands those keys have no power; the audit needs both thresholds ≥ 2.~~ (done)
3. `timelock-schedule-accept TKmds8…V7k --from TXbkkf…Rjp` (signed by 3 of the signers), then after
   48 h `timelock-execute-accept`. Until the execute, `TWoyj…9mh` is admin and can cancel with
   `transferAdmin(T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb)`.

## Burn and release before the chain-15 cut (2026-09-26)

The tester wallet's 26 zUSD burned on chain 14 (fullnode session), released by the relayer to the
round-1 addresses, relayer fee 0, 10 bps protocol fee:

| seq | to | Rand burn | release |
|---|---|---|---|
| 4 | Ethereum USDT 8.991 → `0xcf37d3657cc8ffc11e2b2ec46e02c5e37d11dd90` | `7cf30a6f722e8b68710aa1a22bfa3b2897f9d45c8de7002c046aaa09994d537a` (h 377101) | `0xbb9e23602c29ecf9c8d3f1947af9d104cd2180d090a16f8d8206087ec6c853e7` |
| 5 | BSC USDT 8.991 → the same | `7091252ab78d1c287263ab9c73ad23e3ea3c101c8afb9919be5a0e8df487bac9` (h 377189) | `0xf3aae2c9995f3982cbe545192605045d4bc8356599d1de84497d201f7676465f` |
| 6 | Solana USDT 7.992 → `FKXy9NgLK3GJygzaTXJaGTEvs8V7XfnXXTgVPZ2c3KHv` | `cf0a826ef16adba662427c83fc89276e15b40210da67be22c84b1258c25e714f` (h 377296) | `2ZzhYvuUBeH1X6KazVsL6mZtBZJgBUhnGiZ8eTdYNrAxmKWGTEpsEjNwQf611mqhSKJoFFSniA2WWLLnSGTr2Mss` |

`rand-bridge-audit` afterwards: custody Tron USDT 9, Solana USDT 1, all else 0; Rand supply 10 zUSD
== Σ locked; custody − locked = 0. That residue (a third party's 10 zUSD) is carried into the chain-15
genesis as `locked` Tron-USDT 9 / Sol-USDT 1 and a 10-zUSD genesis note; chain 15 starts at guardian
set index 1 and burn sequence 7, with `pq_guardians` from
`~/.rand-bridge/mainnet-set1/pq-guardians-chain15.json`.
