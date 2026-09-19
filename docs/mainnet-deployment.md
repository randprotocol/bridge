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
