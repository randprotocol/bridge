# What gets deployed, and what it costs

Measured 2026-09-19. Gas is from `forge test --gas-report` on a mainnet fork; prices were read
the same day (ETH $2,630, BNB $763, TRX $0.338, SOL $112.7; Ethereum gas 0.07 gwei, BSC 0.05 gwei,
Tron energy 100 sun, Solana rent from `getMinimumBalanceForRentExemption`). **Testnets cost nothing**
— Sepolia, BSC testnet, Nile and devnet are faucet-funded.

## What gets deployed

One custody endpoint per chain. All four implement the same rules (`docs/architecture.md` §11);
the three EVM-family ones are the same Solidity base with a 20-line chain wrapper.

| chain | artifact | what it is | deployed by |
|---|---|---|---|
| Ethereum | `EthereumRandBridge` (`evm/src`) | `RandBridgeBase` + bridge chain id 2, consistency level 1. One contract: holds custody of every whitelisted token, verifies guardian attestations (`lib/Attestation.sol`, compiled in), stores the guardian sets, the consumed digests, the per-token caps and the accrued protocol fees. Not upgradeable, no proxy. | `deploy/eth.sh` |
| BNB Smart Chain | `BscRandBridge` | The same base, chain id 3, consistency level 15. | `deploy/bnb.sh` |
| Tron | `TronRandBridge` | The same base, chain id 4; no fork guard (Tron has no `chainid` semantics to pin). Compiled from a mirror of `evm/src` by TronBox, which also deploys its own small `Migrations` bookkeeping contract. | `deploy/trx.sh` |
| Solana | `rand-bridge` program (`solana/programs/rand-bridge`) | One upgradeable native program. Its state lives in PDAs it creates: `config`, one account per guardian set, and per token a registry plus an SPL custody token account owned by the program's authority PDA; one small marker per released digest and one account per outbound message. | `deploy/sol.sh` (deploy, then `Initialize`, which only the upgrade authority may run) |

Constructor / `Initialize` arguments are the same everywhere: `ADMIN` (owns the token whitelist,
the fee rate and fee withdrawals — a multisig), `PAUSER`, `RAND_EMITTER`, and guardian set 0. After
deployment each chain needs `setToken` / `set-token` once per token (USDT, USDC; not Tron USDC),
and each endpoint's address goes into the Rand genesis `bridge.emitters` table. Nothing else is
deployed on the source chains: no token contract, no proxy, no oracle. zUSDT / zUSDC are not
contracts at all — they are shielded notes on Rand, registered by the first attestation.

## Deployment cost (mainnet)

| chain | what | measured | cost at today's price | budget to fund |
|---|---|---|---|---|
| Ethereum | deploy 2,896,462 gas + 2 × `setToken` ~125,000 | 3.02M gas | $0.55 at 0.07 gwei; **$40 at 5 gwei; $160 at 20 gwei** | **0.03 ETH (~$80)** |
| BNB Smart Chain | same bytecode | 3.02M gas | $0.12 at 0.05 gwei; $2.30 at 1 gwei | **0.01 BNB (~$8)** |
| Tron | ~13.8 KB of code at 200 energy/byte (~2.75M) + constructor (~0.3M) + TronBox `Migrations` (~0.3M) + 2 × `setToken` (~0.15M) ≈ 3.5M energy at 100 sun, + ~20 TRX bandwidth, + 1 TRX account activation | estimated, not measured — no Tron VM here; Nile will give the real figure | ~370 TRX ≈ $125 | **500 TRX (~$170)** (`feeLimit` is 1,000 TRX) |
| Solana | program data rent for 211,808 bytes = 1.0766 SOL, held while the program exists; the deploy buffer needs the same again and is refunded; ~220 write transactions ≈ 0.0011 SOL; config + guardian set + 2 × (registry + custody account) ≈ 0.01 SOL | 1.09 SOL sunk, 2.17 SOL at peak | $123 sunk, $245 at peak | **2.5 SOL (~$282)**, ~1.3 SOL comes back |

**Total to buy for a mainnet deployment: about $540 in USDT terms** (ETH $80 + BNB $8 + TRX $170 +
SOL $282), of which roughly $150 returns (the Solana buffer) and the Ethereum line is almost all
headroom against a gas spike. For the testnet round trip: $0.

## Running cost (the relayer's, per transfer)

| action | measured | cost today |
|---|---|---|
| Ethereum `lock` (paid by the user) | 108,000 – 125,000 gas | $0.02 at 0.07 gwei; $3 at 10 gwei |
| Ethereum `release` (relayer) | 180,000 – 276,000 gas (five `ecrecover`s, two token transfers) | $0.05 at 0.07 gwei; $7 at 10 gwei |
| BSC `release` | same gas | ~$0.01 |
| Tron `release` | est. 300,000 – 450,000 energy (Tron USDT transfers are 65,000 – 130,000 each) | **30 – 45 TRX, $10 – $15**, unless the relayer stakes TRX for energy |
| Solana `release` | 5,000 lamports + the permanent spent marker (817,880 lamports) + 1,488,440 lamports if the recipient's token account is new | $0.09, or $0.26 with a new account |
| Rand mint (`BridgeAttest`, relayer) | `BUNDLE_BASE` | 0.001 RAND, plus proving time |
| Rand burn (`BridgeBurn`, user) | `BRIDGE_BURN_FEE` | 0.01 RAND |

A relayer is paid only by the `relayer_fee` a burn offers (and nothing for a deposit), so on Tron
and on a congested Ethereum a burn has to offer a fee that covers the row above, or whoever
operates the bridge runs a relayer at a loss out of the 10 bps.
