// TronBox configuration for the Rand bridge's Tron endpoint
// (TronRandBridge, bridge chain id 4 -- see docs/superpowers/specs/2026-09-10-rand-bridge-design.md
// Section 5.4). See tron/README.md for the full deployment walkthrough.
//
// This file is deployment tooling only: no Tron toolchain is installed on the
// build machine, so it has never actually been run against a live network.

const FEE_LIMIT = 1_000_000_000; // 1000 TRX, in sun
const USER_FEE_PERCENTAGE = 100; // resource consumer pays 100% of bandwidth/energy fees

module.exports = {
  networks: {
    shasta: {
      privateKey: process.env.PRIVATE_KEY_SHASTA,
      userFeePercentage: USER_FEE_PERCENTAGE,
      feeLimit: FEE_LIMIT,
      fullHost: 'https://api.shasta.trongrid.io',
      network_id: '2',
    },
    nile: {
      privateKey: process.env.PRIVATE_KEY_NILE,
      userFeePercentage: USER_FEE_PERCENTAGE,
      feeLimit: FEE_LIMIT,
      fullHost: 'https://nile.trongrid.io',
      network_id: '3',
    },
    mainnet: {
      privateKey: process.env.PRIVATE_KEY_MAINNET,
      userFeePercentage: USER_FEE_PERCENTAGE,
      feeLimit: FEE_LIMIT,
      fullHost: 'https://api.trongrid.io',
      network_id: '1',
    },
  },

  compilers: {
    solc: {
      version: '0.8.20',
      settings: {
        optimizer: {
          enabled: true,
          runs: 200,
        },
        // Tron's TVM does not support the PUSH0 opcode that later EVM
        // targets emit; Paris is the newest evmVersion without it, and is
        // the same target the Foundry side pins in evm/foundry.toml.
        evmVersion: 'paris',
      },
    },
  },
};
