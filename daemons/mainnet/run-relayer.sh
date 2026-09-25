#!/usr/bin/env bash
# Starts the mainnet relayer with every submitter it needs, keys through the
# environment only: the EVM deployer key pays gas on Ethereum and BSC, the Tron
# deployer key on Tron, SOL_PRIVATE_KEY on Solana, the chain-14 relayer wallet on Rand.
# The keys are `export` lines in ~/.zshrc; this reads the four it needs and no others.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
bin=target/release/rand-relayer
[[ -x "$bin" ]] || cargo build --release --bin rand-relayer
eval "$(grep -E '^\s*export (ETH_PRIVATE_KEY|TRON_PRIVATE_KEY|SOL_PRIVATE_KEY)=' ~/.zshrc)"
mkdir -p data/mainnet/logs
env -i PATH="$PATH" HOME="$HOME" \
  RELAYER_EVM_KEY="$ETH_PRIVATE_KEY" RELAYER_TRON_KEY="$TRON_PRIVATE_KEY" SOL_PRIVATE_KEY="$SOL_PRIVATE_KEY" \
  RAND_KEY="$HOME/.rand-chain14/wallets/relayer.key.json" RAND_RPC="http://127.0.0.1:8545" \
  nohup "$bin" --config mainnet/relayer.toml >>data/mainnet/logs/relayer.log 2>&1 &
echo "relayer: pid $! (log data/mainnet/logs/relayer.log)"
