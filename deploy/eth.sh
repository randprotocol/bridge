#!/usr/bin/env bash
# Ethereum endpoint: deploy/eth.sh [mainnet|sepolia] [--dry-run] [--yes] [--verify]
# Signs with ETH_PRIVATE_KEY. See deploy/evm.sh.
net="${1:-sepolia}"; shift || true
case "$net" in
  mainnet|ethereum) net=ethereum ;;
  sepolia|testnet)  net=sepolia ;;
  *) echo "usage: deploy/eth.sh [mainnet|sepolia] [--dry-run] [--yes] [--verify]" >&2; exit 1 ;;
esac
exec "$(dirname "${BASH_SOURCE[0]}")/evm.sh" "$net" "$@"
