#!/usr/bin/env bash
# BNB Smart Chain endpoint: deploy/bnb.sh [mainnet|testnet] [--dry-run] [--yes] [--verify]
# Signs with BSC_PRIVATE_KEY. See deploy/evm.sh.
net="${1:-testnet}"; shift || true
case "$net" in
  mainnet|bsc)     net=bsc ;;
  testnet|chapel)  net=bsc-testnet ;;
  *) echo "usage: deploy/bnb.sh [mainnet|testnet] [--dry-run] [--yes] [--verify]" >&2; exit 1 ;;
esac
exec "$(dirname "${BASH_SOURCE[0]}")/evm.sh" "$net" "$@"
