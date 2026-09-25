#!/usr/bin/env bash
# Starts the two laptop guardians of set 1 (indices 6 and 7). The other six run
# on their own droplets (docs/guardian-hosts.md). Each process is given exactly
# one key, read from ~/.rand-bridge/mainnet-set1/guardian-<i>.key (mode 600).
# Neither holds a Dilithium seed: the chain-14 PQ quorum comes from the droplets.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
bin=target/release/rand-guardian
[[ -x "$bin" ]] || cargo build --release --bin rand-guardian
mkdir -p data/mainnet/logs
for i in 7 8; do
  keyfile="$HOME/.rand-bridge/mainnet-set1/guardian-$i.key"
  [[ -s "$keyfile" ]] || { echo "error: $keyfile is missing" >&2; exit 1; }
  env -i PATH="$PATH" HOME="$HOME" "GUARDIAN${i}_PRIV_KEY=$(<"$keyfile")" \
    nohup "$bin" --config "mainnet/guardian-$i.toml" >>"data/mainnet/logs/guardian-$i.log" 2>&1 &
  echo "guardian $i: pid $! (log data/mainnet/logs/guardian-$i.log)"
done
